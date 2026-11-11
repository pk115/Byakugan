import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

process.env.SUPAPULSE_DATA_DIR = mkdtempSync(join(tmpdir(), "byakugan-health-"));
const { db } = await import("./database.js");
const health = await import("./health.js");

it("keeps acknowledgement on downgrade, reopens on escalation, and resolves on recovery", () => {
  const agent = Number(db.prepare("INSERT INTO agents(name,token_hash) VALUES('health-ack','health-ack')").run().lastInsertRowid);
  const metric = (memory:number,offset:number) => db.prepare("INSERT INTO host_metrics(agent_id,cpu_percent,memory_percent,uptime_seconds,observed_at) VALUES(?,1,?,100,?)").run(agent,memory,new Date(Date.now()+offset).toISOString());
  const status = () => (db.prepare("SELECT status FROM compliance_findings WHERE agent_id=? AND finding_key='health_ram_percent'").get(agent) as {status:string}).status;
  try {
    metric(95,-4000); health.evaluateHealth();
    db.prepare("UPDATE compliance_findings SET status='ACKNOWLEDGED' WHERE agent_id=?").run(agent);
    metric(80,-3000); health.evaluateHealth();
    expect(status()).toBe("ACKNOWLEDGED");
    metric(96,-2000); health.evaluateHealth();
    expect(status()).toBe("OPEN");
    db.prepare("UPDATE compliance_findings SET status='ACKNOWLEDGED' WHERE agent_id=?").run(agent);
    metric(10,-1000); health.evaluateHealth();
    expect(status()).toBe("RESOLVED");
  } finally { db.prepare("DELETE FROM agents WHERE id=?").run(agent); }
});

const policy = (no: number) => (db.prepare("SELECT direction,warning_value AS warningValue,critical_value AS criticalValue,warning_inclusive AS warningInclusive FROM health_policies WHERE no=?").get(no)) as Parameters<typeof health.classify>[1];

// Boundaries come straight from the Health Check standard table.
describe("classify against the standard", () => {
  it.each([
    [1, 69.9, "NORMAL"], [1, 70, "WARNING"], [1, 85, "WARNING"], [1, 85.1, "CRITICAL"],
    [2, 74.9, "NORMAL"], [2, 75, "WARNING"], [2, 90, "WARNING"], [2, 90.1, "CRITICAL"],
    [3, 25.1, "NORMAL"], [3, 25, "WARNING"], [3, 10, "WARNING"], [3, 9.9, "CRITICAL"],
    [5, 49, "NORMAL"], [5, 50, "WARNING"], [5, 150, "WARNING"], [5, 151, "CRITICAL"],
    [8, 31, "NORMAL"], [8, 30, "WARNING"], [8, 15, "WARNING"], [8, 14, "CRITICAL"],
    [9, 99.95, "NORMAL"], [9, 99.9, "NORMAL"], [9, 99.8, "WARNING"], [9, 99.0, "WARNING"], [9, 98.9, "CRITICAL"]
  ])("item %i value %f -> %s", (no, value, level) => {
    expect(health.classify(value, policy(no))).toBe(level);
  });
});

const agentId = Number(db.prepare("INSERT INTO agents(name,token_hash) VALUES('vm-1','h1')").run().lastInsertRowid);
const metric = (cpu: number, minutesAgo: number, freeC = 50, memory = 40) => db.prepare("INSERT INTO host_metrics(agent_id,cpu_percent,memory_percent,uptime_seconds,disks_json,observed_at) VALUES(?,?,?,?,?,?)")
  .run(agentId, cpu, memory, 1000, JSON.stringify([{ mount: "C:", totalBytes: 100, usedBytes: 100 - freeC, usedPercent: 100 - freeC }]), new Date(Date.now() - minutesAgo * 60000).toISOString());
const state = (no: number) => (db.prepare("SELECT level FROM health_state WHERE policy_no=?").get(no) as { level: string } | undefined)?.level;
const openIncidents = () => (db.prepare("SELECT COUNT(*) AS n FROM incidents WHERE health_policy_no=1 AND resolved_at IS NULL").get() as { n: number }).n;

describe("health engine", () => {
  it("raises Critical only when sustained, opens one incident, and resolves on recovery", () => {
    metric(90, 4);
    health.evaluateHealth();
    expect(state(1)).toBe("WARNING"); // one sample is not "5 minutes"
    expect(openIncidents()).toBe(0);

    metric(92, 2);
    health.evaluateHealth();
    expect(state(1)).toBe("CRITICAL");
    expect(openIncidents()).toBe(1);
    health.evaluateHealth();
    expect(openIncidents()).toBe(1); // no duplicate incident while still critical
    expect((db.prepare("SELECT status FROM compliance_findings WHERE agent_id=? AND finding_key='health_cpu_percent'").get(agentId) as { status: string }).status).toBe("OPEN");

    metric(20, 0); // newest sample is healthy again
    health.evaluateHealth();
    expect(state(1)).toBe("NORMAL");
    expect(openIncidents()).toBe(0);
    expect((db.prepare("SELECT status FROM compliance_findings WHERE agent_id=? AND finding_key='health_cpu_percent'").get(agentId) as { status: string }).status).toBe("RESOLVED");
  });

  it("reads free space of C: and ignores stale agents", () => {
    db.prepare("DELETE FROM host_metrics").run();
    metric(20, 0, 8);
    health.evaluateHealth();
    expect(state(3)).toBe("CRITICAL");

    db.prepare("DELETE FROM host_metrics").run();
    metric(99, 60, 5); // an hour old: stale, previous level is kept and nothing new fires
    const before = (db.prepare("SELECT COUNT(*) AS n FROM health_history").get() as { n: number }).n;
    health.evaluateHealth();
    expect((db.prepare("SELECT COUNT(*) AS n FROM health_history").get() as { n: number }).n).toBe(before);
  });

  it("judges SSL days left, monthly SLA and backups", async () => {
    const logs = await import("./log-events.js");
    const now = new Date(), iso = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * 60000).toISOString();
    const project = (name: string, type: string) => Number(db.prepare("INSERT INTO projects(name,monitor_type,target,supabase_url,encrypted_key,interval_seconds) VALUES(?,?,?,?,?,60)").run(name, type, "example.test", "https://x.test", "k").lastInsertRowid);
    const beat = (id: number, status: string, at: string, metric: number | null = null) => db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at,metric_value) VALUES(?,?,10,1,?,?)").run(id, status, at, metric);

    const ssl = project("cert", "SSL");
    beat(ssl, "UP", iso(1), 20);
    health.evaluateHealth();
    expect(state(8)).toBe("WARNING"); // 15-30 days
    beat(ssl, "DOWN", iso(0), 10);
    health.evaluateHealth();
    expect(state(8)).toBe("CRITICAL"); // under 15 days

    const web = project("web", "HTTP");
    for (let i = 0; i < 1000; i++) beat(web, i < 2 ? "DOWN" : "UP", iso(0)); // 99.8 %
    health.evaluateHealth();
    expect((db.prepare("SELECT level FROM health_state WHERE policy_no=9 AND label='web'").get() as { level: string }).level).toBe("WARNING");

    const agent = Number(db.prepare("INSERT INTO agents(name,token_hash) VALUES('log-agent','h2')").run().lastInsertRowid);
    const backup = (event: string, minutesAgo: number) => logs.ingestLogs(agent, [{ source: "db", event, timestamp: iso(minutesAgo), host: "db1", severity: "info", details: { database: "cms", file: "x.dump", size_mb: 12 } }]);
    backup("DB_BACKUP_COMPLETE", 60);
    health.evaluateHealth();
    expect(state(10)).toBe("NORMAL");
    backup("DB_BACKUP_FAILED", 1);
    health.evaluateHealth();
    expect(state(10)).toBe("CRITICAL"); // latest backup failed
    backup("DB_BACKUP_COMPLETE", 0);
    health.evaluateHealth();
    expect(state(10)).toBe("NORMAL");
    expect((db.prepare("SELECT COUNT(*) AS n FROM backup_evidence WHERE asset_name='cms'").get() as { n: number }).n).toBe(3);
  });

  it("parses ping output from Linux and Windows", async () => {
    const { parsePing } = await import("./monitor.js");
    expect(parsePing("4 packets transmitted, 3 received, 25% packet loss\n64 bytes: icmp_seq=1 ttl=57 time=10.0 ms\n64 bytes: time=20.0 ms\n64 bytes: time=30.0 ms")).toEqual({ lossPercent: 25, avgMs: 20 });
    expect(parsePing("Reply from 1.1.1.1: bytes=32 time=12ms TTL=57\nReply from 1.1.1.1: bytes=32 time<1ms TTL=57\nPackets: Sent = 4, Received = 2, Lost = 2 (50% loss),")).toEqual({ lossPercent: 50, avgMs: 6.5 });
    expect(parsePing("Request timed out.")).toEqual({ lossPercent: null, avgMs: null });
  });

  it("judges ping latency and loss, Mongo connections and lag, and log freshness", async () => {
    const logs = await import("./log-events.js");
    const now = new Date(), iso = (m: number) => new Date(now.getTime() - m * 60000).toISOString();
    const add = (name: string, type: string, extra = "") => Number(db.prepare(`INSERT INTO projects(name,monitor_type,target,supabase_url,encrypted_key,interval_seconds${extra ? ",database_engine" : ""}) VALUES(?,?,?,?,?,60${extra ? ",?" : ""})`).run(...[name, type, "h.test", "https://x.test", "k", ...(extra ? [extra] : [])]).lastInsertRowid);
    const ping = (name: string, status: string, ms: number | null, loss: number | null) => db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at,metric_value,loss_percent) VALUES(?,?,10,1,?,?,?)").run(add(name, "PING"), status, iso(0), ms, loss);
    ping("p-fast", "UP", 20, 0); ping("p-slow", "UP", 60, 0); ping("p-lossy", "UP", 20, 25); ping("p-half", "UP", 20, 50); ping("p-dead", "DOWN", null, 100); ping("p-worse", "UP", 200, 0);
    const mongo = (name: string, used: number, lag: number | null) => db.prepare("INSERT INTO database_metrics(project_id,engine,connections_used,connections_max,replication_lag_seconds,details_json,observed_at) VALUES(?,?,?,?,?,'{}',?)").run(add(name, "DATABASE", "MONGODB"), "MONGODB", used, 100, lag, iso(0));
    mongo("m-ok", 50, 0); mongo("m-busy", 85, 0); mongo("m-full", 95, 0); mongo("m-lag", 10, 6);
    logs.ingestLogs(agentId, [{ source: "host", event: "SUDO_COMMAND", timestamp: iso(1), severity: "info", details: {} }]);
    health.setExpectedLogSources(["host", "nginx"]);
    health.evaluateHealth();
    const level = (no: number, label: string) => (db.prepare("SELECT level FROM health_state WHERE policy_no=? AND label LIKE ?").get(no, `${label}%`) as { level: string }).level;
    expect(["p-fast", "p-slow", "p-lossy", "p-half", "p-dead", "p-worse"].map((n) => level(5, n))).toEqual(["NORMAL", "WARNING", "WARNING", "CRITICAL", "CRITICAL", "CRITICAL"]);
    expect(["m-ok", "m-busy", "m-full", "m-lag"].map((n) => level(6, n))).toEqual(["NORMAL", "WARNING", "CRITICAL", "CRITICAL"]);
    expect(level(7, "host")).toBe("NORMAL"); // last event 1 minute ago, under the 5 minute warning
    expect(level(7, "nginx")).toBe("CRITICAL"); // expected source that never sent anything
  });

  it("measures a persistent WebSocket stream and its dropouts", async () => {
    const { WebSocketServer } = await import("ws");
    const watcher = await import("./ws-watcher.js");
    const server = new WebSocketServer({ port: 0, host: "127.0.0.1" });
    await new Promise((resolve) => server.once("listening", resolve));
    const port = (server.address() as { port: number }).port;
    const project = Number(db.prepare("INSERT INTO projects(name,monitor_type,target,supabase_url,encrypted_key,interval_seconds) VALUES('stream','WEBSOCKET',?,?,?,60)").run(`ws://127.0.0.1:${port}`, "https://x.test", "k").lastInsertRowid);
    const until = async (done: () => boolean) => { for (let i = 0; i < 100 && !done(); i++) await new Promise((r) => setTimeout(r, 50)); expect(done()).toBe(true); };
    try {
      watcher.syncWatchers();
      await until(() => watcher.wsStatus(project)?.connected === true);
      expect(watcher.wsDropoutSeconds(project)).toBe(0);
      for (const client of server.clients) client.terminate(); // drop the stream; the server keeps listening
      await until(() => watcher.wsStatus(project)?.connected === false);
      await until(() => watcher.wsStatus(project)?.connected === true); // reconnect after ~0.5 s
      const gap = watcher.wsDropoutSeconds(project)!;
      expect(gap).toBeGreaterThan(0);
      expect(gap).toBeLessThan(3);
      health.evaluateHealth();
      expect((db.prepare("SELECT level FROM health_state WHERE policy_no=4 AND label='stream'").get() as { level: string }).level).toBe("WARNING");
    } finally {
      watcher.stopWatchers();
      server.close();
    }
  });

  it("renders thresholds in the wording of the standard and exports flat rows", () => {
    const rows = health.healthRows();
    expect(rows).toHaveLength(10);
    expect(rows[0]).toMatchObject({ normal: "< 70%", warning: "70% – 85%", critical: "> 85% (5 min)" });
    expect(rows[2]).toMatchObject({ normal: "> 25%", warning: "10% – 25%", critical: "< 10%" });
    expect(rows[8]).toMatchObject({ normal: "≥ 99.9%", warning: "99% – 99.9%", critical: "< 99%" });
    expect(health.withUnit(22, "days")).toBe("22 days");
    expect(health.withUnit(94, "%")).toBe("94%");
  });

  it("reports all ten items, each now backed by an evaluator", () => {
    const status = health.healthStatus();
    expect(status.items).toHaveLength(10);
    expect(status.items.filter((i) => i.level === "NO_DATA")).toEqual([]);
    expect(status.items.find((i) => i.no === 4)?.level).toBe("WARNING");
    expect(status.expectedLogSources).toEqual(["host", "nginx"]);
  });
});
