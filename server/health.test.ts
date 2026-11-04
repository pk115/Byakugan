import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

process.env.SUPAPULSE_DATA_DIR = mkdtempSync(join(tmpdir(), "byakugan-health-"));
const { db } = await import("./database.js");
const health = await import("./health.js");

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

  it("reports all ten items and leaves unmeasured ones as NO_DATA", () => {
    const status = health.healthStatus();
    expect(status.items).toHaveLength(10);
    expect(status.items.find((i) => i.no === 4)?.level).toBe("NO_DATA");
  });
});
