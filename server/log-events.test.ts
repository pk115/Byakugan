import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain ESM script, no types
import { normalize, parseCsv } from "../scripts/import-logs.mjs";

process.env.SUPAPULSE_DATA_DIR = mkdtempSync(join(tmpdir(), "byakugan-logs-"));
const { db } = await import("./database.js");
const logs = await import("./log-events.js");

const agentId = Number(db.prepare("INSERT INTO agents(name,token_hash) VALUES('t','h')").run().lastInsertRowid);
const event = (over: Record<string, unknown>) => ({ source: "host", event: "SSH_LOGIN_FAILED", timestamp: new Date().toISOString(), severity: "warning" as const, details: {}, ...over });

describe("sample CSV mapping", () => {
  const samples: Array<[string, Record<string, string>]> = [
    ["audit_logs", { action: "LOGIN_SUCCESS", username: "dev_admin", ip: "192.0.2.1", timestamp: "2026-08-07T00:00:00.000Z", status: "" }],
    ["db_logs", { event: "DB_AUTH_FAILED", host: "db1", user: "app", src_ip: "10.0.0.1", result: "failure", timestamp: "2026-08-07T00:00:00.000Z" }],
    ["firewall_logs", { action: "DENY", device: "fw", src_ip: "1.1.1.1", rule: "deny-db-from-wan", severity: "warning", timestamp: "2026-08-07T00:00:00.000Z" }],
    ["host_logs", { event: "SUDO_COMMAND", host: "h", user: "u", severity: "info", command: "ls", timestamp: "2026-08-07T00:00:00.000Z" }],
    ["nginx_access_logs", { host: "gw", remote_addr: "2.2.2.2", status: "502", request_uri: "/x", timestamp: "2026-08-07T00:00:00.000Z" }],
    ["vpn_logs", { server: "vpn", event: "VPN_AUTH_FAILED", user: "u", src_ip: "3.3.3.3", result: "failure", timestamp: "2026-08-07T00:00:00.000Z" }]
  ];
  it.each(samples)("%s normalizes to a valid event", (kind, row) => {
    expect(logs.logEventSchema.safeParse(normalize(kind, row)).success).toBe(true);
  });
  it("parses quoted CSV cells", () => {
    expect(parseCsv('a,b\n"x,1","he said ""hi"""\n')).toEqual([{ a: "x,1", b: 'he said "hi"' }]);
  });
});

describe("log ingestion", () => {
  it("filters by agent, severity and literal search, and pages by event time with tied timestamps", () => {
    const second = Number(db.prepare("INSERT INTO agents(name,token_hash) VALUES('windows-test','h2')").run().lastInsertRowid);
    const timestamp = "2026-11-11T00:00:00.000Z";
    logs.ingestLogs(second, [
      event({ timestamp, event: "LOGIN_FAILED", host: "WIN01", actor: "alice", severity: "error", details: { reason: "100%_literal" } }),
      event({ timestamp, event: "SERVICE_STOP", host: "WIN01", severity: "error" }),
      event({ timestamp: "2026-11-10T00:00:00.000Z", event: "LOGIN_SUCCESS", host: "WIN01" })
    ]);
    const first = logs.queryLogs({ agentId: second, severity: "error", limit: 1 }) as Array<{ id: number; occurredAt: string }>;
    expect(first).toHaveLength(1);
    const next = logs.queryLogs({ agentId: second, severity: "error", beforeTime: first[0].occurredAt, beforeId: first[0].id }) as Array<{ id: number }>;
    expect(next).toHaveLength(1);
    expect(next[0].id).not.toBe(first[0].id);
    expect(logs.queryLogs({ agentId: second, search: "100%_literal" })).toHaveLength(1);
    expect(logs.queryLogs({ agentId: second, search: "100%missing" })).toHaveLength(0);
    expect(logs.queryLogs({ agentId: agentId, search: "WIN01" })).toHaveLength(0);
    expect(logs.queryLogs({ agentId: second, from: timestamp, to: timestamp })).toHaveLength(2);
    db.prepare("DELETE FROM agents WHERE id=?").run(second);
  });
  it("dedupes, alerts on repeated failures, resolves, and purges past retention", () => {
    const batch = Array.from({ length: 10 }, (_, i) => event({ actor: "root", srcIp: `203.0.113.${i}` }));
    expect(logs.ingestLogs(agentId, batch)).toEqual({ accepted: 10, duplicates: 0 });
    expect(logs.ingestLogs(agentId, batch)).toEqual({ accepted: 0, duplicates: 10 });
    expect(logs.evaluateLogAlerts(agentId)).toContain("log_auth_failures");
    expect(logs.queryLogs({ event: "SSH_LOGIN_FAILED" })).toHaveLength(10);
    expect(logs.evaluateLogAlerts(agentId, new Date(Date.now() + 20 * 60000))).not.toContain("log_auth_failures");
    expect((db.prepare("SELECT status FROM compliance_findings WHERE finding_key='log_auth_failures'").get() as { status: string }).status).toBe("RESOLVED");

    logs.ingestLogs(agentId, [event({ event: "HTTP_REQUEST", timestamp: "2020-01-01T00:00:00.000Z" })]);
    expect(logs.purgeExpiredLogs()).toBe(1);
    expect(logs.logSummary("2000-01-01T00:00:00.000Z")).toHaveLength(1);
  });
});
