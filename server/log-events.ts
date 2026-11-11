import { activeFindingStatusSql } from "./finding-status.js";
import { createHash } from "node:crypto";
import { z } from "zod";
import { db } from "./database.js";
import { appendAuditEvent } from "./audit.js";

// One normalized table for every source (host, nginx, vpn, firewall, db, app audit...).
db.exec(`
  CREATE TABLE IF NOT EXISTS log_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    dedup_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    event TEXT NOT NULL,
    host TEXT,
    actor TEXT,
    src_ip TEXT,
    result TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    details_json TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(agent_id, dedup_hash)
  );
  CREATE INDEX IF NOT EXISTS idx_log_events_time ON log_events(occurred_at);
  CREATE INDEX IF NOT EXISTS idx_log_events_agent_event ON log_events(agent_id, event, occurred_at);
`);

const detailValue = z.union([z.string().max(1000), z.number(), z.boolean(), z.null()]);
export const logEventSchema = z.object({
  source: z.string().regex(/^[a-z0-9_.-]{1,40}$/),
  event: z.string().regex(/^[A-Za-z0-9_.:-]{1,80}$/),
  timestamp: z.string().datetime(),
  host: z.string().max(253).optional(),
  actor: z.string().max(150).optional(),
  srcIp: z.string().max(64).optional(),
  result: z.string().max(40).optional(),
  severity: z.enum(["debug", "info", "notice", "warning", "error", "critical"]).default("info"),
  details: z.record(z.string().max(60), detailValue).default({})
});
export const logBatchSchema = z.object({ events: z.array(logEventSchema).min(1).max(1000) });
export type LogEvent = z.infer<typeof logEventSchema>;

export function ingestLogs(agentId: number, events: LogEvent[]) {
  const insert = db.prepare(`INSERT OR IGNORE INTO log_events
    (agent_id,dedup_hash,source,event,host,actor,src_ip,result,severity,details_json,occurred_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
  let accepted = 0;
  db.transaction(() => {
    for (const e of events) {
      const details = JSON.stringify(e.details);
      const hash = createHash("sha256")
        .update(JSON.stringify([e.source, e.event, e.timestamp, e.host ?? null, e.actor ?? null, e.srcIp ?? null, e.result ?? null, details]))
        .digest("hex");
      const added = insert.run(agentId, hash, e.source, e.event, e.host ?? null, e.actor ?? null, e.srcIp ?? null, e.result ?? null, e.severity, details, e.timestamp).changes;
      accepted += added;
      if (added && (e.event === "DB_BACKUP_COMPLETE" || e.event === "DB_BACKUP_FAILED")) recordBackup(e);
    }
  })();
  return { accepted, duplicates: events.length - accepted };
}

// Health item 10 reads backup_evidence, so database backup log events become evidence rows (once per new event).
function recordBackup(e: LogEvent) {
  const d = e.details, ok = e.event === "DB_BACKUP_COMPLETE", size = Number(d.size_mb);
  db.prepare(`INSERT INTO backup_evidence(asset_name,backup_type,storage_location,status,started_at,completed_at,size_bytes,checksum,notes)
    VALUES(?,'DATABASE',?,?,?,?,?,?,?)`).run(String(d.database ?? e.host ?? "database"), String(d.file ?? "log event"), ok ? "SUCCESS" : "FAILED", e.timestamp, ok ? e.timestamp : null,
    Number.isFinite(size) && size > 0 ? Math.round(size * 1048576) : null, d.sha256 ? String(d.sha256) : null, ok ? null : String(d.error ?? "backup failed"));
}

const AUTH_FAILURES = ["SSH_LOGIN_FAILED", "SUDO_AUTH_FAILED", "ROOT_LOGIN_DENIED", "VPN_AUTH_FAILED", "DB_AUTH_FAILED", "LOGIN_FAILED"];
const count = (agentId: number, since: string, where: string, ...params: unknown[]) =>
  (db.prepare(`SELECT COUNT(*) AS n FROM log_events WHERE agent_id=? AND occurred_at>=? AND ${where}`).get(agentId, since, ...params) as { n: number }).n;

// Rules run after each batch; a finding resolves on the first batch where its window is clean.
// ponytail: fixed thresholds, move to app_settings if operators need to tune them.
export function evaluateLogAlerts(agentId: number, now = new Date()) {
  const since15 = new Date(now.getTime() - 15 * 60000).toISOString();
  const since24h = new Date(now.getTime() - 86400000).toISOString();
  const marks = AUTH_FAILURES.map(() => "?").join(",");
  const failures = count(agentId, since15, `event IN (${marks})`, ...AUTH_FAILURES);
  const dbFromWan = count(agentId, since15, "event='FIREWALL_DENY' AND json_extract(details_json,'$.rule')='deny-db-from-wan'");
  const backupFailed = count(agentId, since24h, "event='DB_BACKUP_FAILED'");
  const rules = [
    { key: "log_auth_failures", active: failures >= 10, severity: "HIGH", title: "Repeated authentication failures", explanation: `${failures} failed logins in the last 15 minutes (threshold 10)` },
    { key: "log_db_from_wan", active: dbFromWan >= 20, severity: "HIGH", title: "Database port probed from the internet", explanation: `${dbFromWan} blocked database connections from WAN in the last 15 minutes (threshold 20)` },
    { key: "log_backup_failed", active: backupFailed > 0, severity: "HIGH", title: "Database backup failed", explanation: `${backupFailed} failed database backup event(s) in the last 24 hours` }
  ];
  const stamp = now.toISOString();
  for (const r of rules) {
    if (r.active) db.prepare(`INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at)
      VALUES(?,?,'LOG',?,'OPEN',?,?,?,?) ON CONFLICT(agent_id,finding_key) DO UPDATE SET status=${activeFindingStatusSql},severity=excluded.severity,title=excluded.title,explanation=excluded.explanation,last_detected_at=excluded.last_detected_at,resolved_at=NULL`)
      .run(agentId, r.key, r.severity, r.title, r.explanation, stamp, stamp);
    else db.prepare("UPDATE compliance_findings SET status='RESOLVED',resolved_at=?,last_detected_at=? WHERE agent_id=? AND finding_key=? AND status IN ('OPEN','ACKNOWLEDGED')").run(stamp, stamp, agentId, r.key);
  }
  return rules.filter((r) => r.active).map((r) => r.key);
}

export function retentionDays() {
  const row = db.prepare("SELECT value FROM app_settings WHERE key='audit_retention_days'").get() as { value?: string } | undefined;
  return Number(row?.value ?? 365);
}

export function purgeExpiredLogs(now = new Date()) {
  const cutoff = new Date(now.getTime() - retentionDays() * 86400000).toISOString();
  const deleted = db.prepare("DELETE FROM log_events WHERE occurred_at<?").run(cutoff).changes;
  if (deleted) appendAuditEvent(null, "LOG_RETENTION_PURGED", "log_events", null, { deleted, cutoff, retentionDays: retentionDays() });
  return deleted;
}

export type LogQuery = { source?: string; event?: string; actor?: string; srcIp?: string; result?: string; host?: string; from?: string; to?: string; limit?: number; agentId?: number; severity?: string; search?: string; beforeTime?: string; beforeId?: number };
export function queryLogs(q: LogQuery) {
  const where: string[] = []; const params: unknown[] = [];
  const eq = (column: string, value?: string) => { if (value) { where.push(`${column}=?`); params.push(value); } };
  eq("l.source", q.source); eq("l.event", q.event); eq("l.actor", q.actor); eq("l.src_ip", q.srcIp); eq("l.result", q.result); eq("l.host", q.host);
  eq("l.severity", q.severity);
  if (q.agentId) { where.push("l.agent_id=?"); params.push(q.agentId); }
  if (q.search) {
    const term = `%${q.search.replace(/[\\%_]/g, "\\$&")}%`;
    where.push("(l.event LIKE ? ESCAPE '\\' OR l.host LIKE ? ESCAPE '\\' OR l.actor LIKE ? ESCAPE '\\' OR l.src_ip LIKE ? ESCAPE '\\' OR l.details_json LIKE ? ESCAPE '\\')");
    params.push(term, term, term, term, term);
  }
  if (q.beforeTime && q.beforeId) {
    where.push("(l.occurred_at<? OR (l.occurred_at=? AND l.id<?))");
    params.push(q.beforeTime, q.beforeTime, q.beforeId);
  }
  if (q.from) { where.push("l.occurred_at>=?"); params.push(q.from); }
  if (q.to) { where.push("l.occurred_at<=?"); params.push(q.to); }
  const limit = Math.min(Math.max(Math.trunc(q.limit ?? 200) || 200, 1), 1000);
  return db.prepare(`SELECT l.id,l.agent_id AS agentId,a.name AS agent,l.source,l.event,l.host,l.actor,l.src_ip AS srcIp,l.result,l.severity,l.details_json AS detailsJson,l.occurred_at AS occurredAt,l.received_at AS receivedAt
    FROM log_events l JOIN agents a ON a.id=l.agent_id ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY l.occurred_at DESC,l.id DESC LIMIT ?`).all(...params, limit);
}

export function logSummary(since: string) {
  return db.prepare("SELECT source,event,COUNT(*) AS count,MAX(occurred_at) AS lastSeen FROM log_events WHERE occurred_at>=? GROUP BY source,event ORDER BY source,count DESC").all(since);
}
