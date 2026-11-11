import { activeFindingStatusSql } from "./finding-status.js";
import { db } from "./database.js";
import { appendAuditEvent } from "./audit.js";
import { dispatchHealthNotification } from "./notifications.js";
import { wsDropoutSeconds } from "./ws-watcher.js";

export type Level = "NORMAL" | "WARNING" | "CRITICAL" | "NO_DATA";
export type Policy = {
  no: number; nameTh: string; nameEn: string; checkTh: string; frequencyTh: string; metricKey: string; unit: string;
  direction: "HIGH" | "LOW"; warningValue: number | null; criticalValue: number | null; warningInclusive: number; durationSeconds: number; enabled: number;
};
export type Subject = { key: string; agentId?: number; label: string; value: number | null; observedAt: string | null; sustained?: boolean; note?: string; staleMs?: number; forceLevel?: Level; detail?: string };

db.exec(`
  CREATE TABLE IF NOT EXISTS health_policies (
    no INTEGER PRIMARY KEY, name_th TEXT NOT NULL, name_en TEXT NOT NULL, check_th TEXT NOT NULL, frequency_th TEXT NOT NULL,
    metric_key TEXT NOT NULL UNIQUE, unit TEXT NOT NULL DEFAULT '', direction TEXT NOT NULL CHECK(direction IN ('HIGH','LOW')),
    warning_value REAL, critical_value REAL, warning_inclusive INTEGER NOT NULL DEFAULT 1, duration_seconds INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS health_state (
    policy_no INTEGER NOT NULL REFERENCES health_policies(no) ON DELETE CASCADE, subject_key TEXT NOT NULL,
    label TEXT NOT NULL, level TEXT NOT NULL, value REAL, note TEXT, since TEXT NOT NULL, evaluated_at TEXT NOT NULL,
    PRIMARY KEY (policy_no, subject_key)
  );
  CREATE TABLE IF NOT EXISTS health_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, policy_no INTEGER NOT NULL REFERENCES health_policies(no) ON DELETE CASCADE,
    subject_key TEXT NOT NULL, label TEXT NOT NULL, from_level TEXT, to_level TEXT NOT NULL, value REAL, at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_health_history_time ON health_history(at);
`);

// The standard's 10 items. INSERT OR IGNORE so edits made in the UI survive restarts.
const SEED: Array<[number, string, string, string, string, string, string, "HIGH" | "LOW", number | null, number | null, number, number]> = [
  [1, "NIPA Cloud VM - CPU Usage", "NIPA Cloud VM - CPU usage", "ตรวจเช็คผ่าน NIPA Console / Windows Task Manager / Uptime Kuma Health API", "ทุกวัน", "cpu_percent", "%", "HIGH", 70, 85, 1, 300],
  [2, "NIPA Cloud VM - RAM Usage", "NIPA Cloud VM - RAM usage", "ตรวจเช็คผ่าน Windows Resource Monitor / Uptime Kuma Health API", "ทุกวัน", "ram_percent", "%", "HIGH", 75, 90, 1, 0],
  [3, "NIPA Cloud Storage Volume (Drive C:)", "NIPA Cloud storage volume (drive C:) free space", "ตรวจเช็คพื้นที่ว่างในไดรฟ์ Windows Server C:\\", "ทุกสัปดาห์", "disk_c_free_percent", "%", "LOW", 25, 10, 1, 0],
  [4, "Vitals WebSockets Stream", "Vitals WebSockets stream", "ตรวจสอบสถานะการเชื่อมต่อสตรีมสัญญาณชีพและกล้องผ่าน Uptime Kuma (WSS)", "Real-time / ทุกวัน", "wss_dropout_seconds", "s", "HIGH", 0, 3, 0, 0],
  [5, "NIPA Cloud Network Bandwidth", "NIPA Cloud network latency", "ตรวจเช็ค Network Latency & Ping ผ่าน Uptime Kuma / NIPA Console", "ทุกวัน", "network_latency_ms", "ms", "HIGH", 50, 150, 1, 0],
  [6, "MongoDB Atlas Cluster Health", "MongoDB Atlas cluster health", "ตรวจเช็ค Connection & Replication บน MongoDB Atlas Cloud Dashboard", "ทุกวัน", "mongo_connections_percent", "%", "HIGH", 80, 90, 1, 0],
  [7, "Centralized Audit Logs Sync", "Centralized audit logs sync", "ตรวจเช็คการบันทึก Log และการจัดเก็บ Event Logs 90 วัน", "ทุกวัน", "log_gap_minutes", "min", "HIGH", 5, 60, 0, 0],
  [8, "SSL/TLS Domain Certificate", "SSL/TLS certificate expiry", "ตรวจเช็ควันหมดอายุ SSL โดเมนผ่าน Uptime Kuma (TLS Monitor)", "ทุกเดือน", "ssl_days_left", "days", "LOW", 30, 15, 1, 0],
  [9, "NIPA Cloud Service Uptime SLA", "Service uptime SLA", "ตรวจเช็ค Uptime SLA รายเดือนผ่าน Uptime Kuma & NIPA Status Page", "ทุกเดือน", "uptime_sla_percent", "%", "LOW", 99.9, 99.0, 0, 0],
  [10, "Automated Cloud Backup Status", "Automated cloud backup status", "ตรวจเช็ครายงาน Daily Snapshot Backup บน NIPA Cloud / Windows Backup", "ทุกวัน", "backup_age_ratio", "x", "HIGH", 1, 2, 0, 0]
];
const seed = db.prepare("INSERT OR IGNORE INTO health_policies(no,name_th,name_en,check_th,frequency_th,metric_key,unit,direction,warning_value,critical_value,warning_inclusive,duration_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
db.transaction(() => { for (const row of SEED) seed.run(...row); })();
// Item 10 first shipped as absolute hours; it is now age / the connector's own max_age_hours (late > 1x, critical > 2x or failed).
db.prepare("UPDATE health_policies SET metric_key='backup_age_ratio',unit='x',warning_value=1,critical_value=2 WHERE no=10 AND metric_key='backup_age_hours'").run();

// The old single-tier cpu/memory/disk findings are replaced by the policy engine (keys health_*).
db.prepare("UPDATE compliance_findings SET status='RESOLVED',resolved_at=CURRENT_TIMESTAMP WHERE finding_key IN ('cpu','memory','disk') AND status IN ('OPEN','ACKNOWLEDGED')").run();

const STALE_MS = 15 * 60000;
export const withUnit = (value: unknown, unit: string) => (value === null || value === undefined ? "—" :`${value}${unit === "%" || unit === "x" ? "" : " "}${unit}`);
const POLICY_SQL = `SELECT no,name_th AS nameTh,name_en AS nameEn,check_th AS checkTh,frequency_th AS frequencyTh,metric_key AS metricKey,unit,direction,warning_value AS warningValue,critical_value AS criticalValue,warning_inclusive AS warningInclusive,duration_seconds AS durationSeconds,enabled FROM health_policies`;

export function classify(value: number, p: Pick<Policy, "direction" | "warningValue" | "criticalValue" | "warningInclusive">): Level {
  const { warningValue: w, criticalValue: c, warningInclusive: inc } = p;
  if (p.direction === "HIGH") {
    if (c !== null && value > c) return "CRITICAL";
    if (w !== null && (inc ? value >= w : value > w)) return "WARNING";
  } else {
    if (c !== null && value < c) return "CRITICAL";
    if (w !== null && (inc ? value <= w : value < w)) return "WARNING";
  }
  return "NORMAL";
}

function hostAgents() {
  return db.prepare(`SELECT a.id,a.name,m.cpu_percent AS cpu,m.memory_percent AS memory,m.disks_json AS disks,m.observed_at AS observedAt
    FROM agents a JOIN host_metrics m ON m.id=(SELECT id FROM host_metrics WHERE agent_id=a.id ORDER BY observed_at DESC LIMIT 1)
    WHERE a.enabled=1 AND a.revoked_at IS NULL`).all() as Array<{ id: number; name: string; cpu: number; memory: number; disks: string; observedAt: string }>;
}

// ponytail: CPU "sustained" = every sample in 1.5x the window is above critical and there are >=2 of them;
// reliable only when the agent interval is <= duration/2 (use 60 s), otherwise it degrades to WARNING.
function cpuSubjects(p: Policy, now: Date): Subject[] {
  return hostAgents().map((a) => {
    const since = new Date(now.getTime() - p.durationSeconds * 1500).toISOString();
    const samples = db.prepare("SELECT cpu_percent AS v FROM host_metrics WHERE agent_id=? AND observed_at>=?").all(a.id, since) as Array<{ v: number }>;
    const sustained = p.durationSeconds === 0 || (samples.length >= 2 && p.criticalValue !== null && samples.every((s) => s.v > p.criticalValue!));
    return { key: `agent:${a.id}`, agentId: a.id, label: a.name, value: a.cpu, observedAt: a.observedAt, sustained };
  });
}

// Windows agents report "C:"; Linux agents report "/". Both count as the system volume.
function diskCSubjects(): Subject[] {
  return hostAgents().flatMap((a) => {
    const disk = (JSON.parse(a.disks) as Array<{ mount: string; usedPercent: number }>).find((d) => /^c:?\\?$/i.test(d.mount) || d.mount === "/");
    return disk ? [{ key: `agent:${a.id}`, agentId: a.id, label: `${a.name} (${disk.mount})`, value: Math.round((100 - disk.usedPercent) * 100) / 100, observedAt: a.observedAt }] : [];
  });
}

function sslSubjects(): Subject[] {
  const rows = db.prepare(`SELECT p.id,p.name,p.interval_seconds AS interval,h.metric_value AS days,h.checked_at AS at FROM projects p
    JOIN heartbeats h ON h.id=(SELECT id FROM heartbeats WHERE project_id=p.id AND metric_value IS NOT NULL ORDER BY checked_at DESC LIMIT 1)
    WHERE p.monitor_type='SSL' AND p.enabled=1`).all() as Array<{ id: number; name: string; interval: number; days: number; at: string }>;
  return rows.map((r) => ({ key: `project:${r.id}`, label: r.name, value: r.days, observedAt: r.at, staleMs: Math.max(STALE_MS, r.interval * 2000) }));
}

// ponytail: calendar month in UTC, counted by check results (not wall-clock downtime); needs 20+ checks before it judges.
function slaSubjects(_p: Policy, now: Date): Subject[] {
  const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
  const rows = db.prepare(`SELECT p.id,p.name,SUM(h.status='UP') AS up,COUNT(*) AS total FROM projects p JOIN heartbeats h ON h.project_id=p.id
    WHERE p.enabled=1 AND p.maintenance=0 AND h.status!='PAUSED' AND h.checked_at>=? GROUP BY p.id`).all(monthStart) as Array<{ id: number; name: string; up: number; total: number }>;
  return rows.map((r) => ({ key: `project:${r.id}`, label: r.name, value: r.total >= 20 ? Math.round((r.up / r.total) * 10000) / 100 : null, observedAt: now.toISOString() }));
}

function backupSubjects(_p: Policy, now: Date): Subject[] {
  const rows = [
    ...(db.prepare(`SELECT 'connector:'||c.id AS key,c.name,c.max_age_hours AS maxAge,c.created_at AS created,
      (SELECT MAX(completed_at) FROM backup_evidence WHERE connector_id=c.id AND status='SUCCESS') AS lastOk,
      (SELECT status FROM backup_evidence WHERE connector_id=c.id ORDER BY COALESCE(completed_at,started_at) DESC,id DESC LIMIT 1) AS latest
      FROM backup_connectors c WHERE c.enabled=1 AND c.revoked_at IS NULL`).all() as Array<{ key: string; name: string; maxAge: number; created: string; lastOk: string | null; latest: string | null }>),
    // Evidence created from DB_BACKUP_* log events has no connector; judge it against a 24 h schedule.
    ...(db.prepare(`SELECT 'asset:'||b.asset_name AS key,b.asset_name AS name,24 AS maxAge,MIN(b.created_at) AS created,
      MAX(CASE WHEN b.status='SUCCESS' THEN b.completed_at END) AS lastOk,
      (SELECT status FROM backup_evidence b2 WHERE b2.asset_name=b.asset_name AND b2.connector_id IS NULL ORDER BY COALESCE(b2.completed_at,b2.started_at) DESC,b2.id DESC LIMIT 1) AS latest
      FROM backup_evidence b WHERE b.connector_id IS NULL GROUP BY b.asset_name`).all() as Array<{ key: string; name: string; maxAge: number; created: string; lastOk: string | null; latest: string | null }>)
  ];
  return rows.map((r) => {
    const ageHours = (now.getTime() - new Date(r.lastOk ?? r.created).getTime()) / 3600000;
    return { key: r.key, label: r.name, value: Math.round((ageHours / r.maxAge) * 100) / 100, observedAt: now.toISOString(), forceLevel: r.latest === "FAILED" ? "CRITICAL" as Level : undefined };
  });
}

// Item 5: average latency of the last 4-packet ping; any loss lifts a NORMAL latency to WARNING, >=50% loss or no reply is CRITICAL.
function pingSubjects(p: Policy): Subject[] {
  const rows = db.prepare(`SELECT p.id,p.name,p.interval_seconds AS interval,h.status,h.metric_value AS ms,h.loss_percent AS loss,h.checked_at AS at FROM projects p
    JOIN heartbeats h ON h.id=(SELECT id FROM heartbeats WHERE project_id=p.id ORDER BY checked_at DESC LIMIT 1)
    WHERE p.monitor_type='PING' AND p.enabled=1 AND p.maintenance=0`).all() as Array<{ id: number; name: string; interval: number; status: string; ms: number | null; loss: number | null; at: string }>;
  return rows.map((r) => {
    const loss = r.loss ?? 0;
    const forceLevel: Level | undefined = r.status === "DOWN" || loss >= 50 ? "CRITICAL" : loss > 0 && r.ms !== null && classify(r.ms, p) === "NORMAL" ? "WARNING" : undefined;
    return { key: `project:${r.id}`, label: r.name, detail: loss > 0 ? `loss ${loss}%` : undefined, value: r.ms, observedAt: r.at, staleMs: Math.max(STALE_MS, r.interval * 2000), forceLevel };
  });
}

// Item 6: connection usage of MongoDB monitors; replication lag above 5 s is CRITICAL regardless of connections.
function mongoSubjects(): Subject[] {
  const rows = db.prepare(`SELECT p.id,p.name,p.interval_seconds AS interval,m.connections_used AS used,m.connections_max AS max,m.replication_lag_seconds AS lag,m.observed_at AS at FROM projects p
    JOIN database_metrics m ON m.id=(SELECT id FROM database_metrics WHERE project_id=p.id ORDER BY observed_at DESC LIMIT 1)
    WHERE p.monitor_type='DATABASE' AND p.database_engine='MONGODB' AND p.enabled=1 AND p.maintenance=0`).all() as Array<{ id: number; name: string; interval: number; used: number | null; max: number | null; lag: number | null; at: string }>;
  return rows.map((r) => ({
    key: `project:${r.id}`, label: r.name, detail: r.lag === null ? undefined : `lag ${r.lag}s`, observedAt: r.at, staleMs: Math.max(STALE_MS, r.interval * 2000),
    value: r.used !== null && r.max ? Math.round((r.used / r.max) * 10000) / 100 : null,
    forceLevel: r.lag !== null && r.lag > 5 ? "CRITICAL" as Level : undefined
  }));
}

export function expectedLogSources() {
  const row = db.prepare("SELECT value FROM app_settings WHERE key='expected_log_sources'").get() as { value?: string } | undefined;
  return (row?.value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}
export function setExpectedLogSources(sources: string[]) {
  db.prepare("INSERT INTO app_settings(key,value,updated_at) VALUES('expected_log_sources',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").run(sources.join(","));
}

// Item 7: minutes since the last event of each source an admin expects to be continuous; a source that never arrived is CRITICAL.
// ponytail: only listed sources are judged, so bursty sources (e.g. app audit) do not raise false alarms; 90-day coverage is not checked yet.
function logSyncSubjects(_p: Policy, now: Date): Subject[] {
  return expectedLogSources().map((source) => {
    const last = (db.prepare("SELECT MAX(occurred_at) AS at FROM log_events WHERE source=?").get(source) as { at: string | null }).at;
    return last
      ? { key: `source:${source}`, label: source, value: Math.max(0, Math.round((now.getTime() - new Date(last).getTime()) / 6000) / 10), observedAt: now.toISOString() }
      : { key: `source:${source}`, label: source, detail: "no logs received", value: null, observedAt: now.toISOString(), forceLevel: "CRITICAL" as Level };
  });
}

// Item 4: seconds a persistent WebSocket stream is down (see ws-watcher.ts). No watcher yet means no data.
function wssSubjects(_p: Policy, now: Date): Subject[] {
  const rows = db.prepare("SELECT id,name FROM projects WHERE monitor_type='WEBSOCKET' AND enabled=1 AND maintenance=0").all() as Array<{ id: number; name: string }>;
  return rows.map((r) => ({ key: `project:${r.id}`, label: r.name, value: wsDropoutSeconds(r.id, now), observedAt: now.toISOString() }));
}

const evaluators: Record<string, (p: Policy, now: Date) => Subject[]> = {
  wss_dropout_seconds: wssSubjects,
  network_latency_ms: pingSubjects,
  mongo_connections_percent: mongoSubjects,
  log_gap_minutes: logSyncSubjects,
  ssl_days_left: sslSubjects,
  uptime_sla_percent: slaSubjects,
  backup_age_ratio: backupSubjects,
  cpu_percent: cpuSubjects,
  ram_percent: () => hostAgents().map((a) => ({ key: `agent:${a.id}`, agentId: a.id, label: a.name, value: a.memory, observedAt: a.observedAt })),
  disk_c_free_percent: diskCSubjects
  // Remaining metric_keys have no data source yet (plan phase 2) and report NO_DATA.
};

const rank: Record<Level, number> = { NO_DATA: 0, NORMAL: 1, WARNING: 2, CRITICAL: 3 };
export const worst = (levels: Level[]): Level => levels.reduce<Level>((a, b) => (rank[b] > rank[a] ? b : a), "NO_DATA");

export function evaluateSubjects(p: Policy, now = new Date()) {
  const subjects = evaluators[p.metricKey]?.(p, now) ?? [];
  return subjects.map((s) => {
    const stale = !s.observedAt || now.getTime() - new Date(s.observedAt).getTime() > (s.staleMs ?? STALE_MS);
    // forceLevel: a condition the numeric value cannot express (failed backup, packet loss, replication lag, a source that never arrived).
    let level: Level = stale ? "NO_DATA" : s.forceLevel ?? (s.value === null ? "NO_DATA" : classify(s.value, p));
    if (level === "CRITICAL" && p.direction === "HIGH" && s.sustained === false) level = "WARNING"; // not yet sustained for the full duration
    return { ...s, level };
  });
}

const pending: Array<() => Promise<void>> = [];

function transition(p: Policy, s: ReturnType<typeof evaluateSubjects>[number], from: Level | null, now: string) {
  db.prepare("INSERT INTO health_history(policy_no,subject_key,label,from_level,to_level,value,at) VALUES(?,?,?,?,?,?,?)").run(p.no, s.key, s.label, from, s.level, s.value, now);
  appendAuditEvent(null, "HEALTH_LEVEL_CHANGED", "health_policy", p.no, { subject: s.label, from, to: s.level, value: s.value, unit: p.unit });
  // The incident's source_label must stay the same while the situation changes, so it uses the stable label; details (loss, lag) only go in text.
  const source = `${p.nameEn} · ${s.label}`, name = s.detail ? `${s.label} (${s.detail})` : s.label, text = `${p.no}. ${p.nameTh}\n${name}: ${withUnit(s.value, p.unit)} → ${s.level}`;
  const findingKey = `health_${p.metricKey}`;
  if (s.level === "NORMAL") {
    if (s.agentId) db.prepare("UPDATE compliance_findings SET status='RESOLVED',resolved_at=?,last_detected_at=? WHERE agent_id=? AND finding_key=? AND status IN ('OPEN','ACKNOWLEDGED')").run(now, now, s.agentId, findingKey);
    db.prepare("UPDATE incidents SET resolved_at=? WHERE health_policy_no=? AND source_label=? AND resolved_at IS NULL").run(now, p.no, source);
    if (from === "WARNING" || from === "CRITICAL") pending.push(() => dispatchHealthNotification("HEALTH_RECOVERY", `🟢 ${text}`));
    return;
  }
  if (s.level !== "WARNING" && s.level !== "CRITICAL") return;
  if (s.agentId) db.prepare(`INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at)
    VALUES(?,?,'HEALTH',?,'OPEN',?,?,?,?) ON CONFLICT(agent_id,finding_key) DO UPDATE SET status=${activeFindingStatusSql},severity=excluded.severity,title=excluded.title,explanation=excluded.explanation,last_detected_at=excluded.last_detected_at,resolved_at=NULL`)
    .run(s.agentId, findingKey, s.level === "CRITICAL" ? "CRITICAL" : "MEDIUM", p.nameEn, `${name}: ${withUnit(s.value, p.unit)} (${s.level})`, now, now);
  if (s.level === "CRITICAL") {
    const open = db.prepare("SELECT id FROM incidents WHERE health_policy_no=? AND source_label=? AND resolved_at IS NULL").get(p.no, source);
    if (!open) db.prepare("INSERT INTO incidents(project_id,status,message,started_at,severity,health_policy_no,source_label) VALUES(NULL,'CRITICAL',?,?,'HIGH',?,?)").run(`${name}: ${withUnit(s.value, p.unit)} exceeds the Critical threshold`, now, p.no, source);
    pending.push(() => dispatchHealthNotification("HEALTH_CRITICAL", `🔴 ${text}\nIncident Process required`));
  } else pending.push(() => dispatchHealthNotification("HEALTH_WARNING", `🟡 ${text}\nPlease check or open a Help desk ticket`));
}

export function evaluateHealth(now = new Date()) {
  const stamp = now.toISOString();
  const policies = db.prepare(`${POLICY_SQL} WHERE enabled=1`).all() as Policy[];
  db.transaction(() => {
    for (const p of policies) {
      const subjects = evaluateSubjects(p, now);
      const keep = new Set(subjects.map((s) => s.key));
      for (const row of db.prepare("SELECT subject_key AS k FROM health_state WHERE policy_no=?").all(p.no) as Array<{ k: string }>) // subject was removed (agent revoked, monitor deleted)
        if (!keep.has(row.k)) db.prepare("DELETE FROM health_state WHERE policy_no=? AND subject_key=?").run(p.no, row.k);
      for (const s of subjects) {
      const prev = db.prepare("SELECT level,since FROM health_state WHERE policy_no=? AND subject_key=?").get(p.no, s.key) as { level: Level; since: string } | undefined;
      if (s.level === "NO_DATA" && prev) { db.prepare("UPDATE health_state SET evaluated_at=?,note='stale' WHERE policy_no=? AND subject_key=?").run(stamp, p.no, s.key); continue; } // keep the last actionable level
      const changed = prev?.level !== s.level;
      db.prepare(`INSERT INTO health_state(policy_no,subject_key,label,level,value,note,since,evaluated_at) VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(policy_no,subject_key) DO UPDATE SET label=excluded.label,level=excluded.level,value=excluded.value,note=excluded.note,since=CASE WHEN ?=1 THEN excluded.since ELSE health_state.since END,evaluated_at=excluded.evaluated_at`)
        .run(p.no, s.key, s.label, s.level, s.value, s.detail ?? null, stamp, stamp, changed ? 1 : 0);
      if (changed && !(s.level === "NORMAL" && (!prev || prev.level === "NO_DATA"))) transition(p, s, prev?.level ?? null, stamp);
      }
    }
  })();
  return pending.splice(0);
}

export async function runHealthChecks() {
  try { for (const send of evaluateHealth()) await send().catch(() => undefined); }
  catch (error) { console.error("Health check failed:", error instanceof Error ? error.message : error); }
}

// Same wording as the standard's Normal / Warning / Critical columns, derived from the editable thresholds.
export function thresholdText(p: Pick<Policy, "direction" | "warningValue" | "criticalValue" | "warningInclusive" | "unit" | "durationSeconds">) {
  const u = p.unit === "%" || p.unit === "x" ? p.unit : ` ${p.unit}`, w = p.warningValue, c = p.criticalValue;
  const f = (v: number | null) => (v === null ? "—" : `${v}${u}`);
  const dur = p.durationSeconds ? ` (${Math.round(p.durationSeconds / 60)} min)` : "";
  return p.direction === "HIGH"
    ? { normal: `${p.warningInclusive ? "<" : "≤"} ${f(w)}`, warning: `${f(w)} – ${f(c)}`, critical: `> ${f(c)}${dur}` }
    : { normal: `${p.warningInclusive ? ">" : "≥"} ${f(w)}`, warning: `${f(c)} – ${f(w)}`, critical: `< ${f(c)}` };
}

// Flat rows for CSV / XLSX / PDF sections of the audit report.
export function healthRows() {
  return healthStatus().items.map((i) => ({
    no: i.no, itemEn: i.nameEn, itemTh: i.nameTh, level: i.level,
    measured: i.subjects.length ? i.subjects.map((s) => `${s.label}${s.note && s.note !== "stale" ? ` (${s.note})` : ""}: ${withUnit(s.value, i.unit)}`).join("; ") : "—",
    normal: i.thresholds.normal, warning: i.thresholds.warning, critical: i.thresholds.critical, frequency: i.frequencyTh
  }));
}

export function healthHistory(from: string, to: string) {
  return db.prepare(`SELECT h.at,h.policy_no AS no,p.name_en AS item,h.label AS subject,h.from_level AS fromLevel,h.to_level AS toLevel,h.value,p.unit
    FROM health_history h JOIN health_policies p ON p.no=h.policy_no WHERE h.at BETWEEN ? AND ? ORDER BY h.at`).all(from, to) as Array<Record<string, unknown>>;
}

export function healthStatus() {
  const policies = db.prepare(`${POLICY_SQL} ORDER BY no`).all() as Policy[];
  const states = db.prepare("SELECT policy_no AS policyNo,subject_key AS subjectKey,label,level,value,note,since,evaluated_at AS evaluatedAt FROM health_state").all() as Array<{ policyNo: number; level: Level; [k: string]: unknown }>;
  const items = policies.map((p) => {
    const subjects = states.filter((s) => s.policyNo === p.no);
    return { ...p, thresholds: thresholdText(p), enabled: Boolean(p.enabled), warningInclusive: Boolean(p.warningInclusive), level: p.enabled ? worst(subjects.map((s) => s.level)) : "NO_DATA" as Level, subjects };
  });
  return { items, expectedLogSources: expectedLogSources(), summary: { normal: items.filter((i) => i.level === "NORMAL").length, warning: items.filter((i) => i.level === "WARNING").length, critical: items.filter((i) => i.level === "CRITICAL").length, noData: items.filter((i) => i.level === "NO_DATA").length } };
}

export function updatePolicy(no: number, v: { warningValue: number | null; criticalValue: number | null; durationSeconds: number; enabled: boolean }) {
  const result = db.prepare("UPDATE health_policies SET warning_value=?,critical_value=?,duration_seconds=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE no=?").run(v.warningValue, v.criticalValue, v.durationSeconds, v.enabled ? 1 : 0, no);
  return result.changes > 0;
}
