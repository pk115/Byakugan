#!/usr/bin/env node
// Full-loop test of the Health Check standard on a THROWAWAY instance (temp data dir, port 3197): metric -> level -> notification
// -> incident -> recovery for all ten items, plus evidence export. Needs `npm run build` first. Takes about 6-8 minutes.
//   node scripts/health-loop-test.mjs
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const Database = require("better-sqlite3");
const { WebSocketServer } = require("ws");
const root = fileURLToPath(new URL("..", import.meta.url));
const PORT = 3197, BASE = `http://127.0.0.1:${PORT}`, HOOK_PORT = 3196, WS_PORT = 3195;
const dataDir = mkdtempSync(join(tmpdir(), "byakugan-loop-"));
const results = [];
let cookie = "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const check = (name, ok, detail = "") => { results.push({ name, ok }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`); };
const iso = (minutesAgo = 0) => new Date(Date.now() - minutesAgo * 60000).toISOString();

async function api(method, path, body, headers = {}) {
  const res = await fetch(BASE + path, { method, headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(cookie ? { cookie } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const set = res.headers.getSetCookie?.() ?? [];
  if (set.length) cookie = set.map((c) => c.split(";")[0]).join("; ");
  const buffer = Buffer.from(await res.arrayBuffer());
  let json; try { json = JSON.parse(buffer.toString("utf8")); } catch { /* binary or empty */ }
  return { status: res.status, json, buffer };
}

// ---- stand-ins for the outside world: webhook receivers (Help desk + everyone else) and a WebSocket stream
const hooks = { helpdesk: [], other: [] };
const hookServer = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { (hooks[req.url.slice(1)] ??= []).push(JSON.parse(b || "{}").text ?? b); res.end("ok"); }); }).listen(HOOK_PORT, "127.0.0.1");
let wss;
const startWs = () => new Promise((resolve) => { wss = new WebSocketServer({ port: WS_PORT, host: "127.0.0.1" }); wss.once("listening", resolve); });
const stopWs = async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); };

const server = spawn(process.execPath, ["dist-server/server.js"], { cwd: root, env: { ...process.env, SUPAPULSE_DATA_DIR: dataDir, SUPAPULSE_PORT: String(PORT), SUPAPULSE_HOST: "127.0.0.1" }, stdio: ["ignore", "pipe", "pipe"] });
let serverLog = ""; server.stdout.on("data", (d) => (serverLog += d)); server.stderr.on("data", (d) => (serverLog += d));

async function level(no, label) {
  const item = (await api("GET", "/api/health")).json.items.find((i) => i.no === no);
  const s = label ? item.subjects.find((x) => x.label.startsWith(label)) : item.subjects[0];
  return s ? { level: s.level, value: s.value } : { level: "MISSING", value: null };
}
async function waitLevel(no, label, want, timeoutMs = 100000) {
  const end = Date.now() + timeoutMs; let got;
  while (Date.now() < end) { got = await level(no, label); if (got.level === want) return check(`item ${no} ${label ?? ""} -> ${want}`, true, `value ${got.value}`), got; await sleep(3000); }
  return check(`item ${no} ${label ?? ""} -> ${want}`, false, `last ${got.level} (${got.value})`), got;
}

let agentToken, db;
const ingest = (cpu, mem, freeC, minutesAgo) => api("POST", "/api/agent/ingest", {
  agentVersion: "loop-test", observedAt: iso(minutesAgo), hostname: "loop-vm",
  inventory: { osName: "Windows Server", architecture: "x64", cpuModel: "test", cpuCount: 4, totalMemoryBytes: 8e9 },
  metrics: { cpuPercent: cpu, memoryPercent: mem, uptimeSeconds: 1000, disks: [{ mount: "C:", totalBytes: 100, usedBytes: 100 - freeC, usedPercent: 100 - freeC }], containers: [] }
}, { Authorization: `Bearer ${agentToken}`, cookie: "" });
const shipLog = (event, source = "host", details = {}) => api("POST", "/api/agent/logs", { events: [{ source, event, timestamp: iso(0), severity: "info", details }] }, { Authorization: `Bearer ${agentToken}`, cookie: "" });
const mkProject = async (body) => (await api("POST", "/api/projects", { retryCount: 0, timeoutSeconds: 3, intervalSeconds: 20, ...body })).json?.id;

try {
  for (let i = 0; i < 40; i++) { try { if ((await fetch(BASE + "/health")).ok) break; } catch { /* starting */ } await sleep(500); }
  check("server starts", (await api("GET", "/health")).status === 200);
  await api("POST", "/api/setup", { username: "loop-admin", password: "Loop-Test-Pass-4821" });
  check("admin session", (await api("GET", "/api/session")).json?.authenticated === true);
  db = new Database(join(dataDir, "supapulse.db")); db.pragma("busy_timeout = 5000");
  agentToken = (await api("POST", "/api/agents", { name: "loop-vm" })).json.token;
  const mkHook = async (name, path, helpDesk) => { const id = (await api("POST", "/api/notifications", { name, type: "WEBHOOK", url: `http://127.0.0.1:${HOOK_PORT}/${path}`, enabled: true })).json.id; if (helpDesk) await api("PUT", `/api/notifications/${id}/help-desk`, { helpDesk: true }); return id; };
  await mkHook("loop-helpdesk", "helpdesk", true); await mkHook("loop-other", "other", false);
  await api("PUT", "/api/health/policies/7", { warningValue: 0.7, criticalValue: 1.2, durationSeconds: 0, enabled: true }); // minutes; health runs every 30 s, so a fresh event reads 0-0.5 (Normal), then 1.0 (Warning), 1.5 (Critical)
  await api("PUT", "/api/health/log-sources", { sources: ["host", "nginx"] });
  await startWs();

  console.log("\n== items 1-3: agent metrics (CPU sustained, RAM, drive C:)");
  await ingest(90, 80, 8, 3); await ingest(92, 80, 8, 0);
  await waitLevel(1, "loop-vm", "CRITICAL"); await waitLevel(2, "loop-vm", "WARNING"); await waitLevel(3, "loop-vm", "CRITICAL");
  check("critical CPU opened an incident", (await api("GET", "/api/incidents")).json.some((i) => /CPU/i.test(i.projectName) && !i.resolvedAt));

  console.log("\n== items 4, 5, 8, 9, 6: monitors");
  const pingOk = await mkProject({ name: "ping-local", monitorType: "PING", target: "127.0.0.1" });
  await mkProject({ name: "ping-unreachable", monitorType: "PING", target: "192.0.2.1" });
  await mkProject({ name: "tls-domain", monitorType: "SSL", target: "byakugan.uncledev.net", sslPort: 443 });
  await mkProject({ name: "vitals-stream", monitorType: "WEBSOCKET", target: `ws://127.0.0.1:${WS_PORT}` });
  const sla = await mkProject({ name: "sla-site", monitorType: "TCP", tcpHost: "127.0.0.1", tcpPort: PORT, intervalSeconds: 86400 });
  const mongo = await mkProject({ name: "atlas-sim", monitorType: "DATABASE", databaseEngine: "MONGODB", connectionString: "mongodb://127.0.0.1:1/loop", intervalSeconds: 3600 });
  check("monitors created", [pingOk, sla, mongo].every(Boolean));

  await waitLevel(5, "ping-local", "NORMAL"); await waitLevel(5, "ping-unreachable", "CRITICAL");
  let ssl = await level(8, "tls-domain");
  for (let i = 0; i < 40 && (ssl.level === "NO_DATA" || ssl.level === "MISSING"); i++) { await sleep(3000); ssl = await level(8, "tls-domain"); }
  check("item 8 SSL days measured from the real certificate", ssl.value !== null, `${ssl.value} days left, ${ssl.level}`);
  const days = Math.ceil(ssl.value ?? 60);
  await api("PUT", "/api/health/policies/8", { warningValue: days + 5, criticalValue: 0, durationSeconds: 0, enabled: true }); await waitLevel(8, "tls-domain", "WARNING");
  await api("PUT", "/api/health/policies/8", { warningValue: days + 20, criticalValue: days + 10, durationSeconds: 0, enabled: true }); await waitLevel(8, "tls-domain", "CRITICAL");
  await api("PUT", "/api/health/policies/8", { warningValue: 30, criticalValue: 15, durationSeconds: 0, enabled: true }); await waitLevel(8, "tls-domain", ssl.level);

  await waitLevel(4, "vitals-stream", "NORMAL");
  for (const c of wss.clients) c.terminate();
  await waitLevel(4, "vitals-stream", "WARNING");
  await stopWs(); await waitLevel(4, "vitals-stream", "CRITICAL");
  await startWs(); await sleep(35000);
  db.prepare("UPDATE ws_gaps SET ended_at=?").run(iso(60)); // pretend the 10 minute memory has passed
  await waitLevel(4, "vitals-stream", "NORMAL");

  const beat = db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at) VALUES(?,?,5,1,?)");
  const fill = (up, down) => { db.prepare("DELETE FROM heartbeats WHERE project_id=?").run(sla); db.transaction(() => { for (let i = 0; i < up; i++) beat.run(sla, "UP", iso(0)); for (let i = 0; i < down; i++) beat.run(sla, "DOWN", iso(0)); })(); };
  fill(1000, 0); await waitLevel(9, "sla-site", "NORMAL"); fill(1000, 2); await waitLevel(9, "sla-site", "WARNING"); fill(1000, 20); await waitLevel(9, "sla-site", "CRITICAL");
  fill(1000, 0); await waitLevel(9, "sla-site", "NORMAL");

  const metric = db.prepare("INSERT INTO database_metrics(project_id,engine,connections_used,connections_max,replication_lag_seconds,details_json,observed_at) VALUES(?,?,?,?,?,'{}',?)");
  metric.run(mongo, "MONGODB", 50, 100, 0, iso(0)); await waitLevel(6, "atlas-sim", "NORMAL");
  metric.run(mongo, "MONGODB", 85, 100, 0, iso(0)); await waitLevel(6, "atlas-sim", "WARNING");
  metric.run(mongo, "MONGODB", 10, 100, 6, iso(0)); await waitLevel(6, "atlas-sim", "CRITICAL");
  metric.run(mongo, "MONGODB", 10, 100, 0, iso(0)); await waitLevel(6, "atlas-sim", "NORMAL");

  console.log("\n== item 7: log freshness (expected sources host and nginx)");
  await shipLog("SUDO_COMMAND"); await waitLevel(7, "host", "NORMAL");
  await waitLevel(7, "nginx", "CRITICAL"); // never sent anything
  await waitLevel(7, "host", "WARNING"); await waitLevel(7, "host", "CRITICAL"); // silent for 0.7 then 1.2 minutes
  await shipLog("SUDO_COMMAND"); await shipLog("HTTP_REQUEST", "nginx"); await waitLevel(7, "host", "NORMAL"); await waitLevel(7, "nginx", "NORMAL");

  console.log("\n== item 10: backups reported through log events");
  const details = { database: "loopdb", file: "loopdb.dump", size_mb: 12 };
  await shipLog("DB_BACKUP_COMPLETE", "db", details); await waitLevel(10, "loopdb", "NORMAL");
  await shipLog("DB_BACKUP_FAILED", "db", { ...details, error: "disk full" }); await waitLevel(10, "loopdb", "CRITICAL");
  await shipLog("DB_BACKUP_COMPLETE", "db", details); await waitLevel(10, "loopdb", "NORMAL");

  console.log("\n== recovery of items 1-3");
  await ingest(20, 40, 50, 0);
  await waitLevel(1, "loop-vm", "NORMAL"); await waitLevel(2, "loop-vm", "NORMAL"); await waitLevel(3, "loop-vm", "NORMAL");

  console.log("\n== notifications, incidents, evidence");
  await shipLog("SUDO_COMMAND"); await shipLog("HTTP_REQUEST", "nginx"); // the log sources fell silent again while the other steps ran, which is correct (new Critical incidents)
  await waitLevel(7, "host", "NORMAL"); await waitLevel(7, "nginx", "NORMAL");
  const has = (list, re) => list.some((t) => re.test(t));
  check("Help desk channel got Warning, Critical and Recovery", has(hooks.helpdesk, /🟡/) && has(hooks.helpdesk, /🔴/) && has(hooks.helpdesk, /🟢/), `${hooks.helpdesk.length} messages`);
  check("other channel got Critical and Recovery but no Warning", has(hooks.other, /🔴/) && has(hooks.other, /🟢/) && !has(hooks.other, /🟡/), `${hooks.other.length} messages`);
  const healthIncidents = (await api("GET", "/api/incidents")).json.filter((i) => i.projectName.includes(" · ")); // monitor incidents have no " · "
  const stillOpen = healthIncidents.filter((i) => !i.resolvedAt);
  check("critical items opened Health Check incidents", healthIncidents.length >= 8, `${healthIncidents.length} incidents`);
  // The unreachable ping is still down, and the monthly SLA of the stream that was deliberately cut stays below target until next month.
  check("recovered items closed theirs; only the unreachable ping and the monthly SLA stay open", stillOpen.length >= 1 && stillOpen.every((i) => /ping-unreachable|Service uptime SLA/.test(i.projectName)), `open: ${stillOpen.map((i) => i.projectName).join(" ; ")}`);
  const zip = await api("GET", "/api/audit/export");
  check("evidence ZIP has health-check.csv, health-history.csv, log-events.csv", zip.status === 200 && ["health-check.csv", "health-history.csv", "log-events.csv"].every((n) => zip.buffer.includes(n)));
  const pdf = await api("GET", "/api/health/report");
  check("Health Check PDF", pdf.status === 200 && pdf.buffer.subarray(0, 5).toString() === "%PDF-", `${pdf.buffer.length} bytes`);
  const chain = (await api("GET", "/api/audit/verify")).json;
  check("audit chain still valid", chain?.valid === true || chain?.auditChain?.valid === true, JSON.stringify(chain).slice(0, 80));
  check("server log has no errors", !/"level":50/.test(serverLog));
} catch (error) {
  check("test script ran to the end", false, error instanceof Error ? error.stack : String(error));
} finally {
  server.kill(); hookServer.close(); try { await stopWs(); } catch { /* already stopped */ }
  try { db?.close(); } catch { /* ignore */ }
  await sleep(500); rmSync(dataDir, { recursive: true, force: true });
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed${failed.length ? "; FAILED: " + failed.map((f) => f.name).join(" | ") : ""}`);
  process.exit(failed.length ? 1 : 0);
}
