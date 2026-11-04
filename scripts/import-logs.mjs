#!/usr/bin/env node
// Ships CSV log exports (audit, db, firewall, host, nginx, vpn) to POST /api/agent/logs.
// Usage: node scripts/import-logs.mjs <dir> --url https://byakugan.example.com --token <agent token> [--dry-run]
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export function parseCsv(text) {
  const rows = []; let row = [], cell = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else quoted = false; } else cell += c; }
    else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cell); cell = ""; if (row.length > 1 || row[0] !== "") rows.push(row); row = []; }
    else cell += c;
  }
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  const [header, ...body] = rows;
  return body.map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
}

const pick = (row, keys) => Object.fromEntries(keys.filter((k) => row[k] !== undefined && row[k] !== "").map((k) => [k, row[k].slice(0, 1000)]));
const failed = (s) => /FAILED|DENIED/.test(s);

// Per-file mapping from the sample export columns to the normalized event.
const mappers = {
  audit_logs: (r) => ({ source: "app-audit", event: r.action, timestamp: r.timestamp, actor: r.username, srcIp: r.ip, result: r.status || "success", severity: "info", details: pick(r, ["role", "resource", "resource_id", "method", "user_id"]) }),
  db_logs: (r) => ({ source: "db", event: r.event, timestamp: r.timestamp, host: r.host, actor: r.user, srcIp: r.src_ip, result: r.result, severity: failed(r.event) ? "warning" : "info", details: pick(r, ["database", "mechanism", "error", "command", "target_user", "role", "tool", "job", "collection", "size_mb", "file", "sha256", "target_database", "duration_seconds"]) }),
  firewall_logs: (r) => ({ source: "firewall", event: `FIREWALL_${r.action}`, timestamp: r.timestamp, host: r.device, srcIp: r.src_ip, result: r.action.toLowerCase(), severity: ["debug", "info", "notice", "warning", "error", "critical"].includes(r.severity) ? r.severity : "info", details: pick(r, ["direction", "protocol", "src_port", "dst_ip", "dst_port", "rule"]) }),
  host_logs: (r) => ({ source: "host", event: r.event, timestamp: r.timestamp, host: r.host, actor: r.user, srcIp: r.src_ip, result: r.result, severity: ["debug", "info", "notice", "warning", "error", "critical"].includes(r.severity) ? r.severity : "info", details: pick(r, ["host_ip", "source", "auth_method", "reason", "session_seconds", "run_as", "tty", "command", "service"]) }),
  nginx_access_logs: (r) => { const status = Number(r.status); return { source: "nginx", event: "HTTP_REQUEST", timestamp: r.timestamp, host: r.host, srcIp: r.remote_addr, result: r.status, severity: status >= 500 ? "error" : status >= 400 ? "warning" : "info", details: { ...pick(r, ["server_name", "method", "request_uri", "body_bytes_sent", "request_time", "upstream_addr", "http_user_agent", "http_referer"]), status } }; },
  vpn_logs: (r) => ({ source: "vpn", event: r.event, timestamp: r.timestamp, host: r.server, actor: r.user, srcIp: r.src_ip, result: r.result, severity: failed(r.event) ? "warning" : "info", details: pick(r, ["protocol", "assigned_ip", "mfa", "duration_seconds", "bytes_in", "bytes_out", "reason"]) })
};

export function normalize(kind, row) {
  const event = mappers[kind](row);
  for (const key of ["host", "actor", "srcIp", "result"]) if (!event[key]) delete event[key];
  return event;
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
  const dir = args.find((a) => !a.startsWith("--") && a !== opt("url") && a !== opt("token"));
  const dryRun = args.includes("--dry-run");
  const url = (opt("url") ?? "").replace(/\/$/, ""), token = opt("token") ?? process.env.BYAKUGAN_AGENT_TOKEN;
  if (!dir || (!dryRun && (!url || !token))) { console.error("Usage: import-logs.mjs <dir> --url <server> --token <agent token> [--dry-run]"); process.exit(2); }
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".csv")).sort()) {
    const kind = Object.keys(mappers).find((k) => file.endsWith(`${k}.csv`));
    if (!kind) { console.log(`skip ${file}`); continue; }
    const events = parseCsv(readFileSync(join(dir, file), "utf8")).map((r) => normalize(kind, r));
    let accepted = 0, duplicates = 0;
    for (let i = 0; i < events.length && !dryRun; i += 500) {
      const response = await fetch(`${url}/api/agent/logs`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ events: events.slice(i, i + 500) }) });
      if (!response.ok) { console.error(`${file}: HTTP ${response.status} ${await response.text()}`); process.exit(1); }
      const result = await response.json(); accepted += result.accepted; duplicates += result.duplicates;
    }
    console.log(dryRun ? `${file}: ${events.length} events (dry run) e.g. ${JSON.stringify(events[0])}` : `${file}: ${accepted} accepted, ${duplicates} duplicates`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
