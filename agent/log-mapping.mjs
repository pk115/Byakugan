// Shared by scripts/import-logs.mjs (CSV import) and the agent log collectors: normalized event shape and names.
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
// Event names shared with the sample export; the Windows agent (agent-windows/byakugan-agent.ps1) uses the same strings.
export const EVENT = { LOGIN_SUCCESS: "LOGIN_SUCCESS", LOGIN_FAILED: "LOGIN_FAILED", SSH_LOGIN_SUCCESS: "SSH_LOGIN_SUCCESS", SSH_LOGIN_FAILED: "SSH_LOGIN_FAILED", ROOT_LOGIN_DENIED: "ROOT_LOGIN_DENIED", SUDO_COMMAND: "SUDO_COMMAND", SUDO_AUTH_FAILED: "SUDO_AUTH_FAILED", SERVICE_START: "SERVICE_START", SERVICE_STOP: "SERVICE_STOP", SERVICE_RESTART: "SERVICE_RESTART", HTTP_REQUEST: "HTTP_REQUEST" };
export const statusSeverity = (status) => (status >= 500 ? "error" : status >= 400 ? "warning" : "info");
const failed = (s) => /FAILED|DENIED/.test(s);

// Per-file mapping from the sample export columns to the normalized event.
export const mappers = {
  audit_logs: (r) => ({ source: "app-audit", event: r.action, timestamp: r.timestamp, actor: r.username, srcIp: r.ip, result: r.status || "success", severity: "info", details: pick(r, ["role", "resource", "resource_id", "method", "user_id"]) }),
  db_logs: (r) => ({ source: "db", event: r.event, timestamp: r.timestamp, host: r.host, actor: r.user, srcIp: r.src_ip, result: r.result, severity: failed(r.event) ? "warning" : "info", details: pick(r, ["database", "mechanism", "error", "command", "target_user", "role", "tool", "job", "collection", "size_mb", "file", "sha256", "target_database", "duration_seconds"]) }),
  firewall_logs: (r) => ({ source: "firewall", event: `FIREWALL_${r.action}`, timestamp: r.timestamp, host: r.device, srcIp: r.src_ip, result: r.action.toLowerCase(), severity: ["debug", "info", "notice", "warning", "error", "critical"].includes(r.severity) ? r.severity : "info", details: pick(r, ["direction", "protocol", "src_port", "dst_ip", "dst_port", "rule"]) }),
  host_logs: (r) => ({ source: "host", event: r.event, timestamp: r.timestamp, host: r.host, actor: r.user, srcIp: r.src_ip, result: r.result, severity: ["debug", "info", "notice", "warning", "error", "critical"].includes(r.severity) ? r.severity : "info", details: pick(r, ["host_ip", "source", "auth_method", "reason", "session_seconds", "run_as", "tty", "command", "service"]) }),
  nginx_access_logs: (r) => { const status = Number(r.status); return { source: "nginx", event: EVENT.HTTP_REQUEST, timestamp: r.timestamp, host: r.host, srcIp: r.remote_addr, result: r.status, severity: statusSeverity(status), details: { ...pick(r, ["server_name", "method", "request_uri", "body_bytes_sent", "request_time", "upstream_addr", "http_user_agent", "http_referer"]), status } }; },
  vpn_logs: (r) => ({ source: "vpn", event: r.event, timestamp: r.timestamp, host: r.server, actor: r.user, srcIp: r.src_ip, result: r.result, severity: failed(r.event) ? "warning" : "info", details: pick(r, ["protocol", "assigned_ip", "mfa", "duration_seconds", "bytes_in", "bytes_out", "reason"]) })
};

export function normalize(kind, row) {
  const event = mappers[kind](row);
  for (const key of ["host", "actor", "srcIp", "result"]) if (!event[key]) delete event[key];
  return event;
}
