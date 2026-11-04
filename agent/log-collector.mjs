// Linux log collectors: auth.log (sshd/sudo), nginx access log, journald service state.
// Pure parsers + an offset-persisting reader; the agent loop in supapulse-agent.mjs ships the result.
import { open, stat, readFile, writeFile, mkdir } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { EVENT, statusSeverity } from "./log-mapping.mjs";

const exec = promisify(execFile);
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const cut = (v, n = 1000) => String(v).slice(0, n);
const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== ""));
const event = (e) => clean({ ...e, details: clean(e.details ?? {}) });

function syslogTime(text, now) {
  if (/^\d{4}-/.test(text)) { const d = new Date(text); return Number.isNaN(+d) ? undefined : d.toISOString(); }
  const m = /^([A-Z][a-z]{2})\s+(\d+)\s([\d:]{8})$/.exec(text);
  if (!m) return undefined;
  const [h, mi, s] = m[3].split(":").map(Number);
  const d = new Date(now.getFullYear(), MONTHS.indexOf(m[1]), Number(m[2]), h, mi, s);
  if (d - now > 86400000) d.setFullYear(d.getFullYear() - 1); // Dec lines read in January
  return d.toISOString();
}

const LINE = /^(\S+T\S+|[A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s+(\S+)\s+([\w./-]+)(?:\[\d+\])?:\s+(.*)$/;

/** One /var/log/auth.log (or /var/log/secure) line -> normalized event, or null when not interesting. */
export function parseAuthLine(line, now = new Date()) {
  const m = LINE.exec(line);
  if (!m) return null;
  const [, rawTime, host, proc, msg] = m;
  const timestamp = syslogTime(rawTime, now);
  if (!timestamp) return null;
  const base = { source: "host", timestamp, host };
  let r;
  if (proc === "sshd") {
    if ((r = /^Accepted (\S+) for (\S+) from (\S+) port/.exec(msg)))
      return event({ ...base, event: EVENT.SSH_LOGIN_SUCCESS, actor: r[2], srcIp: r[3], result: "success", severity: "info", details: { auth_method: r[1] } });
    if ((r = /^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port/.exec(msg)))
      return event({ ...base, event: EVENT.SSH_LOGIN_FAILED, actor: r[2], srcIp: r[3], result: "failed", severity: "warning", details: { auth_method: r[1] } });
    if ((r = /^ROOT LOGIN REFUSED FROM (\S+)/.exec(msg)) || (r = /^User root from (\S+) not allowed/.exec(msg)))
      return event({ ...base, event: EVENT.ROOT_LOGIN_DENIED, actor: "root", srcIp: r[1], result: "denied", severity: "warning" });
  } else if (proc === "sudo") {
    if ((r = /^\s*(\S+)\s*: .*?TTY=(\S+) ; PWD=(.*?) ; USER=(\S+) ; COMMAND=(.*)$/.exec(msg)) && !/incorrect password/.test(msg))
      return event({ ...base, event: EVENT.SUDO_COMMAND, actor: r[1], result: "success", severity: "info", details: { tty: r[2], run_as: r[4], command: cut(r[5]) } });
    if ((r = /^pam_unix\(sudo:auth\): authentication failure;.*\buser=(\S+)/.exec(msg)))
      return event({ ...base, event: EVENT.SUDO_AUTH_FAILED, actor: r[1], result: "failed", severity: "warning" });
  }
  return null;
}

const NGINX = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S*)[^"]*" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"(?: (\d+(?:\.\d+)?))?/;
const NGINX_TIME = /^(\d+)\/([A-Za-z]{3})\/(\d{4}):([\d:]{8}) ([+-]\d{2})(\d{2})$/;

/** One nginx "combined" access-log line (optional trailing request_time) -> HTTP_REQUEST event. */
export function parseNginxLine(line, host) {
  const m = NGINX.exec(line), t = m && NGINX_TIME.exec(m[2]);
  if (!m || !t) return null;
  const timestamp = new Date(`${t[3]}-${String(MONTHS.indexOf(t[2]) + 1).padStart(2, "0")}-${t[1].padStart(2, "0")}T${t[4]}${t[5]}:${t[6]}`).toISOString();
  const status = Number(m[5]);
  return event({ source: "nginx", event: EVENT.HTTP_REQUEST, timestamp, host, srcIp: m[1], result: m[5], severity: statusSeverity(status),
    details: { method: m[3], request_uri: cut(m[4]), status, body_bytes_sent: m[6] === "-" ? undefined : Number(m[6]), http_referer: m[7] === "-" ? undefined : cut(m[7]), http_user_agent: cut(m[8]), request_time: m[9] } });
}

/** One `journalctl -o json` record from PID 1 -> SERVICE_* event. */
export function parseJournalEntry(entry) {
  const unit = entry.UNIT;
  if (typeof unit !== "string" || !unit.endsWith(".service")) return null;
  const msg = String(entry.MESSAGE ?? "");
  const name = /^Started /.test(msg) ? EVENT.SERVICE_START : /^Stopped /.test(msg) ? EVENT.SERVICE_STOP : /Scheduled restart job/.test(msg) ? EVENT.SERVICE_RESTART : null;
  if (!name) return null;
  return event({ source: "host", event: name, timestamp: new Date(Number(entry.__REALTIME_TIMESTAMP) / 1000).toISOString(), host: entry._HOSTNAME, result: "success", severity: "info", details: { service: unit } });
}

/**
 * Read complete lines appended since state.offset. state = {offset, ino}. Handles rotation
 * (inode change or truncation -> restart at 0). Returns the new state to persist after a successful send.
 * ponytail: lines written to the old file between the last read and rotation are lost; add rotated-file lookup if that matters.
 */
export async function readNewLines(path, state, { maxBytes = 4_000_000, backfill = false } = {}) {
  let st;
  try { st = await stat(path); } catch { return { lines: [], state }; }
  let offset = state?.offset;
  if (offset === undefined) offset = backfill ? 0 : st.size; // first run: start at EOF unless backfilling
  else if (state.ino !== st.ino || st.size < offset) offset = 0;
  const length = Math.min(st.size - offset, maxBytes);
  if (length <= 0) return { lines: [], state: { offset, ino: st.ino } };
  const handle = await open(path, "r");
  try {
    const buf = Buffer.alloc(length);
    await handle.read(buf, 0, length, offset);
    const end = buf.lastIndexOf(10) + 1; // drop a trailing partial line
    return { lines: buf.subarray(0, end).toString("utf8").split("\n").filter(Boolean), state: { offset: offset + end, ino: st.ino } };
  } finally { await handle.close(); }
}

export async function loadState(file) { try { return JSON.parse(await readFile(file, "utf8")); } catch { return {}; } }
export async function saveState(file, state) { await mkdir(dirname(file), { recursive: true }); await writeFile(file, JSON.stringify(state)); }

async function readJournal(dir, journalDir) {
  const cursorFile = join(dir, "journal.cursor");
  let fresh = false;
  try { await stat(cursorFile); } catch { fresh = true; }
  const args = ["_PID=1", "-o", "json", "--no-pager", `--cursor-file=${cursorFile}`, ...(fresh ? ["--since=-1h"] : []), ...(journalDir ? [`--directory=${journalDir}`] : [])];
  const { stdout } = await exec("journalctl", args, { timeout: 20000, maxBuffer: 20_000_000 });
  return stdout.split("\n").filter(Boolean).map((l) => { try { return parseJournalEntry(JSON.parse(l)); } catch { return null; } }).filter(Boolean);
}

/**
 * Collect new events from every configured source. cfg: {hostname, stateDir, authLog, nginxLog, journal, journalDir, backfill}.
 * Returns {events, commit()}; call commit() only after the server accepted the batch, so a failed send is retried.
 */
export async function collectLogs(cfg) {
  const stateFile = join(cfg.stateDir, "log-state.json");
  const state = await loadState(stateFile), next = { ...state }, events = [];
  const now = new Date();
  for (const [key, path, parse] of [["auth", cfg.authLog, (l) => parseAuthLine(l, now)], ["nginx", cfg.nginxLog, (l) => parseNginxLine(l, cfg.hostname)]]) {
    if (!path) continue;
    const { lines, state: s } = await readNewLines(path, state[key], { backfill: cfg.backfill });
    next[key] = s;
    for (const line of lines) { const e = parse(line); if (e) events.push(e); }
  }
  if (cfg.journal) { try { events.push(...await readJournal(cfg.stateDir, cfg.journalDir)); } catch { /* journalctl missing or unreadable: skip */ } }
  for (const e of events) e.host ??= cfg.hostname;
  return { events, commit: () => saveState(stateFile, next) };
}

// Dry run: node agent/log-collector.mjs --dry-run <auth.log> [nginx.log]   (prints normalized events, sends nothing)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.argv[2] === "--dry-run") {
  const read = async (p) => (await readFile(p, "utf8")).split("\n").filter(Boolean);
  for (const l of await read(process.argv[3])) { const e = parseAuthLine(l); if (e) console.log(JSON.stringify(e)); }
  if (process.argv[4]) for (const l of await read(process.argv[4])) { const e = parseNginxLine(l, "dry-run"); if (e) console.log(JSON.stringify(e)); }
}
