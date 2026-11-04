import { db, type ProjectRow } from "./database.js";

// Persistent WebSocket monitors: one socket per WEBSOCKET project, reconnecting with backoff. Every period without a
// connection is stored as a "gap", which is what health item 4 judges (<3 s = Warning, longer or still down = Critical).
db.exec(`
  CREATE TABLE IF NOT EXISTS ws_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL, ended_at TEXT, seconds REAL, reason TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ws_gaps_project ON ws_gaps(project_id, started_at DESC);
`);
// A gap left open by a previous process has no known end.
db.prepare("UPDATE ws_gaps SET ended_at=started_at,seconds=NULL,reason='server restart' WHERE ended_at IS NULL").run();

type Watcher = { target: string; timeoutMs: number; socket?: WebSocket; connected: boolean; connectedAt: number | null; connectMs: number | null; gapId: number | null; gapStart: number | null; attempt: number; timer?: NodeJS.Timeout; stopped: boolean };
const watchers = new Map<number, Watcher>();
const BACKOFF_MS = [500, 1000, 2000, 5000, 10000, 30000];

function openGap(projectId: number, w: Watcher, reason: string) {
  if (w.gapId !== null) return;
  w.gapStart = Date.now();
  w.gapId = Number(db.prepare("INSERT INTO ws_gaps(project_id,started_at,reason) VALUES(?,?,?)").run(projectId, new Date(w.gapStart).toISOString(), reason.slice(0, 200)).lastInsertRowid);
}
function closeGap(w: Watcher) {
  if (w.gapId === null || w.gapStart === null) return;
  const now = Date.now();
  db.prepare("UPDATE ws_gaps SET ended_at=?,seconds=? WHERE id=?").run(new Date(now).toISOString(), (now - w.gapStart) / 1000, w.gapId);
  w.gapId = null; w.gapStart = null;
}

function connect(projectId: number, w: Watcher) {
  if (w.stopped) return;
  const began = Date.now();
  let socket: WebSocket;
  try { socket = new WebSocket(w.target); } catch (error) { return lost(projectId, w, error instanceof Error ? error.message : "Invalid WebSocket URL"); }
  w.socket = socket;
  let done = false;
  const timeout = setTimeout(() => socket.close(), w.timeoutMs);
  const fail = (reason: string) => { if (done) return; done = true; clearTimeout(timeout); lost(projectId, w, reason); };
  socket.addEventListener("open", () => { clearTimeout(timeout); w.connected = true; w.connectedAt = Date.now(); w.connectMs = w.connectedAt - began; w.attempt = 0; closeGap(w); });
  socket.addEventListener("close", () => fail("Connection closed"));
  socket.addEventListener("error", () => fail("Connection error"));
}

function lost(projectId: number, w: Watcher, reason: string) {
  w.connected = false; w.connectedAt = null;
  openGap(projectId, w, reason);
  const delay = BACKOFF_MS[Math.min(w.attempt++, BACKOFF_MS.length - 1)];
  w.timer = setTimeout(() => connect(projectId, w), delay);
  w.timer.unref();
}

function stop(projectId: number) {
  const w = watchers.get(projectId); if (!w) return;
  w.stopped = true; clearTimeout(w.timer);
  try { w.socket?.close(); } catch { /* already closed */ }
  closeGap(w); watchers.delete(projectId);
}

// Called every scheduler tick: start watchers for new/changed monitors, stop the ones that were removed, disabled or put in maintenance.
export function syncWatchers() {
  const rows = db.prepare("SELECT id,target,timeout_seconds FROM projects WHERE monitor_type='WEBSOCKET' AND enabled=1 AND maintenance=0 AND target IS NOT NULL").all() as Array<Pick<ProjectRow, "id" | "target" | "timeout_seconds">>;
  const wanted = new Set(rows.map((r) => r.id));
  for (const id of [...watchers.keys()]) if (!wanted.has(id) || watchers.get(id)!.target !== rows.find((r) => r.id === id)!.target) stop(id);
  for (const r of rows) if (!watchers.has(r.id)) {
    const w: Watcher = { target: r.target!, timeoutMs: r.timeout_seconds * 1000, connected: false, connectedAt: null, connectMs: null, gapId: null, gapStart: null, attempt: 0, stopped: false };
    watchers.set(r.id, w); openGap(r.id, w, "starting"); connect(r.id, w);
  }
  db.prepare("DELETE FROM ws_gaps WHERE started_at<?").run(new Date(Date.now() - 30 * 86400000).toISOString());
}

export function stopWatchers() { for (const id of [...watchers.keys()]) stop(id); }

export function wsStatus(projectId: number) {
  const w = watchers.get(projectId);
  return w ? { connected: w.connected, connectedForSeconds: w.connectedAt ? (Date.now() - w.connectedAt) / 1000 : 0, connectMs: w.connectMs, downForSeconds: w.gapStart ? (Date.now() - w.gapStart) / 1000 : 0 } : undefined;
}

// Seconds the stream is currently down, or else the longest gap that ended in the last 10 minutes (so a short drop stays visible as a Warning).
export function wsDropoutSeconds(projectId: number, now = new Date()): number | null {
  const status = wsStatus(projectId);
  if (!status) return null;
  if (!status.connected) return Math.round(status.downForSeconds * 100) / 100;
  const since = new Date(now.getTime() - 600000).toISOString();
  const row = db.prepare("SELECT MAX(seconds) AS s FROM ws_gaps WHERE project_id=? AND ended_at>=? AND reason!='starting' AND reason!='server restart'").get(projectId, since) as { s: number | null };
  return Math.round((row.s ?? 0) * 100) / 100;
}
