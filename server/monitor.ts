import { performance } from "node:perf_hooks";
import { Socket } from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { promises as dns } from "node:dns";
import { connect as tlsConnect } from "node:tls";
import { request as httpRequest } from "node:http";
import { db, type ProjectRow } from "./database.js";
import { decrypt } from "./crypto.js";
import { dispatchNotifications } from "./notifications.js";
import { appendAuditEvent } from "./audit.js";
import { probeDatabase, type DatabaseMetrics } from "./database-monitor.js";

export type MonitorStatus =
  | "UP"
  | "DOWN"
  | "PAUSED"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "MISCONFIGURED";

type CheckResult = {
  status: MonitorStatus;
  httpStatus: number | null;
  responseTimeMs: number;
  message: string;
  attempt: number;
  databaseMetrics?: DatabaseMetrics;
};
const execFileAsync = promisify(execFile);

export function statusFromHttp(httpStatus: number): MonitorStatus {
  if (httpStatus === 540) return "PAUSED";
  if (httpStatus === 401) return "UNAUTHORIZED";
  if (httpStatus === 403) return "FORBIDDEN";
  if (httpStatus === 404) return "MISCONFIGURED";
  return "DOWN";
}

async function attemptCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  if (project.monitor_type === "HTTP") return attemptHttpCheck(project, attempt);
  if (project.monitor_type === "TCP") return attemptTcpCheck(project, attempt);
  if (project.monitor_type === "PING") return attemptPingCheck(project, attempt);
  if (project.monitor_type === "DNS") return attemptDnsCheck(project, attempt);
  if (project.monitor_type === "SSL") return attemptSslCheck(project, attempt);
  if (project.monitor_type === "DOCKER") return attemptDockerCheck(project, attempt);
  if (project.monitor_type === "DATABASE") return attemptDatabaseCheck(project,attempt);
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), project.timeout_seconds * 1000);
  try {
    const key = decrypt(project.encrypted_key);
    const endpoint = new URL("/rest/v1/supapulse_heartbeat", project.supabase_url);
    endpoint.searchParams.set("select", "id,value");
    endpoint.searchParams.set("limit", "1");
    const response = await fetch(endpoint, {
      headers: { apikey: key, Authorization: `Bearer ${key}`, Accept: "application/json" },
      signal: controller.signal,
      redirect: "error"
    });
    const elapsed = Math.round(performance.now() - started);
    if (!response.ok) {
      const message = response.status === 540 ? "Supabase project is paused"
        : response.status === 401 ? "Publishable key was rejected (HTTP 401)"
        : response.status === 403 ? "Heartbeat query is forbidden; check grants and RLS (HTTP 403)"
        : response.status === 404 ? "Heartbeat table was not found by the Data API (HTTP 404)"
        : `Supabase returned HTTP ${response.status}`;
      return {
        status: statusFromHttp(response.status), httpStatus: response.status,
        responseTimeMs: elapsed, message, attempt
      };
    }
    const body = await response.json() as Array<{ id?: number; value?: string }>;
    if (Array.isArray(body) && body.length === 0) {
      return {
        status: "MISCONFIGURED", httpStatus: response.status, responseTimeMs: elapsed,
        message: "No readable heartbeat row; check the row and anon RLS policy", attempt
      };
    }
    if (!Array.isArray(body) || body[0]?.id !== 1 || body[0]?.value !== "alive") {
      return {
        status: "MISCONFIGURED", httpStatus: response.status, responseTimeMs: elapsed,
        message: "Heartbeat row must contain id=1 and value=alive", attempt
      };
    }
    return { status: "UP", httpStatus: response.status, responseTimeMs: elapsed, message: "Healthy", attempt };
  } catch (error) {
    const elapsed = Math.round(performance.now() - started);
    const message = error instanceof Error
      ? (error.name === "AbortError" ? "Request timed out" : error.message)
      : "Unknown monitor error";
    return { status: "DOWN", httpStatus: null, responseTimeMs: elapsed, message, attempt };
  } finally {
    clearTimeout(timeout);
  }
}

async function attemptDatabaseCheck(project:ProjectRow,attempt:number):Promise<CheckResult>{const started=performance.now();try{if(!project.database_engine)throw new Error("Database engine is missing");const result=await probeDatabase(project.database_engine,decrypt(project.encrypted_key),project.timeout_seconds);return{status:"UP",httpStatus:null,responseTimeMs:result.responseTimeMs,message:result.message,attempt,databaseMetrics:result.metrics}}catch(error){const code=typeof error==="object"&&error&&"code" in error?String((error as {code:unknown}).code):"QUERY_FAILED";return{status:"DOWN",httpStatus:null,responseTimeMs:Math.round(performance.now()-started),message:`Database connection or monitoring query failed (${code.replace(/[^A-Z0-9_-]/gi,"").slice(0,40)})`,attempt}}}

async function attemptPingCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  const started = performance.now();
  try {
    if (!project.target) throw new Error("Ping hostname is missing");
    const isWindows = process.platform === "win32";
    const args = isWindows
      ? ["-n", "1", "-w", String(project.timeout_seconds * 1000), project.target]
      : ["-c", "1", "-W", String(project.timeout_seconds), project.target];
    await execFileAsync("ping", args, { timeout: (project.timeout_seconds + 1) * 1000 });
    return { status: "UP", httpStatus: null, responseTimeMs: Math.round(performance.now() - started), message: "Host replied to ICMP ping", attempt };
  } catch (error) {
    return { status: "DOWN", httpStatus: null, responseTimeMs: Math.round(performance.now() - started), message: error instanceof Error ? error.message : "Ping failed", attempt };
  }
}

async function attemptDnsCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  const started = performance.now();
  try {
    if (!project.target) throw new Error("DNS hostname is missing");
    const records = await Promise.race([
      dns.resolve(project.target, project.dns_record_type),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("DNS query timed out")), project.timeout_seconds * 1000))
    ]);
    const count = Array.isArray(records) ? records.length : 0;
    if (!count) throw new Error(`No ${project.dns_record_type} records found`);
    return { status: "UP", httpStatus: null, responseTimeMs: Math.round(performance.now() - started), message: `${count} ${project.dns_record_type} record(s) resolved`, attempt };
  } catch (error) {
    return { status: "DOWN", httpStatus: null, responseTimeMs: Math.round(performance.now() - started), message: error instanceof Error ? error.message : "DNS query failed", attempt };
  }
}

async function attemptSslCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  const started = performance.now();
  return new Promise((resolve) => {
    if (!project.target) return resolve({ status: "DOWN", httpStatus: null, responseTimeMs: 0, message: "SSL hostname is missing", attempt });
    const socket = tlsConnect({ host: project.target, port: project.ssl_port, servername: project.target, rejectUnauthorized: true });
    const finish = (status: "UP" | "DOWN", message: string) => {
      const responseTimeMs = Math.round(performance.now() - started);
      socket.destroy(); resolve({ status, httpStatus: null, responseTimeMs, message, attempt });
    };
    socket.setTimeout(project.timeout_seconds * 1000);
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const expires = new Date(cert.valid_to);
      const days = Math.floor((expires.getTime() - Date.now()) / 86400000);
      finish(days < project.ssl_expiry_days ? "DOWN" : "UP", days < project.ssl_expiry_days ? `Certificate expires in ${days} day(s)` : `Certificate valid for ${days} day(s)`);
    });
    socket.once("timeout", () => finish("DOWN", "TLS connection timed out"));
    socket.once("error", (error) => finish("DOWN", error.message));
  });
}

async function attemptDockerCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  const started = performance.now();
  return new Promise((resolve) => {
    if (!project.docker_container) return resolve({ status: "DOWN", httpStatus: null, responseTimeMs: 0, message: "Docker container name or ID is missing", attempt });
    const req = httpRequest({ socketPath: process.env.SUPAPULSE_DOCKER_SOCKET || "/var/run/docker.sock", path: `/containers/${encodeURIComponent(project.docker_container)}/json`, method: "GET", timeout: project.timeout_seconds * 1000 }, (res) => {
      let body = ""; res.setEncoding("utf8"); res.on("data", (chunk) => body += chunk); res.on("end", () => {
        try {
          if (res.statusCode !== 200) throw new Error(`Docker API returned HTTP ${res.statusCode}`);
          const info = JSON.parse(body) as { State?: { Running?: boolean; Status?: string; Health?: { Status?: string } } };
          const running = Boolean(info.State?.Running);
          const health = info.State?.Health?.Status;
          const up = running && health !== "unhealthy";
          resolve({ status: up ? "UP" : "DOWN", httpStatus: res.statusCode ?? null, responseTimeMs: Math.round(performance.now() - started), message: health ? `Container is ${info.State?.Status}, health: ${health}` : `Container is ${info.State?.Status ?? "unknown"}`, attempt });
        } catch (error) { resolve({ status: "DOWN", httpStatus: res.statusCode ?? null, responseTimeMs: Math.round(performance.now() - started), message: error instanceof Error ? error.message : "Invalid Docker response", attempt }); }
      });
    });
    req.once("timeout", () => req.destroy(new Error("Docker API timed out")));
    req.once("error", (error) => resolve({ status: "DOWN", httpStatus: null, responseTimeMs: Math.round(performance.now() - started), message: `${error.message}. Mount the Docker socket to enable this monitor.`, attempt }));
    req.end();
  });
}

async function attemptHttpCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), project.timeout_seconds * 1000);
  try {
    if (!project.target) throw new Error("HTTP target URL is missing");
    const response = await fetch(project.target, {
      method: project.http_method || "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Byakugan/0.2.0", Accept: "*/*" }
    });
    const elapsed = Math.round(performance.now() - started);
    const expected = project.expected_status;
    if (expected ? response.status !== expected : !response.ok) {
      return { status: "DOWN", httpStatus: response.status, responseTimeMs: elapsed,
        message: expected ? `Expected HTTP ${expected}, received ${response.status}` : `HTTP ${response.status}`, attempt };
    }
    if (project.keyword) {
      const body = await response.text();
      if (!body.includes(project.keyword)) {
        return { status: "DOWN", httpStatus: response.status, responseTimeMs: elapsed,
          message: `Response did not contain keyword: ${project.keyword}`, attempt };
      }
    }
    return { status: "UP", httpStatus: response.status, responseTimeMs: elapsed, message: "Healthy", attempt };
  } catch (error) {
    const elapsed = Math.round(performance.now() - started);
    const message = error instanceof Error ? (error.name === "AbortError" ? "Request timed out" : error.message) : "HTTP check failed";
    return { status: "DOWN", httpStatus: null, responseTimeMs: elapsed, message, attempt };
  } finally {
    clearTimeout(timeout);
  }
}

async function attemptTcpCheck(project: ProjectRow, attempt: number): Promise<CheckResult> {
  const started = performance.now();
  return new Promise((resolve) => {
    const socket = new Socket();
    const finish = (status: "UP" | "DOWN", message: string) => {
      const responseTimeMs = Math.round(performance.now() - started);
      socket.destroy();
      resolve({ status, httpStatus: null, responseTimeMs, message, attempt });
    };
    socket.setTimeout(project.timeout_seconds * 1000);
    socket.once("connect", () => finish("UP", "TCP port is reachable"));
    socket.once("timeout", () => finish("DOWN", "TCP connection timed out"));
    socket.once("error", (error) => finish("DOWN", error.message));
    socket.connect(project.tcp_port ?? 0, project.tcp_host ?? "");
  });
}

const activeChecks = new Set<number>();

export async function checkProject(projectId: number): Promise<CheckResult> {
  if (activeChecks.has(projectId)) throw new Error("A check is already running for this project");
  const project = db.prepare("SELECT * FROM projects WHERE id = ?").get(projectId) as ProjectRow | undefined;
  if (!project) throw new Error("Project not found");
  if (!project.enabled) throw new Error("Project is disabled");

  activeChecks.add(projectId);
  let result: CheckResult = { status: "DOWN", httpStatus: null, responseTimeMs: 0, message: "Not checked", attempt: 0 };
  try {
    for (let attempt = 1; attempt <= project.retry_count + 1; attempt += 1) {
      result = await attemptCheck(project, attempt);
      if (result.status !== "DOWN") break;
      if (attempt <= project.retry_count) await new Promise((resolve) => setTimeout(resolve, attempt * 500));
    }
    const now = new Date();
    const next = new Date(now.getTime() + project.interval_seconds * 1000);
    const previousStatus = project.last_status;
    const transaction = db.transaction(() => {
      db.prepare(`INSERT INTO heartbeats
        (project_id, status, http_status, response_time_ms, attempt, error_message, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(project.id, result.status, result.httpStatus, result.responseTimeMs, result.attempt,
          result.status === "UP" ? null : result.message, now.toISOString());
      db.prepare(`UPDATE projects SET last_status = ?, last_message = ?, last_checked_at = ?,
        next_check_at = ?, consecutive_failures = ?, updated_at = ? WHERE id = ?`)
        .run(result.status, result.message, now.toISOString(), next.toISOString(), result.status === "UP" ? 0 : project.consecutive_failures + 1, now.toISOString(), project.id);
      if(result.databaseMetrics){const metric=result.databaseMetrics;db.prepare(`INSERT INTO database_metrics(project_id,engine,connections_used,connections_max,database_size_bytes,replication_lag_seconds,long_running_queries,details_json,observed_at) VALUES(?,?,?,?,?,?,?,?,?)`).run(project.id,project.database_engine,metric.connectionsUsed,metric.connectionsMax,metric.databaseSizeBytes,metric.replicationLagSeconds,metric.longRunningQueries,JSON.stringify(metric.details),now.toISOString())}

      if (result.status !== "UP" && ["UP", "PENDING"].includes(previousStatus)) {
        db.prepare(`INSERT INTO incidents (project_id, status, message, started_at) VALUES (?, ?, ?, ?)`)
          .run(project.id, result.status, result.message, now.toISOString());
      } else if (result.status === "UP" && !["UP", "PENDING"].includes(previousStatus)) {
        db.prepare(`UPDATE incidents SET resolved_at = ? WHERE id = (
          SELECT id FROM incidents WHERE project_id = ? AND resolved_at IS NULL ORDER BY started_at DESC LIMIT 1)`)
          .run(now.toISOString(), project.id);
      }
    });
    transaction();
    if (result.status !== "UP" && ["UP", "PENDING"].includes(previousStatus)) {
      appendAuditEvent(null, "INCIDENT_OPENED", "project", project.id, { status: result.status, message: result.message, responseTimeMs: result.responseTimeMs });
    } else if (result.status === "UP" && !["UP", "PENDING"].includes(previousStatus)) {
      appendAuditEvent(null, "INCIDENT_RESOLVED", "project", project.id, { previousStatus, responseTimeMs: result.responseTimeMs });
    }
    if (result.status !== "UP" && (["UP", "PENDING"].includes(previousStatus) || previousStatus !== result.status)) {
      await dispatchNotifications(project, result.status === "PAUSED" ? "PAUSED" : "DOWN", result.message);
    } else if (result.status === "UP" && !["UP", "PENDING"].includes(previousStatus)) {
      await dispatchNotifications(project, "RECOVERY", "Monitor is healthy again / มอนิเตอร์กลับมาทำงานปกติแล้ว");
    }
    return result;
  } finally {
    activeChecks.delete(projectId);
  }
}
