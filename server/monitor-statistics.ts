import { db, type ProjectRow } from "./database.js";
import { certificateDays, certificateTarget } from "./certificates.js";
export function monitorStatistics(project:ProjectRow,now=Date.now()) {

  const cutoff24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
  const cutoff30d = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
  const aggregate = (cutoff: string) => db.prepare(`SELECT COUNT(*) AS total,
    SUM(CASE WHEN status = 'UP' THEN 1 ELSE 0 END) AS up,
    AVG(CASE WHEN status = 'UP' THEN response_time_ms END) AS averageResponseMs,
    MIN(response_time_ms) AS minResponseMs, MAX(response_time_ms) AS maxResponseMs
    FROM heartbeats WHERE project_id = ? AND julianday(checked_at) >= julianday(?) AND julianday(checked_at)<=julianday(?)`).get(project.id, cutoff,new Date(now).toISOString()) as {
      total: number; up: number | null; averageResponseMs: number | null; minResponseMs: number | null; maxResponseMs: number | null;
    };
  const day = aggregate(cutoff24h);
  const month = aggregate(cutoff30d);
  const percent = (value: { total: number; up: number | null }) => value.total ? Math.round(((value.up ?? 0) / value.total) * 10000) / 100 : null;
  return {
    currentResponseMs: project.last_checked_at ? (db.prepare("SELECT response_time_ms FROM heartbeats WHERE project_id = ? AND julianday(checked_at)<=julianday(?) ORDER BY julianday(checked_at) DESC,id DESC LIMIT 1").get(project.id,new Date(now).toISOString()) as { response_time_ms?: number } | undefined)?.response_time_ms ?? null : null,
    averageResponse24hMs: day.averageResponseMs === null ? null : Math.round(day.averageResponseMs * 100) / 100,
    uptime24h: percent(day), uptime30d: percent(month), checks24h: day.total, checks30d: month.total,
    minResponse24hMs: day.minResponseMs, maxResponse24hMs: day.maxResponseMs,
    certificate: { applicable: Boolean(certificateTarget(project)), expiresAt:project.tls_expires_at,checkedAt:project.tls_checked_at,daysRemaining:certificateDays(project.tls_expires_at,now),valid:project.tls_valid===null?null:Boolean(project.tls_valid),error:project.tls_error }
  };
}
export function publicMonitorStatistics(project:ProjectRow){
  const stats=monitorStatistics(project);
  return {...stats,certificate:{...stats.certificate,error:stats.certificate.error?"TLS certificate validation or inspection failed":null}};
}
