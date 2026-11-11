import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { db } from "./database.js";
import { config } from "./config.js";
import { appendAuditEvent } from "./audit.js";

// Configuration and audit evidence are never cleanup targets.
const targets = {
  logs: [{ table: "log_events", time: "occurred_at", eligible: "1=1" }],
  monitors: [{ table: "heartbeats", time: "checked_at", eligible: "id NOT IN (SELECT MAX(id) FROM heartbeats GROUP BY project_id)" }],
  hosts: [
    { table: "host_metrics", time: "observed_at", eligible: "id NOT IN (SELECT MAX(id) FROM host_metrics GROUP BY agent_id)" },
    { table: "asset_snapshots", time: "observed_at", eligible: "id NOT IN (SELECT MAX(id) FROM asset_snapshots GROUP BY agent_id)" }
  ],
  databases: [{ table: "database_metrics", time: "observed_at", eligible: "id NOT IN (SELECT MAX(id) FROM database_metrics GROUP BY project_id)" }],
  health: [
    { table: "health_history", time: "at", eligible: "1=1" },
    { table: "ws_gaps", time: "ended_at", eligible: "ended_at IS NOT NULL" }
  ],
  notifications: [{ table: "notification_deliveries", time: "created_at", eligible: "1=1" }],
  incidents: [{ table: "incidents", time: "closed_at", eligible: "closed_at IS NOT NULL AND resolved_at IS NOT NULL" }],
  findings: [{ table: "compliance_findings", time: "resolved_at", eligible: "status='RESOLVED'" }]
} as const;
const resetTargets = {
  vulnerabilities: [
    { table: "vulnerability_findings", time: "last_detected_at", eligible: "1=1" },
    { table: "vulnerability_scans", time: "received_at", eligible: "1=1" },
    { table: "vulnerability_scan_jobs", time: "COALESCE(completed_at,requested_at)", eligible: "status IN ('COMPLETED','FAILED','CANCELLED')" }
  ],
  findings: [
    { table: "compliance_findings", time: "last_detected_at", eligible: "1=1" },
    { table: "backup_policy_findings", time: "last_detected_at", eligible: "1=1" }
  ],
  health: [
    { table: "health_state", time: "evaluated_at", eligible: "1=1" },
    { table: "health_history", time: "at", eligible: "1=1" },
    { table: "compliance_findings", time: "last_detected_at", eligible: "category='HEALTH'" }
  ]
} as const;
export const cleanupSchema = z.object({
  mode: z.enum(["history", "reset"]).default("history"),
  categories: z.array(z.enum(["logs", "monitors", "hosts", "databases", "health", "notifications", "incidents", "findings", "vulnerabilities"])).min(1).max(8),
  olderThanDays: z.number().int().min(1).max(3650).nullable()
}).refine(input => input.categories.every(key => key in (input.mode === "reset" ? resetTargets : targets)) && (input.mode !== "reset" || input.olderThanDays === null), { message: "Invalid cleanup scope" });
type Item = { table: string; time: string; eligible: string; maxId: number; count: number; category: string };
type Plan = { id: string; userId: number; expiresAt: number; cutoff: string; items: Item[]; mode: "history" | "reset"; categories: string[] };
const plans = new Map<string, Plan>();
let busy = false;
function where(item: Item) { return `rowid<=? AND julianday(${item.time})<julianday(?) AND (${item.eligible})`; }
function checkActiveScans(mode: string, categories: string[]) {
  if (mode === "reset" && categories.includes("vulnerabilities") && db.prepare("SELECT 1 FROM vulnerability_scan_jobs WHERE status IN ('QUEUED','RUNNING') LIMIT 1").get()) {
    throw new Error("Cancel or finish active vulnerability scans before resetting");
  }
}
export function previewCleanup(userId: number, input: z.infer<typeof cleanupSchema>) {
  checkActiveScans(input.mode, input.categories);
  for (const [id, plan] of plans) if (plan.expiresAt < Date.now() || plan.userId === userId) plans.delete(id);
  if (plans.size >= 100) throw new Error("Too many cleanup previews; try again later");
  const cutoff = new Date(Date.now() - (input.olderThanDays ?? 0) * 86400000).toISOString();
  const catalog: Record<string, readonly { table: string; time: string; eligible: string }[]> = input.mode === "reset" ? resetTargets : targets;
  const items = [...new Set(input.categories)].flatMap(category => catalog[category].filter(target => !(input.mode === "reset" && category === "health" && target.table === "compliance_findings" && input.categories.includes("findings"))).map(target => {
    const item: Item = { ...target, category, maxId: (db.prepare(`SELECT COALESCE(MAX(rowid),0) n FROM ${target.table}`).get() as { n: number }).n, count: 0 };
    item.count = (db.prepare(`SELECT COUNT(*) n FROM ${item.table} WHERE ${where(item)}`).get(item.maxId, cutoff) as { n: number }).n;
    return item;
  }));
  const plan: Plan = { id: randomUUID(), userId, cutoff, items, mode: input.mode, categories: input.categories, expiresAt: Date.now() + 10 * 60000 };
  plans.set(plan.id, plan);
  return { id: plan.id, mode: plan.mode, confirmation: plan.mode === "reset" ? "RESET MONITORING" : "DELETE HISTORY", cutoff, expiresAt: new Date(plan.expiresAt).toISOString(), counts: items.map(({ category, table, count }) => ({ category, table, count })), total: items.reduce((sum, item) => sum + item.count, 0) };
}
export async function executeCleanup(userId: number, id: string, confirmation: string) {
  const plan = plans.get(id);
  if (!plan || plan.userId !== userId || plan.expiresAt < Date.now()) throw new Error("Cleanup preview expired; preview again");
  if (confirmation !== (plan.mode === "reset" ? "RESET MONITORING" : "DELETE HISTORY")) throw new Error("Confirmation does not match cleanup mode");
  if (busy) throw new Error("Another cleanup is running");
  busy = true;
  plans.delete(id);
  try {
    checkActiveScans(plan.mode, plan.categories);
    if (!plan.items.some(item => item.count)) throw new Error("No eligible history to delete");
    const directory = join(config.dataDir, "maintenance-backups");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const backup = join(directory, `before-cleanup-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}.db`);
    await db.backup(backup);
    const deleted = db.transaction(() => {
      checkActiveScans(plan.mode, plan.categories);
      for (const item of plan.items) {
        const count = (db.prepare(`SELECT COUNT(*) n FROM ${item.table} WHERE ${where(item)}`).get(item.maxId, plan.cutoff) as { n: number }).n;
        if (count !== item.count) throw new Error("History changed; preview again");
      }
      const counts = plan.items.map(item => ({ category: item.category, table: item.table, count: db.prepare(`DELETE FROM ${item.table} WHERE ${where(item)}`).run(item.maxId, plan.cutoff).changes }));
      appendAuditEvent(userId, plan.mode === "reset" ? "MONITORING_DATA_RESET" : "HISTORY_CLEANED", "settings", "data-management", { cutoff: plan.cutoff, categories: plan.categories, counts, backup });
      return counts;
    })();
    return { mode: plan.mode, deleted, backup, total: deleted.reduce((sum, row) => sum + row.count, 0) };
  } finally { busy = false; }
}
