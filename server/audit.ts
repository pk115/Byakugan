import { createHash } from "node:crypto";
import { db } from "./database.js";

export function appendAuditEvent(actorUserId: number | null, action: string, entityType: string, entityId: string | number | null, details: Record<string, unknown> = {}) {
  const previous = db.prepare("SELECT event_hash AS eventHash FROM audit_events ORDER BY id DESC LIMIT 1").get() as { eventHash?: string } | undefined;
  const createdAt = new Date().toISOString();
  const detailsJson = JSON.stringify(details);
  const material = JSON.stringify({ actorUserId, action, entityType, entityId: entityId === null ? null : String(entityId), detailsJson, previousHash: previous?.eventHash ?? null, createdAt });
  const eventHash = createHash("sha256").update(material).digest("hex");
  db.prepare(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, details_json, previous_hash, event_hash, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(actorUserId, action, entityType, entityId === null ? null : String(entityId), detailsJson, previous?.eventHash ?? null, eventHash, createdAt);
  return eventHash;
}

export function verifyAuditChain() {
  const rows = db.prepare("SELECT * FROM audit_events ORDER BY id").all() as Array<Record<string, unknown>>;
  let previousHash: string | null = null;
  for (const row of rows) {
    if ((row.previous_hash ?? null) !== previousHash) return { valid: false, events: rows.length, failedAt: row.id };
    const material = JSON.stringify({ actorUserId: row.actor_user_id, action: row.action, entityType: row.entity_type,
      entityId: row.entity_id, detailsJson: row.details_json, previousHash: row.previous_hash, createdAt: row.created_at });
    const expected = createHash("sha256").update(material).digest("hex");
    if (expected !== row.event_hash) return { valid: false, events: rows.length, failedAt: row.id };
    previousHash = String(row.event_hash);
  }
  return { valid: true, events: rows.length, headHash: previousHash };
}
