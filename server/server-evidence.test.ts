import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
process.env.SUPAPULSE_DATA_DIR = mkdtempSync(join(tmpdir(), "byakugan-evidence-"));
const { db } = await import("./database.js");
await import("./log-events.js");
const { collectServerEvidence, evidenceScope, createServerEvidence } = await import("./server-evidence.js");
const { createXlsxWorkbook } = await import("./reports.js");
const from = "2026-01-01T00:00:00.000Z", to = "2026-12-31T23:59:59.999Z", at = "2026-06-01T00:00:00.000Z";
const a = Number(db.prepare("INSERT INTO agents(name,hostname,token_hash) VALUES('one','HOST-ONE','secret-one')").run().lastInsertRowid);
const b = Number(db.prepare("INSERT INTO agents(name,hostname,token_hash) VALUES('two','HOST-TWO','secret-two')").run().lastInsertRowid);
const p = Number(db.prepare("INSERT INTO projects(name,supabase_url,encrypted_key) VALUES('service-one','https://example.test','secret-key')").run().lastInsertRowid);
for (const id of [a,b]) {
  db.prepare("INSERT INTO host_metrics(agent_id,cpu_percent,memory_percent,uptime_seconds,observed_at) VALUES(?,12.5,30,100,?)").run(id,at);
  db.prepare("INSERT INTO compliance_findings(agent_id,finding_key,category,severity,title,explanation,first_detected_at,last_detected_at) VALUES(?,'test','HEALTH','HIGH','Test','Evidence',?,?)").run(id,at,at);
  db.prepare("INSERT INTO health_state(policy_no,subject_key,label,level,since,evaluated_at) VALUES(1,?,?,'CRITICAL',?,?)").run(`agent:${id}`,`HOST-${id}`,at,at);
}
db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at) VALUES(?,'UP',12,1,?)").run(p,at);
db.prepare("INSERT INTO backup_evidence(asset_name,backup_type,storage_location,status,started_at) VALUES('HOST-ONE','DATABASE','private','SUCCESS',?)").run(at);
const data = (scope = "all") => collectServerEvidence(from,to,evidenceScope(scope),"en-US","Asia/Bangkok");
const rows = (report: ReturnType<typeof data>, name: string) => report.sheets.find(s=>s.name===name)!.rows;

describe("scoped server evidence", () => {
  it("includes all topics, no credential columns, and honest gaps", () => {
    const report = data();
    expect(report.sheets.length).toBe(28);
    expect(rows(report,"Servers")).toHaveLength(2);
    expect(rows(report,"Backups")).toHaveLength(1);
    expect(JSON.stringify(report)).not.toContain("secret-one");
    expect(JSON.stringify(report)).not.toContain("secret-key");
    expect(rows(report,"Coverage and Gaps").some(row=>row.evidenceStatus==='EXTERNAL_EVIDENCE_REQUIRED')).toBe(true);
  });
  it("filters every host dataset and health subject by stable agent ID", () => {
    const report=data(`agent:${a}`);
    expect(rows(report,"Host Metrics").map(row=>row.agentId)).toEqual([a]);
    expect(rows(report,"Action Items").map(row=>row.agentId)).toEqual([a]);
    expect(rows(report,"Health State").map(row=>row.subjectKey)).toEqual([`agent:${a}`]);
    expect(rows(report,"Monitors")).toHaveLength(0);
    expect(rows(report,"Backups")).toHaveLength(0);
    expect(rows(report,"Coverage and Gaps").find(row=>row.topic==='Backups')?.evidenceStatus).toBe('NOT_LINKED_TO_SCOPE');
    expect(JSON.stringify(report)).not.toContain('HOST-TWO');
  });
  it("exports monitor checks without guessing a host link", () => {
    const report=data(`project:${p}`);
    expect(rows(report,"Monitor Checks").map(row=>row.monitorId)).toEqual([p]);
    expect(rows(report,"Servers")).toHaveLength(0);
    expect(rows(report,"Host Metrics")).toHaveLength(0);
  });
  it("rejects nonexistent IDs and SQL-like scope strings", () => {
    expect(()=>evidenceScope("agent:999999")).toThrow(/not found/);
    expect(()=>evidenceScope("agent:1 OR 1=1")).toThrow(/Invalid/);
  });
  it("respects period boundaries and exports a real Thai workbook", async () => {
    const report=collectServerEvidence("2025-01-01T00:00:00Z","2025-12-31T23:59:59Z",evidenceScope("all"),"en-US","UTC");
    expect(rows(report,"Host Metrics")).toHaveLength(0);
    const result=await createServerEvidence(from,to,evidenceScope(`agent:${a}`),"th-TH","Asia/Bangkok");
    expect(result.buffer.subarray(0,2).toString()).toBe("PK");
    expect(result.counts.some(row=>row.sheet==='ความครอบคลุมและสิ่งที่ขาด')).toBe(true);
  });
  it("fails oversized cells instead of silently discarding evidence", async () => {
    await expect(createXlsxWorkbook([{name:"test",rows:[{evidence:"x".repeat(32768)}]}])).rejects.toThrow(/cell limit/);
  });
  it("fails row overflow rather than truncating evidence", () => {
    db.prepare(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<25001) INSERT INTO host_metrics(agent_id,cpu_percent,memory_percent,uptime_seconds,observed_at) SELECT ?,1,1,1,? FROM n`).run(b,at);
    expect(()=>data(`agent:${b}`)).toThrow(/too large/);
    expect(()=>data(`agent:${a}`)).not.toThrow();
  });
});
