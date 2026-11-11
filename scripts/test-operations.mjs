// Integration checks against a disposable local server; run after npm run build:server.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {once} from "node:events";
import {mkdtemp,rm} from "node:fs/promises";
import {createServer} from "node:http";
import {tmpdir} from "node:os";
import {join,resolve,sep} from "node:path";
import {randomBytes} from "node:crypto";

const dataDir=await mkdtemp(join(tmpdir(),"byakugan-operations-"));
process.env.SUPAPULSE_DATA_DIR=dataDir;
const {db}=await import("../dist-server/database.js");
const target=createServer((_req,res)=>res.end("healthy"));
target.listen(0,"127.0.0.1");await once(target,"listening");
const reservation=createServer();reservation.listen(0,"127.0.0.1");await once(reservation,"listening");
const port=reservation.address().port;await new Promise(r=>reservation.close(r));
const base=`http://127.0.0.1:${port}`;
const child=spawn(process.execPath,["dist-server/server.js"],{stdio:"ignore",env:{...process.env,NODE_ENV:"test",SUPAPULSE_HOST:"127.0.0.1",SUPAPULSE_PORT:String(port),SUPAPULSE_MASTER_KEY:randomBytes(32).toString("hex"),SUPAPULSE_SESSION_SECRET:randomBytes(32).toString("hex")}});
let cookie="";
async function request(path,method="GET",body,headers={}) {
  return fetch(base+path,{method,headers:{...(body===undefined?{}:{"Content-Type":"application/json"}),Cookie:cookie,...headers},body:body===undefined?undefined:JSON.stringify(body)});
}
async function ok(path,method="GET",body,headers={}) {
  const response=await request(path,method,body,headers);const value=await response.json();
  assert.ok(response.ok,`${path}: ${response.status} ${JSON.stringify(value)}`);return value;
}
try {
  let ready=false;
  for(let i=0;i<100;i++){try{ready=(await fetch(base+"/ready")).ok;if(ready)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  assert.ok(ready,"Server did not become ready");
  const setup=await request("/api/setup","POST",{username:"testadmin",password:"LocalOperationsTest123!"});
  assert.equal(setup.status,200);cookie=setup.headers.get("set-cookie").split(";")[0];
  assert.equal((await ok("/api/session")).user.locale,"th-TH","New accounts must use the configured system default");
  const agent=await ok("/api/agents","POST",{name:"test-windows"});
  const payload={hostname:"WIN-TEST",agentVersion:"test",observedAt:new Date().toISOString(),inventory:{osName:"Windows",architecture:"x64",cpuModel:"fixture",cpuCount:1,totalMemoryBytes:1024,securityUpdateCount:2},metrics:{cpuPercent:1,memoryPercent:1,uptimeSeconds:100,disks:[],containers:[]}};
  const ingest=()=>ok("/api/agent/ingest","POST",{...payload,observedAt:new Date().toISOString()},{Authorization:`Bearer ${agent.token}`});
  await ingest();
  const finding=db.prepare("SELECT id FROM compliance_findings WHERE agent_id=? AND finding_key='security_updates'").get(agent.id);
  await ok(`/api/findings/${finding.id}`,"PUT",{status:"ACKNOWLEDGED",owner:"Operations"});
  await ingest();
  assert.equal(db.prepare("SELECT status FROM compliance_findings WHERE id=?").get(finding.id).status,"ACKNOWLEDGED");
  const actionDetails=(await ok("/api/action-required")).find(item=>item.id===finding.id);
  assert.equal(actionDetails.findingKey,"security_updates");
  assert.ok(actionDetails.explanation&&actionDetails.firstDetectedAt&&actionDetails.lastDetectedAt);
  payload.inventory.securityUpdateCount=0;await ingest();
  assert.equal(db.prepare("SELECT status FROM compliance_findings WHERE id=?").get(finding.id).status,"RESOLVED");
  console.log("PASS Agent acknowledgement survives ingest and resolves on recovery");

  const project=await ok("/api/projects","POST",{name:"test-service",monitorType:"HTTP",target:`http://127.0.0.1:${target.address().port}`,intervalSeconds:60,timeoutSeconds:3,retryCount:0});
  db.prepare("UPDATE projects SET next_check_at=? WHERE id=?").run(new Date(Date.now()+3600000).toISOString(),project.id);
  for(const flags of [{enabled:false},{maintenance:true}])await ok("/api/projects","POST",{name:"skipped-service",monitorType:"HTTP",target:`http://127.0.0.1:${target.address().port}`,timeoutSeconds:3,retryCount:0,...flags});
  const incident=Number(db.prepare("INSERT INTO incidents(project_id,status,started_at) VALUES(?,'DOWN',?)").run(project.id,new Date().toISOString()).lastInsertRowid);
  const incidentEvidence=(await ok("/api/incidents")).find(row=>row.id===incident);
  assert.equal(incidentEvidence.monitorType,"HTTP");
  assert.equal(incidentEvidence.healthMetricKey,null);
  const healthIncident=Number(db.prepare("INSERT INTO incidents(status,message,started_at,health_policy_no,source_label) VALUES('CRITICAL','Memory threshold exceeded',?,2,'RAM test')").run(new Date().toISOString()).lastInsertRowid);
  const healthEvidence=(await ok("/api/incidents")).find(row=>row.id===healthIncident);
  assert.equal(healthEvidence.healthMetricKey,"ram_percent");
  assert.equal(healthEvidence.message,"Memory threshold exceeded");
  const review={severity:"MEDIUM",rootCause:"Test cause",correctiveAction:"Test correction",reviewStatus:"APPROVED"};
  assert.equal((await request(`/api/incidents/${incident}/review`,"PUT",{severity:"MEDIUM",reviewStatus:"APPROVED"})).status,400);
  assert.equal((await request(`/api/incidents/${incident}/review`,"PUT",{...review,reviewStatus:"PENDING",closeCase:true})).status,400);
  await ok(`/api/incidents/${incident}/review`,"PUT",review);
  assert.equal(db.prepare("SELECT closed_at FROM incidents WHERE id=?").get(incident).closed_at,null);
  await ok(`/api/incidents/${incident}/review`,"PUT",{...review,closeCase:true});
  const closed=db.prepare("SELECT closed_at,closed_by,resolved_at FROM incidents WHERE id=?").get(incident);
  assert.ok(closed.closed_at&&closed.closed_by);
  assert.equal(closed.resolved_at,null,"Closing a case must not claim service recovery");
  await ok(`/api/incidents/${incident}/review`,"PUT",{...review,closeCase:true});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_events WHERE action='INCIDENT_CLOSED' AND entity_id=?").get(String(incident)).n,1);
  console.log("PASS approval, validated case closure, audit and unchanged service status");

  const result=await ok("/api/health/run","POST");
  assert.equal(result.checkedMonitors,1);assert.ok(result.checkedAt&&result.health.items.length===10);
  assert.equal(db.prepare("SELECT status FROM heartbeats WHERE project_id=? ORDER BY id DESC LIMIT 1").get(project.id).status,"UP");
  const {createHash}=await import("node:crypto");
  for (const scope of ["all",`agent:${agent.id}`]) {
    const response=await request(`/api/audit/report.servers.xlsx?scope=${encodeURIComponent(scope)}`);
    assert.equal(response.status,200);
    const bytes=Buffer.from(await response.arrayBuffer());
    assert.equal(bytes.subarray(0,2).toString(),"PK");
    assert.equal(response.headers.get("x-content-sha256"),createHash("sha256").update(bytes).digest("hex"));
  }
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_events WHERE action='SERVER_EVIDENCE_EXPORTED'").get().n,2);
  console.log("PASS scoped Excel exports, response checksum and export audit trail");
  console.log("PASS Check now performs a real HTTP probe and evaluates health");
  const expiry=new Date(Date.now()+11.5*86400000).toISOString();
  const certProject=Number(db.prepare("INSERT INTO projects(name,supabase_url,encrypted_key,monitor_type,target,enabled,published,tls_expires_at,tls_checked_at,tls_valid) VALUES('certificate fixture','unused','unused','HTTP','https://example.test',0,1,?,?,1)").run(expiry,new Date().toISOString()).lastInsertRowid);
  const certStats=await ok(`/api/projects/${certProject}/stats`);
  assert.equal(certStats.certificate.expiresAt,expiry);
  assert.equal(certStats.certificate.daysRemaining,11);
  const published=(await ok("/api/public/status")).monitors.find(row=>row.id===certProject);
  assert.equal(published.certificate.expiresAt,expiry);
  assert.equal(published.target,undefined,"Public status must not expose private monitor targets");
  assert.equal(published.supabaseUrl,undefined);
  assert.equal(published.checks24h,0);
  assert.equal(published.uptime24h,null,"No samples must never display 100% uptime");
  await ok(`/api/projects/${certProject}`,"PATCH",{target:"http://example.test"});
  assert.equal((await ok(`/api/projects/${certProject}/stats`)).certificate.expiresAt,null,"Target changes must invalidate cached certificates");
  // Language preference persists in the same user record used by session, settings and report generation.
  for (const value of ["th-TH","en-US"]) {
    await ok("/api/settings/preferences","PUT",{locale:value,timezone:"Asia/Bangkok"});
    assert.equal((await ok("/api/session")).user.locale,value);
    assert.equal((await ok("/api/settings/regional")).userLocale,value);
  }
  console.log("PASS real expiry metadata on private/public views, cache invalidation and persistent language round trip");
  const old="2020-01-01T00:00:00.000Z";
  const oldBeat=Number(db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at) VALUES(?,'UP',1,1,?)").run(project.id,old).lastInsertRowid);
  const latestBeat=Number(db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at) VALUES(?,'UP',1,1,?)").run(project.id,new Date().toISOString()).lastInsertRowid);
  const unresolved=Number(db.prepare("INSERT INTO incidents(project_id,status,started_at) VALUES(?,'DOWN',?)").run(project.id,old).lastInsertRowid);
  db.prepare("UPDATE incidents SET resolved_at=?,closed_at=? WHERE id=?").run(old,old,incident);
  const plan=await ok("/api/settings/data/preview","POST",{categories:["monitors","incidents"],olderThanDays:90});
  assert.equal(plan.total,2);
  assert.ok(db.prepare("SELECT id FROM heartbeats WHERE id=?").get(oldBeat),"Preview must not delete");
  assert.equal((await request("/api/settings/data/cleanup","POST",{previewId:plan.id,confirmation:"wrong"})).status,400);
  const postPreview=Number(db.prepare("INSERT INTO heartbeats(project_id,status,response_time_ms,attempt,checked_at) VALUES(?,'UP',1,1,?)").run(project.id,old).lastInsertRowid);
  const cleaned=await ok("/api/settings/data/cleanup","POST",{previewId:plan.id,confirmation:"DELETE HISTORY"});
  assert.equal(cleaned.total,2);
  assert.equal(db.prepare("SELECT id FROM heartbeats WHERE id=?").get(oldBeat),undefined);
  assert.ok(db.prepare("SELECT id FROM heartbeats WHERE id=?").get(latestBeat));
  assert.ok(db.prepare("SELECT id FROM heartbeats WHERE id=?").get(postPreview),"New records are outside preview fence");
  assert.ok(db.prepare("SELECT id FROM incidents WHERE id=?").get(unresolved),"Active incident must survive");
  assert.equal(db.prepare("SELECT id FROM incidents WHERE id=?").get(incident),undefined);
  const {default:Database}=await import("better-sqlite3");
  const backupDb=new Database(cleaned.backup,{readonly:true,fileMustExist:true});
  assert.ok(backupDb.prepare("SELECT id FROM heartbeats WHERE id=?").get(oldBeat),"Backup contains deleted history");
  assert.equal(backupDb.pragma("integrity_check",{simple:true}),"ok");backupDb.close();
  const {verifyAuditChain}=await import("../dist-server/audit.js");
  assert.equal(verifyAuditChain().valid,true);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_events WHERE action='HISTORY_CLEANED'").get().n,1);
  assert.equal((await request("/api/settings/data/cleanup","POST",{previewId:plan.id,confirmation:"DELETE HISTORY"})).status,409,"Preview must be single use");
  const fullPreview=await ok("/api/settings/data/preview","POST",{categories:["logs","monitors","hosts","databases","health","notifications","incidents","findings"],olderThanDays:null});
  assert.equal(fullPreview.counts.length,10);
  // Reproduce the reported symptom: history cleanup retains current red state and open findings.
  const vulnerabilityId=Number(db.prepare("INSERT INTO vulnerability_findings(agent_id,vulnerability_id,package_name,severity,status,first_detected_at,last_detected_at) VALUES(?,'CVE-TEST','test-package','CRITICAL','OPEN',?,?)").run(agent.id,old,old).lastInsertRowid);
  const openFinding=Number(db.prepare("INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at) VALUES(?,'reset-test','HEALTH','CRITICAL','ACKNOWLEDGED','Test','Test',?,?)").run(agent.id,old,old).lastInsertRowid);
  db.prepare("INSERT OR REPLACE INTO health_state(policy_no,subject_key,label,level,value,since,evaluated_at) VALUES(1,'reset-test','Test','CRITICAL',100,?,?)").run(old,old);
  const {healthStatus}=await import("../dist-server/health.js");
  assert.ok(healthStatus().summary.critical>0);
  const {previewCleanup,executeCleanup,cleanupSchema}=await import("../dist-server/data-management.js");
  const adminId=db.prepare("SELECT id FROM users WHERE username='testadmin'").get().id;
  assert.equal(cleanupSchema.safeParse({mode:"history",categories:["vulnerabilities"],olderThanDays:null}).success,false);
  assert.equal(cleanupSchema.safeParse({mode:"reset",categories:["logs"],olderThanDays:null}).success,false);
  assert.equal(cleanupSchema.safeParse({mode:"reset",categories:["health"],olderThanDays:90}).success,false);
  const scanJob=Number(db.prepare("INSERT INTO vulnerability_scan_jobs(agent_id,target_type,target,status) VALUES(?,'FILESYSTEM','C:/test','RUNNING')").run(agent.id).lastInsertRowid);
  assert.equal((await request("/api/settings/data/preview","POST",{mode:"reset",categories:["vulnerabilities"],olderThanDays:null})).status,409);
  db.prepare("UPDATE vulnerability_scan_jobs SET status='FAILED',completed_at=? WHERE id=?").run(old,scanJob);
  const resetInput={mode:"reset",categories:["vulnerabilities","findings","health"],olderThanDays:null};
  const resetPlan=await ok("/api/settings/data/preview","POST",resetInput);
  assert.equal(resetPlan.confirmation,"RESET MONITORING");
  assert.equal(resetPlan.counts.filter(item=>item.table==='compliance_findings').length,1,"Overlapping scopes must not double-count");
  const localPlan=previewCleanup(adminId,cleanupSchema.parse(resetInput));
  await assert.rejects(()=>executeCleanup(adminId,localPlan.id,"DELETE HISTORY"),/Confirmation/);
  assert.ok(db.prepare("SELECT id FROM vulnerability_findings WHERE id=?").get(vulnerabilityId));
  const userCount=db.prepare("SELECT COUNT(*) n FROM users").get().n;
  const resetResult=await ok("/api/settings/data/cleanup","POST",{previewId:resetPlan.id,confirmation:"RESET MONITORING"});
  assert.equal(resetResult.mode,"reset");
  assert.equal(db.prepare("SELECT id FROM vulnerability_findings WHERE id=?").get(vulnerabilityId),undefined);
  assert.equal(db.prepare("SELECT id FROM compliance_findings WHERE id=?").get(openFinding),undefined);
  assert.equal(db.prepare("SELECT id FROM vulnerability_scan_jobs WHERE id=?").get(scanJob),undefined);
  assert.equal(healthStatus().summary.critical,0);
  assert.equal(healthStatus().summary.noData,10);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM users").get().n,userCount);
  assert.ok(db.prepare("SELECT id FROM agents WHERE id=?").get(agent.id));
  assert.ok(db.prepare("SELECT id FROM projects WHERE id=?").get(project.id));
  assert.equal(verifyAuditChain().valid,true);
  // A scan starting after preview must prevent the entire reset transaction.
  db.prepare("INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at) VALUES(?,'guard-test','HEALTH','CRITICAL','OPEN','Test','Test',?,?)").run(agent.id,old,old);
  const guarded=previewCleanup(adminId,cleanupSchema.parse(resetInput));
  db.prepare("INSERT INTO vulnerability_scan_jobs(agent_id,target_type,target,status) VALUES(?,'FILESYSTEM','C:/test','QUEUED')").run(agent.id);
  await assert.rejects(()=>executeCleanup(adminId,guarded.id,"RESET MONITORING"),/active vulnerability/);
  assert.ok(db.prepare("SELECT id FROM compliance_findings WHERE finding_key='guard-test'").get(),"Guard must leave all selected scopes unchanged");
  console.log("PASS reset clears open vulnerabilities, acknowledged actions and red health; preserves configuration and guards live scans");
  console.log("PASS preview, typed confirmation, backup, bounded cleanup, active record protection and intact audit chain");
  await ok("/api/users","POST",{username:"testviewer",password:"LocalViewerTest123!",role:"VIEWER"});
  const viewer=await request("/api/auth/login","POST",{username:"testviewer",password:"LocalViewerTest123!"});
  cookie=viewer.headers.get("set-cookie").split(";")[0];
  await ok("/api/settings/preferences","PUT",{locale:"en-US",timezone:"SYSTEM"});
  assert.equal((await ok("/api/session")).user.role,"VIEWER");
  assert.equal((await ok("/api/session")).user.locale,"en-US","Read-only users may change only their own preferences");
  assert.equal((await request("/api/health/run","POST")).status,403);
  assert.equal((await request("/api/audit/report.servers.xlsx?scope=all")).status,403);
  assert.equal((await request("/api/settings/data/preview","POST",{categories:["logs"],olderThanDays:null})).status,403);
  assert.equal((await request("/api/settings/data/cleanup","POST",{previewId:plan.id,confirmation:"DELETE HISTORY"})).status,403);
  assert.equal((await request(`/api/incidents/${incident}/review`,"PUT",review)).status,403);
  console.log("PASS Viewer cannot run checks or close cases");
} finally {
  if(child.exitCode===null){child.kill();await once(child,"exit");}
  target.closeAllConnections();await new Promise(r=>target.close(r));db.close();
  if(resolve(dataDir).startsWith(resolve(tmpdir())+sep+"byakugan-operations-"))await rm(dataDir,{recursive:true,force:true});
}
