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
  const agent=await ok("/api/agents","POST",{name:"test-windows"});
  const payload={hostname:"WIN-TEST",agentVersion:"test",observedAt:new Date().toISOString(),inventory:{osName:"Windows",architecture:"x64",cpuModel:"fixture",cpuCount:1,totalMemoryBytes:1024,securityUpdateCount:2},metrics:{cpuPercent:1,memoryPercent:1,uptimeSeconds:100,disks:[],containers:[]}};
  const ingest=()=>ok("/api/agent/ingest","POST",{...payload,observedAt:new Date().toISOString()},{Authorization:`Bearer ${agent.token}`});
  await ingest();
  const finding=db.prepare("SELECT id FROM compliance_findings WHERE agent_id=? AND finding_key='security_updates'").get(agent.id);
  await ok(`/api/findings/${finding.id}`,"PUT",{status:"ACKNOWLEDGED",owner:"Operations"});
  await ingest();
  assert.equal(db.prepare("SELECT status FROM compliance_findings WHERE id=?").get(finding.id).status,"ACKNOWLEDGED");
  payload.inventory.securityUpdateCount=0;await ingest();
  assert.equal(db.prepare("SELECT status FROM compliance_findings WHERE id=?").get(finding.id).status,"RESOLVED");
  console.log("PASS Agent acknowledgement survives ingest and resolves on recovery");

  const project=await ok("/api/projects","POST",{name:"test-service",monitorType:"HTTP",target:`http://127.0.0.1:${target.address().port}`,intervalSeconds:60,timeoutSeconds:3,retryCount:0});
  db.prepare("UPDATE projects SET next_check_at=? WHERE id=?").run(new Date(Date.now()+3600000).toISOString(),project.id);
  for(const flags of [{enabled:false},{maintenance:true}])await ok("/api/projects","POST",{name:"skipped-service",monitorType:"HTTP",target:`http://127.0.0.1:${target.address().port}`,timeoutSeconds:3,retryCount:0,...flags});
  const incident=Number(db.prepare("INSERT INTO incidents(project_id,status,started_at) VALUES(?,'DOWN',?)").run(project.id,new Date().toISOString()).lastInsertRowid);
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
  console.log("PASS Check now performs a real HTTP probe and evaluates health");
  await ok("/api/users","POST",{username:"testviewer",password:"LocalViewerTest123!",role:"VIEWER"});
  const viewer=await request("/api/auth/login","POST",{username:"testviewer",password:"LocalViewerTest123!"});
  cookie=viewer.headers.get("set-cookie").split(";")[0];
  assert.equal((await request("/api/health/run","POST")).status,403);
  assert.equal((await request(`/api/incidents/${incident}/review`,"PUT",review)).status,403);
  console.log("PASS Viewer cannot run checks or close cases");
} finally {
  if(child.exitCode===null){child.kill();await once(child,"exit");}
  target.closeAllConnections();await new Promise(r=>target.close(r));db.close();
  if(resolve(dataDir).startsWith(resolve(tmpdir())+sep+"byakugan-operations-"))await rm(dataDir,{recursive:true,force:true});
}
