import { db, type ProjectRow } from "./database.js";
import { checkProject } from "./monitor.js";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { config } from "./config.js";
import { appendAuditEvent } from "./audit.js";
import { collectAuditReport, createPdfReport, createXlsxReport, reportSha256 } from "./reports.js";
import { systemRegional, systemText } from "./localization.js";
import {decrypt} from "./crypto.js";
import {deliverReport,deliveryErrorCode,type DeliveryConfig} from "./report-delivery.js";
import { scheduleThreatIntelligence } from "./threat-intelligence.js";

let timer: NodeJS.Timeout | undefined;
let reportsRunning=false;
function backupFreshness(){const now=new Date(),connectors=db.prepare(`SELECT c.id,c.name,c.max_age_hours AS maxAgeHours,c.created_at AS createdAt,(SELECT MAX(b.completed_at) FROM backup_evidence b WHERE b.connector_id=c.id AND b.status='SUCCESS') AS lastSuccess FROM backup_connectors c WHERE c.enabled=1`).all() as Array<{id:number;name:string;maxAgeHours:number;createdAt:string;lastSuccess:string|null}>;for(const connector of connectors){const reference=new Date(connector.lastSuccess??connector.createdAt),stale=now.getTime()-reference.getTime()>connector.maxAgeHours*3600000,stamp=now.toISOString(),title=systemText("Backup evidence is stale","หลักฐานการสำรองข้อมูลเก่าเกินกำหนด"),explanation=systemText(`${connector.name} has no successful backup within ${connector.maxAgeHours} hours`,`${connector.name} ไม่มีหลักฐานการสำรองข้อมูลสำเร็จภายใน ${connector.maxAgeHours} ชั่วโมง`);if(stale)db.prepare(`INSERT INTO backup_policy_findings(connector_id,severity,status,title,explanation,first_detected_at,last_detected_at) VALUES(?,'HIGH','OPEN',?,?,?,?) ON CONFLICT(connector_id) DO UPDATE SET status='OPEN',title=excluded.title,explanation=excluded.explanation,last_detected_at=excluded.last_detected_at,resolved_at=NULL`).run(connector.id,title,explanation,stamp,stamp);else db.prepare("UPDATE backup_policy_findings SET status='RESOLVED',resolved_at=?,last_detected_at=? WHERE connector_id=? AND status='OPEN'").run(stamp,stamp,connector.id)}}

function scheduledSecurityScans(){const now=new Date(),stamp=now.toISOString();db.prepare(`UPDATE vulnerability_scan_jobs SET heartbeat_at=(SELECT last_seen_at FROM agents WHERE agents.id=vulnerability_scan_jobs.agent_id) WHERE status='RUNNING' AND EXISTS(SELECT 1 FROM agents WHERE agents.id=vulnerability_scan_jobs.agent_id AND agents.last_seen_at IS NOT NULL AND agents.last_seen_at>vulnerability_scan_jobs.heartbeat_at)`).run();db.prepare(`UPDATE vulnerability_scan_jobs SET status='FAILED',completed_at=?,error_code='AGENT_TIMEOUT',error_message='Agent stopped reporting scan progress' WHERE status='RUNNING' AND heartbeat_at IS NOT NULL AND ((julianday(?) - julianday(heartbeat_at))*86400 > timeout_seconds+120 OR (started_at IS NOT NULL AND (julianday(?) - julianday(started_at))*86400 > timeout_seconds*3+120))`).run(stamp,stamp,stamp);const schedules=db.prepare(`SELECT s.id,s.agent_id AS agentId,s.profile_id AS profileId,s.target,s.frequency,p.target_type AS targetType,p.scanners,p.severity,p.timeout_seconds AS timeoutSeconds FROM vulnerability_scan_schedules s JOIN vulnerability_scan_profiles p ON p.id=s.profile_id JOIN agents a ON a.id=s.agent_id WHERE s.enabled=1 AND p.enabled=1 AND a.enabled=1 AND s.next_run_at<=? ORDER BY s.next_run_at LIMIT 50`).all(stamp) as Array<{id:number;agentId:number;profileId:number;target:string;frequency:"DAILY"|"WEEKLY";targetType:string;scanners:string;severity:string;timeoutSeconds:number}>;for(const schedule of schedules){db.transaction(()=>{const active=db.prepare("SELECT id FROM vulnerability_scan_jobs WHERE agent_id=? AND target_type=? AND target=? AND status IN ('QUEUED','RUNNING')").get(schedule.agentId,schedule.targetType,schedule.target) as {id:number}|undefined,next=new Date(now.getTime()+(schedule.frequency==="DAILY"?1:7)*86400000).toISOString();if(active){db.prepare("UPDATE vulnerability_scan_schedules SET next_run_at=?,updated_at=? WHERE id=?").run(next,stamp,schedule.id);appendAuditEvent(null,"VULNERABILITY_SCAN_SCHEDULE_SKIPPED","scan_schedule",schedule.id,{activeJobId:active.id,nextRunAt:next});return}const result=db.prepare("INSERT INTO vulnerability_scan_jobs(agent_id,profile_id,schedule_id,target_type,target,scanners,severity,timeout_seconds) VALUES(?,?,?,?,?,?,?,?)").run(schedule.agentId,schedule.profileId,schedule.id,schedule.targetType,schedule.target,schedule.scanners,schedule.severity,schedule.timeoutSeconds),jobId=Number(result.lastInsertRowid);db.prepare("UPDATE vulnerability_scan_schedules SET last_run_at=?,last_job_id=?,next_run_at=?,updated_at=? WHERE id=?").run(stamp,jobId,next,stamp,schedule.id);appendAuditEvent(null,"VULNERABILITY_SCAN_SCHEDULE_QUEUED","scan_schedule",schedule.id,{jobId,agentId:schedule.agentId,profileId:schedule.profileId,target:schedule.target,nextRunAt:next})})()}}

async function scheduledReports(){
  if(reportsRunning)return;reportsRunning=true;
  try{
    const now=new Date(),regional=systemRegional();
    const schedules=db.prepare("SELECT * FROM report_schedules WHERE enabled=1 AND next_run_at<=?").all(now.toISOString()) as Array<{id:number;name:string;frequency:string;formats:string;period_days:number}>;
    if(!schedules.length)return;
    const reportsDir=join(config.dataDir,"reports");await mkdir(reportsDir,{recursive:true});
    for(const schedule of schedules){
      const to=now.toISOString(),from=new Date(now.getTime()-schedule.period_days*86400000).toISOString(),data=collectAuditReport(from,to);
      const channels=db.prepare(`SELECT c.id,c.type,c.encrypted_config AS encryptedConfig FROM report_delivery_channels c JOIN report_schedule_channels sc ON sc.channel_id=c.id WHERE sc.schedule_id=? AND c.enabled=1`).all(schedule.id) as Array<{id:number;type:"SMTP"|"S3";encryptedConfig:string}>;
      for(const format of schedule.formats.split(",")){
        try{
          const buffer=format==="PDF"?await createPdfReport(data,regional.locale,regional.timezone):await createXlsxReport(data,regional.locale,regional.timezone),sha256=reportSha256(buffer);
          const fileName=`byakugan-${schedule.id}-${regional.locale}-${now.toISOString().replace(/[:.]/g,"-")}.${format.toLowerCase()}`,filePath=join(reportsDir,fileName);await writeFile(filePath,buffer);
          const inserted=db.prepare(`INSERT INTO generated_reports(schedule_id,format,date_from,date_to,file_name,file_path,size_bytes,sha256,status) VALUES(?,?,?,?,?,?,?,?, 'READY')`).run(schedule.id,format,from,to,fileName,filePath,buffer.length,sha256),reportId=Number(inserted.lastInsertRowid);
          appendAuditEvent(null,"SCHEDULED_REPORT_CREATED","generated_report",reportId,{scheduleId:schedule.id,format,from,to,fileName,...regional,sha256});
          for(const channel of channels){let delivered=false,lastCode="DELIVERY_FAILED";for(let attempt=1;attempt<=3&&!delivered;attempt++){try{const value={type:channel.type,config:JSON.parse(decrypt(channel.encryptedConfig))} as DeliveryConfig,result=await deliverReport(value,{buffer,fileName,format,sha256,scheduleName:schedule.name,period:{from,to}}),worm="wormMode" in result?result:{wormMode:null,retainUntil:null,legalHold:false,objectVersionId:null,immutableVerified:false};db.prepare(`INSERT INTO report_deliveries(generated_report_id,schedule_id,channel_id,status,attempts,destination,object_key,worm_mode,retain_until,legal_hold,object_version_id,immutable_verified,delivered_at) VALUES(?,?,?,'DELIVERED',?,?,?,?,?,?,?,?,?)`).run(reportId,schedule.id,channel.id,attempt,result.destination,result.objectKey,worm.wormMode,worm.retainUntil,Number(worm.legalHold),worm.objectVersionId,Number(worm.immutableVerified),new Date().toISOString());appendAuditEvent(null,"REPORT_DELIVERED","generated_report",reportId,{scheduleId:schedule.id,channelId:channel.id,type:channel.type,format,sha256,destination:result.destination,objectKey:result.objectKey,wormMode:worm.wormMode,retainUntil:worm.retainUntil,legalHold:worm.legalHold,objectVersionId:worm.objectVersionId,immutableVerified:worm.immutableVerified});delivered=true}catch(error){lastCode=deliveryErrorCode(error);if(attempt<3)await new Promise(resolve=>setTimeout(resolve,attempt*500));else{db.prepare(`INSERT INTO report_deliveries(generated_report_id,schedule_id,channel_id,status,attempts,error_code) VALUES(?,?,?,'FAILED',3,?)`).run(reportId,schedule.id,channel.id,lastCode);appendAuditEvent(null,"REPORT_DELIVERY_FAILED","generated_report",reportId,{scheduleId:schedule.id,channelId:channel.id,type:channel.type,errorCode:lastCode})}}}}
        }catch(error){db.prepare(`INSERT INTO generated_reports(schedule_id,format,date_from,date_to,file_name,file_path,size_bytes,sha256,status,error_message) VALUES(?,?,?,?,?,?,0,'','FAILED',?)`).run(schedule.id,format,from,to,"","",error instanceof Error?error.message:"Report failed")}
      }
      const days=schedule.frequency==="WEEKLY"?7:30;db.prepare("UPDATE report_schedules SET last_run_at=?,next_run_at=?,updated_at=? WHERE id=?").run(to,new Date(now.getTime()+days*86400000).toISOString(),to,schedule.id);
    }
  }finally{reportsRunning=false}
}

async function tick() {
  const due = db.prepare(`SELECT * FROM projects
    WHERE enabled = 1 AND maintenance = 0 AND (next_check_at IS NULL OR next_check_at <= ?)`)
    .all(new Date().toISOString()) as ProjectRow[];
  for (const project of due) {
    checkProject(project.id).catch((error) => {
      console.error(`Monitor failed for project ${project.id}:`, error instanceof Error ? error.message : error);
    });
  }
  await scheduledReports();
  scheduledSecurityScans();
  backupFreshness();
  scheduleThreatIntelligence();
}

export function startScheduler() {
  if (timer) return;
  void tick();
  timer = setInterval(() => void tick(), 30_000);
  timer.unref();
}

export function stopScheduler() {
  if (timer) clearInterval(timer);
  timer = undefined;
}
