import {threatPolicy,excepted} from "./threat-policy.js";
import "./log-events.js";
import {createHash} from "node:crypto";
import {db} from "./database.js";
import {appendAuditEvent} from "./audit.js";

db.exec(`CREATE TABLE IF NOT EXISTS threat_cases (
  finding_id INTEGER PRIMARY KEY REFERENCES compliance_findings(id) ON DELETE CASCADE,
  agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  rule TEXT NOT NULL,src_ip TEXT NOT NULL,actor TEXT NOT NULL,
  first_log_id INTEGER NOT NULL,last_log_id INTEGER NOT NULL,handled_through INTEGER NOT NULL DEFAULT 0,
  evidence_count INTEGER NOT NULL,last_notified_at TEXT
); CREATE INDEX IF NOT EXISTS idx_threat_case_agent ON threat_cases(agent_id,src_ip);
CREATE TABLE IF NOT EXISTS threat_notification_queue(finding_id INTEGER PRIMARY KEY REFERENCES compliance_findings(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_log_agent_ip_time ON log_events(agent_id,src_ip,occurred_at);`);

export function evaluateThreatRules(agentId:number,now=new Date()) {
  const policy=threatPolicy(),since=new Date(now.getTime()-policy.windowMinutes*60000).toISOString(),stamp=now.toISOString();
  const definitions=[
    {rule:"IDS_SIGNATURE",prefix:"threat_ids_",threshold:1,actor:"CAST(COALESCE(json_extract(details_json,'$.signature_id'),'unknown') AS TEXT)",count:"COUNT(*)",where:"event='IDS_ALERT'"},
    {rule:"AUTH_FAILURES",prefix:"threat_auth_",threshold:policy.authThreshold,actor:"COALESCE(actor,'')",count:"COUNT(*)",where:"event IN ('LOGIN_FAILED','SSH_LOGIN_FAILED','SUDO_AUTH_FAILED','ROOT_LOGIN_DENIED','VPN_AUTH_FAILED','DB_AUTH_FAILED')"},
    {rule:"PORT_SCAN",prefix:"threat_ports_",threshold:policy.portThreshold,actor:"''",count:"COUNT(DISTINCT json_extract(details_json,'$.dst_port'))",where:"event='FIREWALL_DENY' AND src_ip IS NOT NULL AND src_ip!='' AND json_extract(details_json,'$.dst_port') IS NOT NULL AND json_extract(details_json,'$.dst_port')!=''"},
    {rule:"WEB_PROBES",prefix:"threat_web_",threshold:policy.webThreshold,actor:"''",count:"COUNT(*)",where:"event='HTTP_PROBE'"}
  ];
  return db.transaction(()=>{
    const opened:number[]=[];
    for(const rule of definitions){
      const groups=db.prepare(`SELECT COALESCE(src_ip,'') AS ip,${rule.actor} AS account,${rule.count} AS n,MIN(id) AS firstId,MAX(id) AS lastId FROM log_events WHERE agent_id=? AND occurred_at BETWEEN ? AND ? AND ${rule.where} GROUP BY COALESCE(src_ip,''),${rule.actor} HAVING ${rule.count}>=?`).all(agentId,since,stamp,rule.threshold) as Array<{ip:string;account:string;n:number;firstId:number;lastId:number}>;
      for(const g of groups){
        if(excepted(policy,agentId,g.ip,now))continue;
        const key=rule.prefix+createHash("sha256").update(JSON.stringify([g.ip,g.account])).digest("hex").slice(0,32);
        const old=db.prepare(`SELECT f.id,f.status,c.handled_through AS handled FROM compliance_findings f JOIN threat_cases c ON c.finding_id=f.id WHERE f.agent_id=? AND f.finding_key=?`).get(agentId,key) as {id:number;status:string;handled:number}|undefined;
        if(old?.status==='RESOLVED'){
          const fresh=db.prepare(`SELECT ${rule.count} AS n,MIN(id) AS firstId FROM log_events WHERE agent_id=? AND id>? AND occurred_at BETWEEN ? AND ? AND COALESCE(src_ip,'')=? AND ${rule.actor}=? AND ${rule.where}`).get(agentId,old.handled,since,stamp,g.ip,g.account) as {n:number;firstId:number};
          if(fresh.n<rule.threshold)continue;g.firstId=fresh.firstId;g.n=fresh.n;
        }
        const explanation=`${rule.rule}: ${g.n} ${rule.rule==='PORT_SCAN'?'distinct denied ports':'events'} / ${policy.windowMinutes} min (threshold ${rule.threshold}); source ${g.ip||'unknown'}, account ${g.account||'unknown'}. Review evidence; compromise is not established.`;
        const id=old?.id??Number(db.prepare(`INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at) VALUES(?,?,'LOG','HIGH','OPEN',?,?,?,?)`).run(agentId,key,rule.rule,explanation,stamp,stamp).lastInsertRowid);
        if(old)db.prepare(`UPDATE compliance_findings SET status=CASE WHEN status='RESOLVED' THEN 'OPEN' ELSE status END,explanation=?,last_detected_at=?,resolved_at=NULL WHERE id=?`).run(explanation,stamp,id);
        db.prepare(`INSERT INTO threat_cases(finding_id,agent_id,rule,src_ip,actor,first_log_id,last_log_id,evidence_count) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET last_log_id=excluded.last_log_id,evidence_count=excluded.evidence_count,first_log_id=CASE WHEN threat_cases.handled_through>=threat_cases.last_log_id THEN excluded.first_log_id ELSE threat_cases.first_log_id END`).run(id,agentId,rule.rule,g.ip,g.account,g.firstId,g.lastId,g.n);
        if(!old||old.status==='RESOLVED'){
          opened.push(id);appendAuditEvent(null,'THREAT_CASE_OPENED','finding',id,{agentId,rule:rule.rule,firstLogId:g.firstId,lastLogId:g.lastId});
          if(policy.notifications)db.prepare('INSERT OR IGNORE INTO threat_notification_queue(finding_id) VALUES(?)').run(id);
        }
      }
    }
    return opened;
  })();
}

export function resolveThreatCase(id:number){
  db.prepare(`UPDATE threat_cases SET handled_through=COALESCE((SELECT MAX(id) FROM log_events WHERE agent_id=threat_cases.agent_id),last_log_id) WHERE finding_id=?`).run(id);
}
export function threatCases(q:{agentId?:number;srcIp?:string;from?:string;to?:string}){
  const where:string[]=[],args:unknown[]=[];
  if(q.agentId){where.push('c.agent_id=?');args.push(q.agentId);}
  if(q.srcIp){where.push('c.src_ip=?');args.push(q.srcIp);}
  if(q.from){where.push('f.last_detected_at>=?');args.push(q.from);}
  if(q.to){where.push('f.first_detected_at<=?');args.push(q.to);}
  return db.prepare(`SELECT f.id,f.status,f.severity,f.explanation,f.owner,f.resolution_note AS resolutionNote,c.rule,c.src_ip AS ip,c.actor,c.agent_id AS agentId,a.name AS agent,c.evidence_count AS evidenceCount,c.first_log_id AS firstLogId,c.last_log_id AS lastLogId,f.first_detected_at AS firstDetectedAt,f.last_detected_at AS lastDetectedAt FROM threat_cases c JOIN compliance_findings f ON f.id=c.finding_id JOIN agents a ON a.id=c.agent_id ${where.length?'WHERE '+where.join(' AND '):''} ORDER BY f.last_detected_at DESC,f.id DESC LIMIT 201`).all(...args);
}

export function caseJourney(id:number){
  const c=db.prepare('SELECT * FROM threat_cases WHERE finding_id=?').get(id) as {agent_id:number;src_ip:string;actor:string;first_log_id:number;last_log_id:number}|undefined;
  if(!c)return null;
  // Include one hour after retained detection evidence to surface related successes/unbans, without claiming causality.
  const bounds=db.prepare('SELECT MIN(occurred_at) AS start,MAX(occurred_at) AS end FROM log_events WHERE agent_id=? AND id BETWEEN ? AND ?').get(c.agent_id,c.first_log_id,c.last_log_id) as {start:string|null;end:string|null};
  if(!bounds.start||!bounds.end)return {events:[],truncated:false};
  const end=new Date(new Date(bounds.end).getTime()+3600000).toISOString();
  const rows=db.prepare(`SELECT id,event,source,actor,src_ip AS srcIp,result,details_json AS detailsJson,occurred_at AS occurredAt FROM log_events WHERE agent_id=? AND COALESCE(src_ip,'')=? AND (?!='' OR COALESCE(actor,'')=?) AND occurred_at BETWEEN ? AND ? ORDER BY occurred_at,id LIMIT 201`).all(c.agent_id,c.src_ip,c.src_ip,c.actor,bounds.start,end);
  return {events:rows.slice(0,200),truncated:rows.length>200};
}
