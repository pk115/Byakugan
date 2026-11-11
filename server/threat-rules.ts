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
CREATE INDEX IF NOT EXISTS idx_log_agent_ip_time ON log_events(agent_id,src_ip,occurred_at);`);

export function evaluateThreatRules(agentId:number,now=new Date()) {
  const since=new Date(now.getTime()-15*60000).toISOString(),stamp=now.toISOString();
  const groups=db.prepare(`SELECT src_ip AS ip,COALESCE(actor,'') AS actor,COUNT(*) AS n,MIN(id) AS firstId,MAX(id) AS lastId
    FROM log_events WHERE agent_id=? AND occurred_at BETWEEN ? AND ?
    AND event IN ('LOGIN_FAILED','SSH_LOGIN_FAILED','SUDO_AUTH_FAILED','ROOT_LOGIN_DENIED','VPN_AUTH_FAILED','DB_AUTH_FAILED')
    GROUP BY src_ip,COALESCE(actor,'') HAVING COUNT(*)>=10`).all(agentId,since,stamp) as Array<{ip:string|null;actor:string;n:number;firstId:number;lastId:number}>;
  return db.transaction(()=>{
    const opened:number[]=[];
    for(const g of groups){
      const ip=g.ip??"",key="threat_auth_"+createHash("sha256").update(JSON.stringify([ip,g.actor])).digest("hex").slice(0,32);
      const old=db.prepare(`SELECT f.id,f.status,c.handled_through AS handled FROM compliance_findings f
        JOIN threat_cases c ON c.finding_id=f.id WHERE f.agent_id=? AND f.finding_key=?`).get(agentId,key) as {id:number;status:string;handled:number}|undefined;
      // Reopening requires a new threshold of evidence after the operator's resolution watermark.
      if(old?.status==='RESOLVED'){
        const fresh=db.prepare(`SELECT COUNT(*) AS n,MIN(id) AS firstId FROM log_events WHERE agent_id=? AND id>? AND occurred_at BETWEEN ? AND ? AND COALESCE(src_ip,'')=? AND COALESCE(actor,'')=? AND event IN ('LOGIN_FAILED','SSH_LOGIN_FAILED','SUDO_AUTH_FAILED','ROOT_LOGIN_DENIED','VPN_AUTH_FAILED','DB_AUTH_FAILED')`).get(agentId,old.handled,since,stamp,ip,g.actor) as {n:number;firstId:number};
        if(fresh.n<10)continue;g.firstId=fresh.firstId;g.n=fresh.n;
      }
      const explanation=`${g.n} authentication failures in 15 minutes; source ${ip||'unknown'}, account ${g.actor||'unknown'}. Investigate; this is not proof of compromise.`;
      const id=old?.id??Number(db.prepare(`INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at) VALUES(?,?,'LOG','HIGH','OPEN','Repeated authentication failures by source and account',?,?,?)`).run(agentId,key,explanation,stamp,stamp).lastInsertRowid);
      if(old)db.prepare(`UPDATE compliance_findings SET status=CASE WHEN status='RESOLVED' THEN 'OPEN' ELSE status END,explanation=?,last_detected_at=?,resolved_at=NULL WHERE id=?`).run(explanation,stamp,id);
      db.prepare(`INSERT INTO threat_cases(finding_id,agent_id,rule,src_ip,actor,first_log_id,last_log_id,evidence_count) VALUES(?,?,'AUTH_FAILURES',?,?,?,?,?)
        ON CONFLICT(finding_id) DO UPDATE SET last_log_id=excluded.last_log_id,evidence_count=excluded.evidence_count,
        first_log_id=CASE WHEN threat_cases.handled_through>=threat_cases.last_log_id THEN excluded.first_log_id ELSE threat_cases.first_log_id END`).run(id,agentId,ip,g.actor,g.firstId,g.lastId,g.n);
      if(!old||old.status==='RESOLVED'){opened.push(id);appendAuditEvent(null,'THREAT_CASE_OPENED','finding',id,{agentId,rule:'AUTH_FAILURES',firstLogId:g.firstId,lastLogId:g.lastId});}
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
