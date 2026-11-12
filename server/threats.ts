import {geoReader,locate,threatLocations} from "./threat-geo.js";
import { db } from "./database.js";
import { logFilter, type LogQuery } from "./log-events.js";

export function threatOverview(query: LogQuery) {
  const {sql,params} = logFilter({...query,threatOnly:"true",beforeId:undefined,beforeTime:undefined});
  return db.transaction(() => {
    const summary = db.prepare(`SELECT COUNT(*) AS events,COUNT(DISTINCT NULLIF(l.src_ip,'')) AS ips,
      COUNT(DISTINCT l.agent_id) AS agents,COALESCE(SUM(l.event='FIREWALL_DENY'),0) AS blocked
      FROM log_events l ${sql}`).get(...params);
    const sources = db.prepare(`SELECT l.src_ip AS ip,COUNT(*) AS events,COUNT(DISTINCT l.agent_id) AS agents,
      MAX(l.occurred_at) AS lastSeen FROM log_events l ${sql} GROUP BY l.src_ip ORDER BY events DESC,l.src_ip LIMIT 50`).all(...params);
    const types = db.prepare(`SELECT l.event,COUNT(*) AS events FROM log_events l ${sql} GROUP BY l.event ORDER BY events DESC`).all(...params);
    const timeline = db.prepare(`SELECT strftime('%Y-%m-%dT%H:00:00Z',l.occurred_at) AS time,COUNT(*) AS events
      FROM log_events l ${sql} GROUP BY time ORDER BY time DESC LIMIT 168`).all(...params).reverse();
    // Coverage is current receipt state, independent of investigation filters except selected agent.
    const coverage = db.prepare(`SELECT a.id AS agentId,a.name,a.hostname,a.enabled,a.last_seen_at AS lastSeen,
      (SELECT MAX(received_at) FROM log_events WHERE agent_id=a.id) AS lastLog,
      (SELECT GROUP_CONCAT(DISTINCT source) FROM log_events WHERE agent_id=a.id) AS sources
      FROM agents a ${query.agentId ? "WHERE a.id=?" : ""} ORDER BY a.id LIMIT 501`).all(...(query.agentId ? [query.agentId] : []));
    return {summary,sources,types,timeline,coverage:coverage.slice(0,500),coverageTruncated:coverage.length>500,generatedAt:new Date().toISOString()};
  })();
}

export async function threatMap(query:LogQuery){
  const {sql,params}=logFilter({...query,threatOnly:"true",beforeId:undefined,beforeTime:undefined});
  const rows=db.prepare(`SELECT l.agent_id AS agentId,a.name AS agent,l.src_ip AS ip,COUNT(*) AS events FROM log_events l JOIN agents a ON a.id=l.agent_id ${sql} GROUP BY l.agent_id,l.src_ip ORDER BY events DESC,l.agent_id,l.src_ip LIMIT 101`).all(...params) as Array<{agentId:number;agent:string;ip:string|null;events:number}>;
  const reader=await geoReader();
  return {available:!!reader,routes:rows.slice(0,100).map(row=>({...row,location:locate(row.ip,reader)})),truncated:rows.length>100,targets:threatLocations()};
}
