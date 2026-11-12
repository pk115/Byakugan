import './threat-rules.js';
import {db} from './database.js';
import {threatPolicy} from './threat-policy.js';
import {dispatchSecurityNotification} from './notifications.js';
let running=false;
export async function flushThreatNotifications(){
  if(running)return;running=true;
  try{
    const policy=threatPolicy();if(!policy.notifications)return;
    if(!db.prepare('SELECT id FROM notifications WHERE enabled=1 LIMIT 1').get())return;
    const last=db.prepare("SELECT value FROM app_settings WHERE key='threat_notification_last'").get() as {value:string}|undefined;
    if(last&&Date.now()-new Date(last.value).getTime()<policy.cooldownMinutes*60000)return;
    const ids=db.prepare(`SELECT q.finding_id AS id FROM threat_notification_queue q JOIN compliance_findings f ON f.id=q.finding_id WHERE f.status='OPEN' ORDER BY q.finding_id LIMIT 100`).all() as {id:number}[];
    db.prepare("DELETE FROM threat_notification_queue WHERE finding_id IN (SELECT id FROM compliance_findings WHERE status!='OPEN')").run();
    if(!ids.length)return;
    // At-most-once dispatch per queued episode; delivery failures stay visible in notification history.
    db.transaction(()=>{for(const row of ids)db.prepare('DELETE FROM threat_notification_queue WHERE finding_id=?').run(row.id);db.prepare("INSERT INTO app_settings(key,value) VALUES('threat_notification_last',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(new Date().toISOString());})();
    await dispatchSecurityNotification('THREAT_DETECTED',`Byakugan: ${ids.length} threat case(s) require review. Cases: ${ids.map(r=>'#'+r.id).join(', ')}. Detection is not confirmation of compromise.`);
  }finally{running=false;}
}
