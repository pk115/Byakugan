import {isIP} from 'node:net';
const cut=v=>String(v??'').slice(0,1000);
function timestamp(value){const d=new Date(value);return Number.isFinite(+d)?d.toISOString():null;}
function webEvent({time,ip,method,path,status,host}){
  if(!time||!isIP(ip))return null;
  let decoded=path;try{decoded=decodeURIComponent(path);}catch{}
  const probe=/(?:^|\/)\.env(?:[/?]|$)|(?:^|\/)\.git(?:\/|$)|(?:^|\/)wp-config\.php(?:[?.]|$)|(?:^|\/)etc\/passwd(?:[?]|$)|\.\.\//i.test(decoded);
  return {source:'nginx',event:probe?'HTTP_PROBE':'HTTP_REQUEST',timestamp:time,host,srcIp:ip,result:String(status),severity:probe?'warning':Number(status)>=500?'error':'info',details:{method,request_uri:cut(path),status:Number(status),...(probe?{detection:'sensitive-path-probe',confidence:'heuristic'}:{})}};
}
export function parseNpmLine(line,host){
  const m=/^\[([^\]]+)\] .*? (\d{3}) - (\S+) \S+ (\S+) "([^"]*)" \[Client ([^\]]+)\]/.exec(line);
  if(!m)return null;
  const t=/^(\d{2})\/(\w{3})\/(\d{4}):([\d:]+) ([+-]\d{2})(\d{2})$/.exec(m[1]);if(!t)return null;
  const month=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(t[2])+1;
  const time=timestamp(`${t[3]}-${String(month).padStart(2,'0')}-${t[1]}T${t[4]}${t[5]}:${t[6]}`);
  const result=webEvent({time,ip:m[6],method:m[3],path:m[5],status:m[2],host});if(result)result.details.virtual_host=cut(m[4]);return result;
}
export function classifyWebEvent(e){if(!e)return e;const updated=webEvent({time:e.timestamp,ip:e.srcIp,method:e.details.method,path:e.details.request_uri,status:e.details.status,host:e.host});return updated?.event==='HTTP_PROBE'?{...e,event:updated.event,severity:'warning',details:{...e.details,...updated.details}}:e;}
export function parseUfwLine(line,host,now=new Date()){
  if(!line.includes('[UFW BLOCK]')&&!line.includes('[UFW REJECT]'))return null;
  const pairs=Object.fromEntries([...line.matchAll(/\b([A-Z]+)=([^\s]*)/g)].map(m=>[m[1],m[2]]));if(!isIP(pairs.SRC??''))return null;
  const raw=/^(\S+T\S+)/.exec(line)?.[1];
  const legacy=/^(\w{3})\s+(\d+)\s+([\d:]{8})/.exec(line);
  let time=raw?timestamp(raw):null;
  if(!time&&legacy){const d=new Date(`${legacy[1]} ${legacy[2]} ${now.getFullYear()} ${legacy[3]}`);if(+d>+now+86400000)d.setFullYear(d.getFullYear()-1);time=timestamp(d);}
  if(!time)return null;
  return {source:'firewall',event:'FIREWALL_DENY',timestamp:time,host,srcIp:pairs.SRC,result:'deny',severity:'warning',details:{dst_ip:cut(pairs.DST),dst_port:cut(pairs.DPT),src_port:cut(pairs.SPT),protocol:cut(pairs.PROTO),rule:line.includes('[UFW REJECT]')?'UFW REJECT':'UFW BLOCK'}};
}
export function parseFail2banLine(line,host){
  const m=/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:[,\.]\d+)? .*?\[([^\]]+)\] (Ban|Unban) (\S+)\s*$/.exec(line);
  if(!m||!isIP(m[4]))return null;const time=timestamp(m[1].replace(' ','T'));if(!time)return null;
  return {source:'fail2ban',event:m[3]==='Ban'?'IP_BANNED':'IP_UNBANNED',timestamp:time,host,srcIp:m[4],result:m[3]==='Ban'?'blocked':'unblocked',severity:m[3]==='Ban'?'warning':'info',details:{jail:cut(m[2])}};
}

export function parseSuricataLine(line,host){
  let r;try{r=JSON.parse(line);}catch{return null;}
  if(!r||r.event_type!=='alert'||!r.alert||!isIP(r.src_ip??'')||!isIP(r.dest_ip??''))return null;
  const time=timestamp(r.timestamp);if(!time||!Number.isInteger(r.alert.signature_id))return null;
  const blocked=r.verdict?.action==='drop'||r.verdict?.action==='reject'||r.alert.action==='blocked';
  const port=v=>Number.isInteger(v)&&v>=0&&v<=65535?v:null;
  return {source:'suricata',event:'IDS_ALERT',timestamp:time,host,srcIp:r.src_ip,result:blocked?'blocked':'detected',severity:Number(r.alert.severity)===1?'critical':Number(r.alert.severity)===2?'error':'warning',details:{
    signature_id:r.alert.signature_id,signature:cut(r.alert.signature),category:cut(r.alert.category),signature_severity:Number(r.alert.severity)||0,
    action:cut(r.alert.action),verdict:cut(r.verdict?.action),dst_ip:r.dest_ip,dst_port:port(r.dest_port),src_port:port(r.src_port),protocol:cut(r.proto),
    flow_id:cut(/"flow_id"\s*:\s*(\d+)/.exec(line)?.[1]??r.flow_id),direction:cut(r.direction),
    alert_source_ip:cut(r.alert.source?.ip),alert_target_ip:cut(r.alert.target?.ip)
  }};
}
