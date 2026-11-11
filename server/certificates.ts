import { connect } from "node:tls";
import { isIP } from "node:net";
import type { ProjectRow } from "./database.js";
export function certificateTarget(project: Pick<ProjectRow,"monitor_type"|"target"|"supabase_url"|"ssl_port">) {
  if (project.monitor_type === "SSL" && project.target) return { host: project.target, port: project.ssl_port };
  const target = project.monitor_type === "SUPABASE" ? project.supabase_url : ["HTTP","WEBSOCKET"].includes(project.monitor_type) ? project.target : null;
  if (!target) return null;
  try { const url=new URL(target); return ["https:","wss:"].includes(url.protocol) ? {host:url.hostname.replace(/^\[|\]$/g,""),port:Number(url.port)||443} : null; } catch { return null; }
}
export function certificateDays(expiresAt:string|null, now=Date.now()) { return expiresAt && Number.isFinite(Date.parse(expiresAt)) ? Math.floor((Date.parse(expiresAt)-now)/86400000) : null; }
export async function inspectCertificate(target:{host:string;port:number}, timeoutMs:number) {
  return new Promise<{expiresAt:string|null;valid:boolean;error:string|null}>(resolve=>{
    // Inspection reads the peer certificate even when invalid; it never changes the service probe's TLS validation.
    const socket=connect({host:target.host,port:target.port,servername:isIP(target.host)?undefined:target.host,rejectUnauthorized:false});
    let finished=false;
    const finish=(expiresAt:string|null,valid:boolean,error:string|null)=>{if(finished)return;finished=true;clearTimeout(timer);socket.destroy();resolve({expiresAt,valid,error});};
    const timer=setTimeout(()=>finish(null,false,"Certificate inspection timed out"),timeoutMs);
    socket.once("secureConnect",()=>{
      const date=new Date(socket.getPeerCertificate().valid_to);
      if(!Number.isFinite(date.getTime()))return finish(null,false,"Certificate expiry is unavailable");
      finish(date.toISOString(),socket.authorized,socket.authorized?null:String(socket.authorizationError||"Certificate validation failed"));
    });
    socket.once("error",error=>finish(null,false,error.message));
  });
}
