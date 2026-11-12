import {z} from 'zod';
import {isIP} from 'node:net';
import {db} from './database.js';
export const threatPolicySchema=z.object({
  windowMinutes:z.number().int().min(1).max(1440),authThreshold:z.number().int().min(2).max(10000),
  portThreshold:z.number().int().min(2).max(10000),webThreshold:z.number().int().min(2).max(10000),
  notifications:z.boolean(),cooldownMinutes:z.number().int().min(1).max(1440),
  exceptions:z.array(z.object({ip:z.string().refine(v=>!!isIP(v),'Valid IP required'),agentId:z.number().int().positive().nullable(),reason:z.string().trim().min(10).max(500),expiresAt:z.string().datetime()})).max(100)
});
export type ThreatPolicy=z.infer<typeof threatPolicySchema>;
export function threatPolicy():ThreatPolicy {
  const row=db.prepare("SELECT value FROM app_settings WHERE key='threat_policy'").get() as {value:string}|undefined;
  if(row){try{return threatPolicySchema.parse(JSON.parse(row.value));}catch{}}
  return {windowMinutes:15,authThreshold:10,portThreshold:20,webThreshold:10,notifications:false,cooldownMinutes:15,exceptions:[]};
}
export function excepted(policy:ThreatPolicy,agentId:number,ip:string,now:Date){return policy.exceptions.some(e=>e.ip===ip&&(e.agentId===null||e.agentId===agentId)&&new Date(e.expiresAt)>now);}
