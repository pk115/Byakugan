#!/usr/bin/env node
import os from "node:os";
import { readFile, access } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const endpoint = process.env.SUPAPULSE_URL?.replace(/\/$/, "");
const token = process.env.SUPAPULSE_AGENT_TOKEN;
const intervalSeconds = Math.max(60, Number(process.env.SUPAPULSE_AGENT_INTERVAL ?? 300));
const jobPollSeconds = Math.max(5, Number(process.env.SUPAPULSE_SCAN_POLL_INTERVAL ?? 15));
const trivyTarget = process.env.SUPAPULSE_TRIVY_TARGET;
if (!endpoint || !token) throw new Error("SUPAPULSE_URL and SUPAPULSE_AGENT_TOKEN are required");

async function command(file, args, timeout = 10000) { try { return (await exec(file, args, { timeout, maxBuffer: 5_000_000 })).stdout.trim(); } catch { return ""; } }
async function request(path,options={}){return fetch(`${endpoint}${path}`,{...options,headers:{Authorization:`Bearer ${token}`,...(options.body?{"Content-Type":"application/json"}:{}),...(options.headers??{})}})}
async function cpuPercent() {
  const sample = () => os.cpus().reduce((sum, cpu) => ({ idle: sum.idle + cpu.times.idle, total: sum.total + Object.values(cpu.times).reduce((a,b)=>a+b,0) }), {idle:0,total:0});
  const before=sample();await new Promise(resolve=>setTimeout(resolve,500));const after=sample();
  return Math.round((100-(after.idle-before.idle)/(after.total-before.total)*100)*100)/100;
}
async function disks() {
  const output=await command("df",["-P","-B1","-x","tmpfs","-x","devtmpfs"]);return output.split("\n").slice(1).map(line=>line.trim().split(/\s+/)).filter(parts=>parts.length>=6).map(parts=>({mount:parts.slice(5).join(" "),totalBytes:Number(parts[1]),usedBytes:Number(parts[2]),usedPercent:Number(parts[4].replace("%",""))})).filter(item=>Number.isFinite(item.usedPercent));
}
async function containers() {
  const output=await command("docker",["ps","-a","--format","{{json .}}"]);if(!output)return[];return output.split("\n").map(line=>{try{const value=JSON.parse(line);return{name:value.Names||value.ID,status:value.Status||"unknown",running:String(value.State).toLowerCase()==="running"}}catch{return null}}).filter(Boolean);
}
async function updates() {
  const installed=Number(await command("sh",["-c","dpkg-query -W -f='${binary:Package}\\n' 2>/dev/null | wc -l"]))||0;
  const list=await command("sh",["-c","apt list --upgradable 2>/dev/null | tail -n +2"]);const lines=list?list.split("\n").filter(Boolean):[];
  return {installedPackageCount:installed,pendingUpdateCount:lines.length,securityUpdateCount:lines.filter(line=>/security/i.test(line)).length};
}
async function exists(path){try{await access(path);return true}catch{return false}}
async function vulnerabilityScan(){
  if(!trivyTarget)return undefined;
  const output=await command("trivy",["fs","--quiet","--scanners","vuln","--format","json",trivyTarget],180000);if(!output)return undefined;
  try{const report=JSON.parse(output);const vulnerabilities=(report.Results??[]).flatMap(result=>(result.Vulnerabilities??[]).map(item=>({id:String(item.VulnerabilityID??"UNKNOWN"),packageName:String(item.PkgName??"unknown"),installedVersion:String(item.InstalledVersion??"unknown"),fixedVersion:item.FixedVersion?String(item.FixedVersion):undefined,severity:["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"].includes(item.Severity)?item.Severity:"UNKNOWN",title:item.Title?String(item.Title).slice(0,1000):undefined}))).slice(0,2000);return{scanner:"Trivy",target:trivyTarget,vulnerabilities}}catch{return undefined}
}
function severity(value){const normalized=String(value??"UNKNOWN").toUpperCase();return["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"].includes(normalized)?normalized:"UNKNOWN"}
function normalizeTrivy(report){const findings=[];for(const result of report.Results??[]){const path=String(result.Target??"").slice(0,1000);for(const item of result.Vulnerabilities??[])findings.push({id:String(item.VulnerabilityID??"UNKNOWN"),type:"VULNERABILITY",packageName:String(item.PkgName??"unknown"),installedVersion:String(item.InstalledVersion??""),...(item.FixedVersion?{fixedVersion:String(item.FixedVersion)}:{}),severity:severity(item.Severity),...(item.Title?{title:String(item.Title).slice(0,1000)}:{}),resourcePath:path,...(item.PrimaryURL?{primaryUrl:String(item.PrimaryURL)}:{})});for(const item of result.Misconfigurations??[])findings.push({id:String(item.ID??"MISCONFIG"),type:"MISCONFIGURATION",packageName:String(item.Type??item.AVDID??"configuration"),installedVersion:"",severity:severity(item.Severity),title:String(item.Title??item.Message??"Configuration finding").slice(0,1000),resourcePath:path,...(item.PrimaryURL?{primaryUrl:String(item.PrimaryURL)}:{})});for(const item of result.Secrets??[])findings.push({id:String(item.RuleID??"SECRET"),type:"SECRET",packageName:String(item.Category??"secret"),installedVersion:"",severity:severity(item.Severity??"HIGH"),title:String(item.Title??"Exposed secret").slice(0,1000),resourcePath:path})}return{findings:findings.slice(0,5000),truncated:findings.length>5000}}
let scanRunning=false;
async function pollScanJob(){if(scanRunning)return;scanRunning=true;let job;try{const response=await request("/api/agent/scan-jobs/next");if(!response.ok)throw new Error(`Job poll returned HTTP ${response.status}`);job=await response.json();if(!job||job.job===null)return;await request(`/api/agent/scan-jobs/${job.id}/progress`,{method:"POST",body:JSON.stringify({progress:15})});const started=Date.now(),subcommand={FILESYSTEM:"fs",ROOTFS:"rootfs",IMAGE:"image"}[job.targetType];if(!subcommand)throw Object.assign(new Error("Unsupported scan target type"),{code:"UNSUPPORTED_TARGET"});const version=(await exec("trivy",["--version"],{timeout:15000,maxBuffer:100000})).stdout.split("\n")[0].trim();const args=[subcommand,"--quiet","--scanners",job.scanners.join(","),"--severity",job.severity.join(","),"--format","json",job.target];const output=(await exec("trivy",args,{timeout:900000,maxBuffer:50_000_000})).stdout;await request(`/api/agent/scan-jobs/${job.id}/progress`,{method:"POST",body:JSON.stringify({progress:90})});const normalized=normalizeTrivy(JSON.parse(output)),result=await request(`/api/agent/scan-jobs/${job.id}/result`,{method:"POST",body:JSON.stringify({scanner:"Trivy",scannerVersion:version,observedAt:new Date().toISOString(),findings:normalized.findings,summary:{durationMs:Date.now()-started,truncated:normalized.truncated}})});if(!result.ok)throw new Error(`Result upload returned HTTP ${result.status}: ${await result.text()}`);console.log(`${new Date().toISOString()} scan job ${job.id} completed with ${normalized.findings.length} finding(s)`)}catch(error){console.error(new Date().toISOString(),error.message);if(job?.id)await request(`/api/agent/scan-jobs/${job.id}/failure`,{method:"POST",body:JSON.stringify({code:error.code??(error.code==="ENOENT"?"TRIVY_NOT_INSTALLED":"SCAN_FAILED"),message:String(error.message??"Scan failed").slice(0,1000)})}).catch(()=>undefined)}finally{scanRunning=false}}
async function collect() {
  const [cpu, diskValues, containerValues, patch, osRelease, vulnerabilities] = await Promise.all([cpuPercent(),disks(),containers(),updates(),readFile("/etc/os-release","utf8").catch(()=>""),vulnerabilityScan()]);
  const osFields=Object.fromEntries(osRelease.split("\n").filter(line=>line.includes("=")).map(line=>{const [key,...rest]=line.split("=");return[key,rest.join("=").replace(/^"|"$/g,"")]}));
  const total=os.totalmem();const free=os.freemem();
  return {agentVersion:"0.3.0",observedAt:new Date().toISOString(),hostname:os.hostname(),inventory:{osName:osFields.PRETTY_NAME||os.type(),osVersion:osFields.VERSION_ID||os.release(),kernel:os.release(),architecture:os.arch(),cpuModel:os.cpus()[0]?.model||"unknown",cpuCount:os.cpus().length,totalMemoryBytes:total,...patch,rebootRequired:await exists("/var/run/reboot-required"),dockerAvailable:containerValues.length>0||Boolean(await command("docker",["version","--format","{{.Server.Version}}"]))},metrics:{cpuPercent:cpu,memoryPercent:Math.round((total-free)/total*10000)/100,swapPercent:null,load1:os.loadavg()[0],load5:os.loadavg()[1],load15:os.loadavg()[2],uptimeSeconds:Math.floor(os.uptime()),disks:diskValues,containers:containerValues},...(vulnerabilities?{vulnerabilityScan:vulnerabilities}:{})};
}
async function send(){const payload=await collect();const response=await fetch(`${endpoint}/api/agent/ingest`,{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify(payload)});if(!response.ok)throw new Error(`Byakugan returned HTTP ${response.status}: ${await response.text()}`);console.log(`${new Date().toISOString()} evidence sent for ${payload.hostname}`)}
await send();void pollScanJob();setInterval(()=>send().catch(error=>console.error(new Date().toISOString(),error.message)),intervalSeconds*1000).unref();setInterval(()=>void pollScanJob(),jobPollSeconds*1000).unref();await new Promise(()=>{});
