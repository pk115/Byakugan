import { existsSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import argon2 from "argon2";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import archiver = require("archiver");
import { z } from "zod";
import QRCode from "qrcode";
import { clearSessionCookie, createSession, requireAuth, sessionUser, setSessionCookie } from "./auth.js";
import { config } from "./config.js";
import { decrypt, encrypt } from "./crypto.js";
import { db, publicProject, type ProjectRow } from "./database.js";
import { checkProject } from "./monitor.js";
import { dispatchSecurityNotification, testNotification, type NotificationType } from "./notifications.js";
import { startScheduler, stopScheduler } from "./scheduler.js";
import { appendAuditEvent, verifyAuditChain } from "./audit.js";
import { auditPeriod, collectAuditReport, createPdfReport, createXlsxReport, reportSha256 } from "./reports.js";
import { createMfaSecret, createRecoveryCodes, mfaUri, recoveryCodeHash, verifyMfaCode } from "./mfa.js";
import * as oidcClient from "openid-client";
import { allowedEmail, authorizationUrl, chooseRole, consumeState, oidcConfiguration, type OidcProvider, type Role } from "./oidc.js";
import {deliveryErrorCode,testDeliveryChannel,type DeliveryConfig} from "./report-delivery.js";
import { syncThreatIntelligence, threatIntelligenceStatus } from "./threat-intelligence.js";

const app = Fastify({ logger: { level: config.isProduction ? "info" : "warn" }, bodyLimit: 64 * 1024 });
await app.register(cookie);
await app.register(rateLimit, { global: false });

const credentialsSchema = z.object({
  username: z.string().trim().min(3).max(64),
  password: z.string().min(10).max(256)
});

const projectObject = z.object({
  name: z.string().trim().min(1).max(100),
  monitorType: z.enum(["SUPABASE", "HTTP", "TCP", "PING", "DNS", "SSL", "DOCKER", "DATABASE"]).default("SUPABASE"),
  supabaseUrl: z.string().url().transform((value) => value.replace(/\/$/, "")).optional(),
  publishableKey: z.string().max(4096).optional(),
  target: z.string().trim().max(2048).optional(),
  httpMethod: z.enum(["GET", "HEAD"]).default("GET"),
  expectedStatus: z.number().int().min(100).max(599).nullable().optional(),
  keyword: z.string().max(500).nullable().optional(),
  tcpHost: z.string().trim().max(253).optional(),
  tcpPort: z.number().int().min(1).max(65535).optional(),
  dnsRecordType: z.enum(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV"]).default("A"),
  sslPort: z.number().int().min(1).max(65535).default(443),
  sslExpiryDays: z.number().int().min(1).max(365).default(14),
  dockerContainer: z.string().trim().max(255).optional(),
  databaseEngine:z.enum(["POSTGRESQL","MYSQL","SQLSERVER","MONGODB"]).optional(),
  connectionString:z.string().trim().max(8192).optional(),
  published: z.boolean().default(false),
  intervalSeconds: z.number().int().min(20).max(604800).default(21600),
  timeoutSeconds: z.number().int().min(3).max(60).default(15),
  retryCount: z.number().int().min(0).max(5).default(2),
  enabled: z.boolean().default(true),
  maintenance: z.boolean().default(false)
});

function validateProjectUrl(value: { supabaseUrl?: string }, context: z.RefinementCtx) {
  const typed = value as z.infer<typeof projectObject>;
  if (typed.monitorType === "SUPABASE" && (!typed.supabaseUrl || !typed.publishableKey || typed.publishableKey.length < 20)) {
    context.addIssue({ code: "custom", path: ["publishableKey"], message: "Supabase URL and publishable key are required" });
    return;
  }
  if (typed.monitorType === "HTTP" && !typed.target) {
    context.addIssue({ code: "custom", path: ["target"], message: "HTTP target URL is required" });
  }
  if (typed.monitorType === "HTTP" && typed.target) {
    try { const url = new URL(typed.target); if (!["http:", "https:"].includes(url.protocol)) throw new Error(); }
    catch { context.addIssue({ code: "custom", path: ["target"], message: "A valid HTTP or HTTPS URL is required" }); }
  }
  if (typed.monitorType === "TCP" && (!typed.tcpHost || !typed.tcpPort)) {
    context.addIssue({ code: "custom", path: ["tcpHost"], message: "TCP host and port are required" });
  }
  if (["PING", "DNS", "SSL"].includes(typed.monitorType) && !typed.target) {
    context.addIssue({ code: "custom", path: ["target"], message: "Hostname is required" });
  }
  if (typed.monitorType === "DOCKER" && !typed.dockerContainer) {
    context.addIssue({ code: "custom", path: ["dockerContainer"], message: "Docker container name or ID is required" });
  }
  if(typed.monitorType==="DATABASE"&&(!typed.databaseEngine||!typed.connectionString)){context.addIssue({code:"custom",path:["connectionString"],message:"Database engine and connection string are required"})}
  if(typed.monitorType==="DATABASE"&&typed.databaseEngine&&typed.connectionString){const schemes:{[key:string]:string[]}={POSTGRESQL:["postgres:","postgresql:"],MYSQL:["mysql:"],MONGODB:["mongodb:","mongodb+srv:"]};if(typed.databaseEngine!=="SQLSERVER"){try{const protocol=new URL(typed.connectionString).protocol;if(!schemes[typed.databaseEngine].includes(protocol))throw new Error()}catch{context.addIssue({code:"custom",path:["connectionString"],message:`Connection string does not match ${typed.databaseEngine}`})}}}
  if (!typed.supabaseUrl) return;
  const url = new URL(typed.supabaseUrl);
  if (url.protocol !== "https:" || !(url.hostname === "supabase.co" || url.hostname.endsWith(".supabase.co"))) {
    context.addIssue({ code: "custom", path: ["supabaseUrl"], message: "Only HTTPS supabase.co project URLs are accepted" });
  }
}

const projectSchema = projectObject.superRefine(validateProjectUrl);
const updateProjectSchema = projectObject.partial();

const notificationSchema = z.object({
  name: z.string().trim().min(1).max(100),
  type: z.enum(["WEBHOOK", "DISCORD", "TELEGRAM"]),
  url: z.string().url().optional(),
  botToken: z.string().min(10).max(256).optional(),
  chatId: z.string().min(1).max(100).optional(),
  enabled: z.boolean().default(true)
}).superRefine((value, context) => {
  if (value.type === "TELEGRAM" && (!value.botToken || !value.chatId)) {
    context.addIssue({ code: "custom", path: ["botToken"], message: "Bot token and chat ID are required" });
  }
  if (value.type !== "TELEGRAM" && !value.url) {
    context.addIssue({ code: "custom", path: ["url"], message: "Webhook URL is required" });
  }
});

const shareDashboardSchema = z.object({
  name: z.string().trim().min(1).max(100),
  projects: z.array(z.object({ projectId: z.number().int().positive(), groupName: z.string().trim().min(1).max(80) })).min(1).max(100)
});
const auditProfileSchema = z.object({
  assetTag: z.string().trim().max(100).nullable().optional(), assetOwner: z.string().trim().max(150).nullable().optional(),
  environment: z.enum(["Production", "Staging", "Development", "DR", "Other"]),
  criticality: z.enum(["Low", "Medium", "High", "Critical"]),
  warningThreshold: z.number().nullable().optional(), criticalThreshold: z.number().nullable().optional(),
  thresholdOperator: z.enum([">=", ">", "<=", "<"]), thresholdDurationSeconds: z.number().int().min(0).max(86400),
  controlIds: z.array(z.number().int().positive()).max(50)
});
const agentPayloadSchema = z.object({
  agentVersion:z.string().max(30), observedAt:z.string().datetime(), hostname:z.string().min(1).max(253),
  inventory:z.object({osName:z.string().max(100),osVersion:z.string().max(150).optional(),kernel:z.string().max(150).optional(),architecture:z.string().max(50),cpuModel:z.string().max(200),cpuCount:z.number().int().min(1).max(2048),totalMemoryBytes:z.number().int().nonnegative(),installedPackageCount:z.number().int().nonnegative().default(0),pendingUpdateCount:z.number().int().nonnegative().default(0),securityUpdateCount:z.number().int().nonnegative().default(0),rebootRequired:z.boolean().default(false),dockerAvailable:z.boolean().default(false)}),
  metrics:z.object({cpuPercent:z.number().min(0).max(100),memoryPercent:z.number().min(0).max(100),swapPercent:z.number().min(0).max(100).nullable().optional(),load1:z.number().nonnegative().nullable().optional(),load5:z.number().nonnegative().nullable().optional(),load15:z.number().nonnegative().nullable().optional(),uptimeSeconds:z.number().int().nonnegative(),disks:z.array(z.object({mount:z.string().max(500),totalBytes:z.number().nonnegative(),usedBytes:z.number().nonnegative(),usedPercent:z.number().min(0).max(100)})).max(100),containers:z.array(z.object({name:z.string().max(255),status:z.string().max(100),running:z.boolean()})).max(500)}),
  vulnerabilityScan:z.object({scanner:z.literal("Trivy"),target:z.string().max(500),vulnerabilities:z.array(z.object({id:z.string().min(1).max(100),packageName:z.string().min(1).max(300),installedVersion:z.string().max(300),fixedVersion:z.string().max(500).optional(),severity:z.enum(["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"]),title:z.string().max(1000).optional()})).max(2000)}).optional()
});
const findingWorkflowSchema = z.object({
  status:z.enum(["OPEN","ACKNOWLEDGED","RESOLVED"]), owner:z.string().trim().max(150).nullable().optional(),
  dueAt:z.string().datetime().nullable().optional(), resolutionNote:z.string().trim().max(2000).nullable().optional()
});
const backupEvidenceSchema = z.object({
  assetName:z.string().trim().min(1).max(150), backupType:z.enum(["FULL","INCREMENTAL","SNAPSHOT","DATABASE","CONFIGURATION"]),
  storageLocation:z.string().trim().min(1).max(500), status:z.enum(["SUCCESS","WARNING","FAILED"]),
  startedAt:z.string().datetime(), completedAt:z.string().datetime().nullable().optional(), sizeBytes:z.number().int().nonnegative().nullable().optional(),
  checksum:z.string().trim().max(256).nullable().optional(), notes:z.string().trim().max(2000).nullable().optional()
});
const restoreTestSchema = z.object({
  backupEvidenceId:z.number().int().positive().nullable().optional(), assetName:z.string().trim().min(1).max(150),
  testScope:z.string().trim().min(1).max(500), result:z.enum(["PASS","PARTIAL","FAIL"]), testedAt:z.string().datetime(),
  rtoMinutes:z.number().int().nonnegative().nullable().optional(), actualMinutes:z.number().int().nonnegative().nullable().optional(),
  evidenceNote:z.string().trim().max(2000).nullable().optional()
});
const vulnerabilityWorkflowSchema=z.object({status:z.enum(["OPEN","IN_PROGRESS","RISK_ACCEPTED","RESOLVED"]),owner:z.string().trim().max(150).nullable().optional(),dueAt:z.string().datetime().nullable().optional(),riskReason:z.string().trim().max(2000).nullable().optional(),riskExpiresAt:z.string().datetime().nullable().optional()}).superRefine((value,context)=>{if(value.status==="RISK_ACCEPTED"&&(!value.riskReason||!value.riskExpiresAt))context.addIssue({code:"custom",path:["riskReason"],message:"Risk reason and expiry are required"})});
const scanJobSchema=z.object({agentId:z.number().int().positive(),profileId:z.number().int().positive().optional(),targetType:z.enum(["FILESYSTEM","ROOTFS","IMAGE"]),target:z.string().trim().min(1).max(500),scanners:z.array(z.enum(["vuln","misconfig","secret"])).min(1).max(3).default(["vuln"]),severity:z.array(z.enum(["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"])).min(1).max(5).default(["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"])});
const scanProfileSchema=z.object({name:z.string().trim().min(1).max(120),description:z.string().trim().max(500).optional(),targetType:z.enum(["FILESYSTEM","ROOTFS","IMAGE"]),scanners:z.array(z.enum(["vuln","misconfig","secret"])).min(1).max(3),severity:z.array(z.enum(["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"])).min(1).max(5),timeoutSeconds:z.number().int().min(60).max(3600).default(900)});
const scanScheduleSchema=z.object({name:z.string().trim().min(1).max(120),agentId:z.number().int().positive(),profileId:z.number().int().positive(),target:z.string().trim().min(1).max(500),frequency:z.enum(["DAILY","WEEKLY"]),firstRunAt:z.string().datetime().optional()});
const scanFindingSchema=z.object({id:z.string().min(1).max(150),type:z.enum(["VULNERABILITY","MISCONFIGURATION","SECRET"]),packageName:z.string().min(1).max(300),installedVersion:z.string().max(300).default(""),fixedVersion:z.string().max(500).optional(),severity:z.enum(["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"]),title:z.string().max(1000).optional(),resourcePath:z.string().max(1000).optional(),primaryUrl:z.string().url().max(2000).optional()});
const scanResultSchema=z.object({scanner:z.literal("Trivy"),scannerVersion:z.string().max(100),observedAt:z.string().datetime(),findings:z.array(scanFindingSchema).max(5000),summary:z.object({durationMs:z.number().int().nonnegative(),truncated:z.boolean().default(false)})});
const userCreateSchema=z.object({username:z.string().trim().min(3).max(64),password:z.string().min(10).max(256),role:z.enum(["ADMIN","OPERATOR","AUDITOR","VIEWER"])});
const userUpdateSchema=z.object({role:z.enum(["ADMIN","OPERATOR","AUDITOR","VIEWER"]),enabled:z.boolean(),password:z.string().min(10).max(256).optional()});
const reportScheduleSchema=z.object({name:z.string().trim().min(1).max(120),frequency:z.enum(["WEEKLY","MONTHLY"]),formats:z.array(z.enum(["PDF","XLSX"])).min(1).max(2),periodDays:z.number().int().min(7).max(365),deliveryChannelIds:z.array(z.number().int().positive()).max(20).default([]),enabled:z.boolean().default(true)});
const smtpDeliverySchema=z.object({name:z.string().trim().min(1).max(120),type:z.literal("SMTP"),host:z.string().trim().min(1).max(253),port:z.number().int().min(1).max(65535),secure:z.boolean(),username:z.string().max(500).optional(),password:z.string().max(4096).optional(),from:z.email(),recipients:z.array(z.email()).min(1).max(50)}).superRefine((value,context)=>{if(Boolean(value.username)!==Boolean(value.password))context.addIssue({code:"custom",path:["username"],message:"SMTP username and password must be supplied together"})});
const s3DeliverySchema=z.object({name:z.string().trim().min(1).max(120),type:z.literal("S3"),endpoint:z.union([z.url(),z.literal("")]).optional(),region:z.string().trim().min(1).max(100),bucket:z.string().trim().min(3).max(255),prefix:z.string().trim().max(500).default("byakugan-audit"),accessKeyId:z.string().min(1).max(500),secretAccessKey:z.string().min(1).max(4096),forcePathStyle:z.boolean().default(false),wormMode:z.enum(["NONE","GOVERNANCE","COMPLIANCE"]).default("NONE"),retentionDays:z.number().int().min(1).max(3650).default(365),legalHold:z.boolean().default(false)});
const reportDeliveryChannelSchema=z.discriminatedUnion("type",[smtpDeliverySchema,s3DeliverySchema]);
function deliveryConfig(body:z.infer<typeof reportDeliveryChannelSchema>):DeliveryConfig{if(body.type==="SMTP"){const{name,type,...config}=body;void name;void type;return{type:"SMTP",config}}const{name,type,...config}=body;void name;void type;return{type:"S3",config}}
const backupConnectorSchema=z.object({name:z.string().trim().min(1).max(120),assetName:z.string().trim().min(1).max(150),backupType:z.enum(["FULL","INCREMENTAL","SNAPSHOT","DATABASE","CONFIGURATION"]),maxAgeHours:z.number().int().min(1).max(8760)});
const backupIngestSchema=z.object({status:z.enum(["SUCCESS","WARNING","FAILED"]),startedAt:z.string().datetime(),completedAt:z.string().datetime().nullable().optional(),storageLocation:z.string().trim().min(1).max(500),sizeBytes:z.number().int().nonnegative().nullable().optional(),checksum:z.string().trim().max(256).nullable().optional(),notes:z.string().trim().max(2000).nullable().optional()});
const incidentReviewSchema=z.object({severity:z.enum(["LOW","MEDIUM","HIGH","CRITICAL"]),owner:z.string().trim().max(150).nullable().optional(),rootCause:z.string().trim().max(4000).nullable().optional(),correctiveAction:z.string().trim().max(4000).nullable().optional(),lessonsLearned:z.string().trim().max(4000).nullable().optional(),reviewStatus:z.enum(["PENDING","IN_REVIEW","APPROVED"])}).superRefine((value,context)=>{if(value.reviewStatus==="APPROVED"&&(!value.rootCause||!value.correctiveAction))context.addIssue({code:"custom",path:["rootCause"],message:"Root cause and corrective action are required for approval"})});
const mfaCodeSchema=z.object({code:z.string().regex(/^\d{6}$/)});const mfaLoginSchema=z.object({challengeToken:z.string().min(32).max(128),code:z.string().trim().regex(/^(?:\d{6}|[A-Fa-f0-9]{4}(?:-[A-Fa-f0-9]{4}){2})$/)});
const preferencesSchema=z.object({locale:z.enum(["en-US","th-TH"]),timezone:z.string().trim().min(1).max(100).refine(value=>value==="SYSTEM"||Intl.supportedValuesOf("timeZone").includes(value),"Unsupported timezone")});
const systemRegionalSchema=z.object({locale:z.enum(["en-US","th-TH"]),timezone:z.string().trim().min(1).max(100).refine(value=>Intl.supportedValuesOf("timeZone").includes(value),"Unsupported timezone")});
const mfaPolicySchema=z.object({requiredRoles:z.array(z.enum(["ADMIN","OPERATOR","AUDITOR","VIEWER"])).max(4)});
const oidcProviderSchema=z.object({name:z.string().trim().min(1).max(100),preset:z.enum(["GENERIC","ENTRA","GOOGLE","KEYCLOAK"]).default("GENERIC"),issuerUrl:z.string().url(),clientId:z.string().trim().min(1).max(500),clientSecret:z.string().min(1).max(4096),scopes:z.string().trim().min(6).max(500).default("openid email profile"),usernameClaim:z.string().trim().min(1).max(100).default("email"),groupsClaim:z.string().trim().min(1).max(100).default("groups"),allowedDomains:z.array(z.string().trim().toLowerCase().regex(/^[a-z0-9.-]+$/)).max(50).default([]),roleMapping:z.partialRecord(z.enum(["ADMIN","OPERATOR","AUDITOR","VIEWER"]),z.array(z.string().min(1).max(300)).max(100)).default({}),defaultRole:z.enum(["ADMIN","OPERATOR","AUDITOR","VIEWER"]).default("VIEWER"),jitProvisioning:z.boolean().default(true),enabled:z.boolean().default(true)});
const mfaChallenges=new Map<string,{userId:number;expiresAt:number}>();

function oidcProvider(id:number):OidcProvider|undefined{const row=db.prepare(`SELECT id,name,preset,issuer_url AS issuerUrl,client_id AS clientId,encrypted_client_secret AS encryptedClientSecret,scopes,username_claim AS usernameClaim,groups_claim AS groupsClaim,allowed_domains_json AS allowedDomains,role_mapping_json AS roleMapping,default_role AS defaultRole,jit_provisioning AS jitProvisioning,enabled FROM oidc_providers WHERE id=?`).get(id) as Record<string,unknown>|undefined;if(!row)return;return{...row,allowedDomains:JSON.parse(String(row.allowedDomains)),roleMapping:JSON.parse(String(row.roleMapping)),jitProvisioning:Boolean(row.jitProvisioning),enabled:Boolean(row.enabled)} as OidcProvider}
function requestOrigin(request:import("fastify").FastifyRequest){if(config.publicOrigin)return config.publicOrigin;const proto=String(request.headers["x-forwarded-proto"]??(config.secureCookies?"https":"http")).split(",")[0].trim(),host=String(request.headers["x-forwarded-host"]??request.headers.host).split(",")[0].trim();return `${proto}://${host}`}

function actor(request: import("fastify").FastifyRequest) { return sessionUser(request.cookies.supapulse_session); }
function authenticatedAgent(request:import("fastify").FastifyRequest){const authorization=request.headers.authorization;if(!authorization?.startsWith("Bearer "))return;const token=authorization.slice(7);if(token.length<32||token.length>256)return;return db.prepare("SELECT id,name FROM agents WHERE token_hash=? AND enabled=1 AND revoked_at IS NULL").get(createHash("sha256").update(token).digest("hex")) as {id:number;name:string}|undefined}
function currentUser(request:import("fastify").FastifyRequest){const id=actor(request);if(!id)return null;return db.prepare("SELECT id,username,role,enabled,mfa_enabled AS mfaEnabled,locale,timezone FROM users WHERE id=?").get(id) as {id:number;username:string;role:"ADMIN"|"OPERATOR"|"AUDITOR"|"VIEWER";enabled:number;mfaEnabled:number;locale:string;timezone:string}|undefined}
function requiredMfaRoles(){const value=(db.prepare("SELECT value FROM app_settings WHERE key='mfa_required_roles'").get() as {value?:string}|undefined)?.value??"[]";try{return z.array(z.enum(["ADMIN","OPERATOR","AUDITOR","VIEWER"])).parse(JSON.parse(value))}catch{return []}}
function reportPreferences(request:import("fastify").FastifyRequest){const user=currentUser(request),setting=(key:string,fallback:string)=>(db.prepare("SELECT value FROM app_settings WHERE key=?").get(key) as {value?:string}|undefined)?.value??fallback;return{locale:(user?.locale==="th-TH"?"th-TH":"en-US") as "th-TH"|"en-US",timezone:user?.timezone&&user.timezone!=="SYSTEM"?user.timezone:setting("application_timezone","Asia/Bangkok")}}
function csv(rows: Array<Record<string, unknown>>) {
  if (!rows.length) return "";
  const columns = Object.keys(rows[0]);
  const escape = (value: unknown) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  return `${columns.map(escape).join(",")}\n${rows.map((row) => columns.map((column) => escape(row[column])).join(",")).join("\n")}\n`;
}

function parse<T>(schema: z.ZodType<T>, value: unknown, reply: import("fastify").FastifyReply): T | undefined {
  const result = schema.safeParse(value);
  if (!result.success) {
    reply.code(400).send({ error: "Validation failed", details: z.flattenError(result.error).fieldErrors });
    return undefined;
  }
  return result.data;
}

app.addHook("preHandler",async(request,reply)=>{
  const path=request.url.split("?")[0];
  if(config.maintenanceMode&&["POST","PUT","PATCH","DELETE"].includes(request.method)&&path!=="/api/auth/logout")return reply.header("Retry-After","300").code(503).send({error:"Byakugan is in maintenance/drain mode"});
  if(["POST","PUT","PATCH","DELETE"].includes(request.method)){const origin=request.headers.origin;if(origin){let allowed=false;try{const expected=config.publicOrigin?new URL(config.publicOrigin).host:(request.headers["x-forwarded-host"]??request.headers.host);allowed=new URL(origin).host===expected}catch{allowed=false}if(!allowed)return reply.code(403).send({error:"Cross-origin state change rejected"})}}
  if(!path.startsWith("/api/")||path.startsWith("/api/public/")||path.startsWith("/api/share/"))return;
  if(["/api/session","/api/setup","/api/auth/login","/api/auth/mfa","/api/auth/logout","/api/backup/ingest"].includes(path)||path.startsWith("/api/agent/")||path.startsWith("/api/auth/oidc/"))return;
  const user=currentUser(request);
  if(!user||!user.enabled)return reply.code(401).send({error:"Authentication required"});
  if(requiredMfaRoles().includes(user.role)&&!user.mfaEnabled&&!path.startsWith("/api/mfa/"))return reply.code(403).send({error:"MFA enrollment is required for this role",code:"MFA_ENROLLMENT_REQUIRED"});
  if(request.method==="GET"){if(user.role==="VIEWER"&&(path==="/api/audit/export"||path.startsWith("/api/audit/report.")||path.includes("/download")))return reply.code(403).send({error:"Auditor, Operator, or Administrator role required to export evidence"});return}
  if(path.startsWith("/api/mfa/")||path==="/api/settings/preferences")return;
  if(["AUDITOR","VIEWER"].includes(user.role))return reply.code(403).send({error:`${user.role} role is read-only`});
  if((path.startsWith("/api/users")||path.startsWith("/api/oidc/providers"))&&user.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});
});
app.addHook("onSend",async(request,reply,payload)=>{reply.header("X-Content-Type-Options","nosniff").header("X-Frame-Options","DENY").header("Referrer-Policy","no-referrer").header("Permissions-Policy","camera=(), microphone=(), geolocation=()").header("Cross-Origin-Opener-Policy","same-origin").header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");if(config.secureCookies)reply.header("Strict-Transport-Security","max-age=31536000; includeSubDomains");return payload});

app.get("/health", async (_request,reply) => reply.header("Cache-Control","no-store").send({ status: "ok" }));
app.get("/ready",async(_request,reply)=>{if(config.maintenanceMode)return reply.header("Cache-Control","no-store").header("Retry-After","300").code(503).send({status:"draining"});try{db.prepare("SELECT 1 AS ready FROM audit_events LIMIT 1").get();return reply.header("Cache-Control","no-store").send({status:"ready",database:"available"})}catch(error){app.log.error(error);return reply.header("Cache-Control","no-store").code(503).send({status:"not-ready"})}});
app.get("/api/settings/regional",{preHandler:requireAuth},async(request)=>{const user=currentUser(request);const get=(key:string,fallback:string)=>(db.prepare("SELECT value FROM app_settings WHERE key=?").get(key) as {value?:string}|undefined)?.value??fallback;return{supportedLocales:["th-TH","en-US"],supportedTimezones:Intl.supportedValuesOf("timeZone"),systemLocale:get("system_locale","th-TH"),applicationTimezone:get("application_timezone","Asia/Bangkok"),serverTimezone:Intl.DateTimeFormat().resolvedOptions().timeZone||"UTC",serverNow:new Date().toISOString(),userLocale:user?.locale??"en-US",userTimezone:user?.timezone??"SYSTEM"}});
app.put("/api/settings/preferences",{preHandler:requireAuth},async(request,reply)=>{const body=parse(preferencesSchema,request.body,reply);if(!body)return;const user=currentUser(request);if(!user)return reply.code(401).send({error:"Authentication required"});db.prepare("UPDATE users SET locale=?,timezone=?,updated_at=? WHERE id=?").run(body.locale,body.timezone,new Date().toISOString(),user.id);appendAuditEvent(user.id,"USER_REGIONAL_PREFERENCES_UPDATED","user",user.id,body);return body});
app.put("/api/settings/regional",{preHandler:requireAuth},async(request,reply)=>{const user=currentUser(request);if(user?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});const body=parse(systemRegionalSchema,request.body,reply);if(!body)return;const save=db.prepare("INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP");db.transaction(()=>{save.run("system_locale",body.locale);save.run("application_timezone",body.timezone)})();appendAuditEvent(user.id,"SYSTEM_REGIONAL_SETTINGS_UPDATED","settings","regional",body);return body});
app.get("/api/security/mfa-policy",{preHandler:requireAuth},async()=>({requiredRoles:requiredMfaRoles()}));
app.put("/api/security/mfa-policy",{preHandler:requireAuth},async(request,reply)=>{const user=currentUser(request);if(user?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});const body=parse(mfaPolicySchema,request.body,reply);if(!body)return;const placeholders=body.requiredRoles.map(()=>"?").join(",");const noncompliant=body.requiredRoles.length?db.prepare(`SELECT username FROM users WHERE enabled=1 AND mfa_enabled=0 AND role IN (${placeholders}) ORDER BY username`).all(...body.requiredRoles) as Array<{username:string}>:[];if(noncompliant.length)return reply.code(409).send({error:"Enable MFA for every affected user before enforcing this policy",users:noncompliant.map(row=>row.username)});db.prepare("INSERT INTO app_settings(key,value,updated_at) VALUES('mfa_required_roles',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").run(JSON.stringify(body.requiredRoles));appendAuditEvent(user.id,"MFA_POLICY_UPDATED","settings","mfa_required_roles",body);return body});

app.post("/api/agent/ingest", { config:{rateLimit:{max:120,timeWindow:"1 minute"}} }, async (request,reply) => {
  const authorization=request.headers.authorization;
  if(!authorization?.startsWith("Bearer "))return reply.code(401).send({error:"Agent token required"});
  const token=authorization.slice(7);if(token.length<32||token.length>256)return reply.code(401).send({error:"Invalid agent token"});
  const tokenHash=createHash("sha256").update(token).digest("hex");
  const agent=db.prepare("SELECT id,name FROM agents WHERE token_hash=? AND enabled=1 AND revoked_at IS NULL").get(tokenHash) as {id:number;name:string}|undefined;
  if(!agent)return reply.code(401).send({error:"Invalid or revoked agent token"});
  const body=parse(agentPayloadSchema,request.body,reply);if(!body)return;
  const observed=new Date(body.observedAt);if(observed.getTime()>Date.now()+300000||observed.getTime()<Date.now()-86400000)return reply.code(400).send({error:"Observation timestamp is outside the accepted window"});
  const now=new Date().toISOString();
  db.transaction(()=>{
    db.prepare("UPDATE agents SET hostname=?,agent_version=?,last_seen_at=?,last_ip=? WHERE id=?").run(body.hostname,body.agentVersion,now,request.ip,agent.id);
    db.prepare(`INSERT INTO asset_snapshots(agent_id,hostname,os_name,os_version,kernel,architecture,cpu_model,cpu_count,total_memory_bytes,installed_package_count,pending_update_count,security_update_count,reboot_required,docker_available,container_count,observed_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(agent.id,body.hostname,body.inventory.osName,body.inventory.osVersion??null,body.inventory.kernel??null,body.inventory.architecture,body.inventory.cpuModel,body.inventory.cpuCount,body.inventory.totalMemoryBytes,body.inventory.installedPackageCount,body.inventory.pendingUpdateCount,body.inventory.securityUpdateCount,body.inventory.rebootRequired?1:0,body.inventory.dockerAvailable?1:0,body.metrics.containers.length,body.observedAt);
    db.prepare(`INSERT INTO host_metrics(agent_id,cpu_percent,memory_percent,swap_percent,load_1,load_5,load_15,uptime_seconds,disks_json,containers_json,observed_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(agent.id,body.metrics.cpuPercent,body.metrics.memoryPercent,body.metrics.swapPercent??null,body.metrics.load1??null,body.metrics.load5??null,body.metrics.load15??null,body.metrics.uptimeSeconds,JSON.stringify(body.metrics.disks),JSON.stringify(body.metrics.containers),body.observedAt);
    const findings=[
      {key:"cpu",active:body.metrics.cpuPercent>=90,severity:"CRITICAL",category:"HEALTH",title:"CPU usage is critical",explanation:`CPU is ${body.metrics.cpuPercent}% (threshold 90%)`},
      {key:"memory",active:body.metrics.memoryPercent>=90,severity:"CRITICAL",category:"HEALTH",title:"Memory usage is critical",explanation:`Memory is ${body.metrics.memoryPercent}% (threshold 90%)`},
      {key:"disk",active:body.metrics.disks.some(d=>d.usedPercent>=85),severity:"HIGH",category:"HEALTH",title:"Disk usage exceeds policy",explanation:`One or more disks exceed 85% usage`},
      {key:"security_updates",active:body.inventory.securityUpdateCount>0,severity:"HIGH",category:"PATCH",title:"Security updates are pending",explanation:`${body.inventory.securityUpdateCount} security update(s) pending`},
      {key:"reboot",active:body.inventory.rebootRequired,severity:"MEDIUM",category:"PATCH",title:"Server reboot is required",explanation:"A reboot is required to complete updates"},
      {key:"container",active:body.metrics.containers.some(c=>!c.running),severity:"HIGH",category:"CONTAINER",title:"Container is stopped",explanation:"One or more monitored containers are not running"}
    ];
    for(const finding of findings){
      if(finding.active)db.prepare(`INSERT INTO compliance_findings(agent_id,finding_key,category,severity,status,title,explanation,first_detected_at,last_detected_at)
        VALUES(?,?,?,?, 'OPEN',?,?,?,?) ON CONFLICT(agent_id,finding_key) DO UPDATE SET severity=excluded.severity,status='OPEN',title=excluded.title,explanation=excluded.explanation,last_detected_at=excluded.last_detected_at,resolved_at=NULL`).run(agent.id,finding.key,finding.category,finding.severity,finding.title,finding.explanation,now,now);
      else db.prepare("UPDATE compliance_findings SET status='RESOLVED',resolved_at=?,last_detected_at=? WHERE agent_id=? AND finding_key=? AND status='OPEN'").run(now,now,agent.id,finding.key);
    }
    if(body.vulnerabilityScan){
      const values=body.vulnerabilityScan.vulnerabilities;const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};for(const item of values)counts[item.severity]++;
      db.prepare(`INSERT INTO vulnerability_scans(agent_id,scanner,target,critical_count,high_count,medium_count,low_count,observed_at) VALUES(?,?,?,?,?,?,?,?)`)
        .run(agent.id,"Trivy",body.vulnerabilityScan.target,counts.CRITICAL,counts.HIGH,counts.MEDIUM,counts.LOW,body.observedAt);
      const upsert=db.prepare(`INSERT INTO vulnerability_findings(agent_id,vulnerability_id,package_name,installed_version,fixed_version,severity,title,status,first_detected_at,last_detected_at)
        VALUES(?,?,?,?,?,?,?,'OPEN',?,?) ON CONFLICT(agent_id,vulnerability_id,package_name,installed_version) DO UPDATE SET fixed_version=excluded.fixed_version,severity=excluded.severity,title=excluded.title,last_detected_at=excluded.last_detected_at,resolved_at=NULL,status=CASE WHEN vulnerability_findings.status='RESOLVED' THEN 'OPEN' ELSE vulnerability_findings.status END`);
      for(const item of values)upsert.run(agent.id,item.id,item.packageName,item.installedVersion,item.fixedVersion??null,item.severity,item.title??null,now,now);
      db.prepare(`UPDATE vulnerability_findings SET status='RESOLVED',resolved_at=? WHERE agent_id=? AND status!='RISK_ACCEPTED' AND last_detected_at<?`).run(now,agent.id,now);
    }
  })();
  return {ok:true,receivedAt:now,nextInSeconds:300};
});

app.get("/api/agent/scan-jobs/next",{config:{rateLimit:{max:120,timeWindow:"1 minute"}}},async(request,reply)=>{
  const agent=authenticatedAgent(request);if(!agent)return reply.code(401).send({error:"Invalid or revoked agent token"});const now=new Date().toISOString();
  const job=db.transaction(()=>{const row=db.prepare("SELECT id,target_type AS targetType,target,scanners,severity,timeout_seconds AS timeoutSeconds FROM vulnerability_scan_jobs WHERE agent_id=? AND status='QUEUED' ORDER BY requested_at LIMIT 1").get(agent.id) as {id:number;targetType:string;target:string;scanners:string;severity:string;timeoutSeconds:number}|undefined;if(!row)return null;const claimed=db.prepare("UPDATE vulnerability_scan_jobs SET status='RUNNING',progress=5,started_at=?,heartbeat_at=? WHERE id=? AND status='QUEUED'").run(now,now,row.id);return claimed.changes?row:null})();
  return job?{...job,scanners:job.scanners.split(","),severity:job.severity.split(",")}:{job:null};
});

app.post("/api/agent/scan-jobs/:id/progress",{config:{rateLimit:{max:120,timeWindow:"1 minute"}}},async(request,reply)=>{const agent=authenticatedAgent(request);if(!agent)return reply.code(401).send({error:"Invalid or revoked agent token"});const id=Number((request.params as {id:string}).id),body=parse(z.object({progress:z.number().int().min(5).max(95)}),request.body,reply);if(!body)return;const result=db.prepare("UPDATE vulnerability_scan_jobs SET progress=?,heartbeat_at=? WHERE id=? AND agent_id=? AND status='RUNNING'").run(body.progress,new Date().toISOString(),id,agent.id);if(!result.changes)return reply.code(404).send({error:"Active scan job not found"});return{ok:true}});

app.post("/api/agent/scan-jobs/:id/result",{bodyLimit:5_000_000,config:{rateLimit:{max:30,timeWindow:"1 minute"}}},async(request,reply)=>{
  const agent=authenticatedAgent(request);if(!agent)return reply.code(401).send({error:"Invalid or revoked agent token"});const id=Number((request.params as {id:string}).id),body=parse(scanResultSchema,request.body,reply);if(!body)return;const job=db.prepare("SELECT id,target,status FROM vulnerability_scan_jobs WHERE id=? AND agent_id=?").get(id,agent.id) as {id:number;target:string;status:string}|undefined;if(!job||job.status!=="RUNNING")return reply.code(409).send({error:"Scan job is not running"});
  const now=new Date().toISOString(),counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};for(const item of body.findings)counts[item.severity]++;const newAlerts=body.findings.filter(item=>["CRITICAL","HIGH"].includes(item.severity)&&!db.prepare("SELECT 1 FROM vulnerability_findings WHERE agent_id=? AND vulnerability_id=? AND package_name=? AND installed_version=? AND status!='RESOLVED'").get(agent.id,item.id,item.packageName,item.installedVersion));
  db.transaction(()=>{const scan=db.prepare(`INSERT INTO vulnerability_scans(agent_id,job_id,scanner,scanner_version,target,critical_count,high_count,medium_count,low_count,observed_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(agent.id,id,"Trivy",body.scannerVersion,job.target,counts.CRITICAL,counts.HIGH,counts.MEDIUM,counts.LOW,body.observedAt);const scanId=Number(scan.lastInsertRowid),upsert=db.prepare(`INSERT INTO vulnerability_findings(agent_id,vulnerability_id,package_name,installed_version,fixed_version,severity,title,finding_type,resource_path,primary_url,status,first_detected_at,last_detected_at,last_scan_job_id) VALUES(?,?,?,?,?,?,?,?,?,?,'OPEN',?,?,?) ON CONFLICT(agent_id,vulnerability_id,package_name,installed_version) DO UPDATE SET fixed_version=excluded.fixed_version,severity=excluded.severity,title=excluded.title,finding_type=excluded.finding_type,resource_path=excluded.resource_path,primary_url=excluded.primary_url,last_detected_at=excluded.last_detected_at,last_scan_job_id=excluded.last_scan_job_id,resolved_at=NULL,reopened_count=CASE WHEN vulnerability_findings.status='RESOLVED' THEN vulnerability_findings.reopened_count+1 ELSE vulnerability_findings.reopened_count END,status=CASE WHEN vulnerability_findings.status='RESOLVED' THEN 'OPEN' ELSE vulnerability_findings.status END`);for(const item of body.findings)upsert.run(agent.id,item.id,item.packageName,item.installedVersion,item.fixedVersion??null,item.severity,item.title??null,item.type,item.resourcePath??null,item.primaryUrl??null,now,now,id);db.prepare(`UPDATE vulnerability_findings SET status='RESOLVED',resolved_at=? WHERE agent_id=? AND status NOT IN ('RISK_ACCEPTED','RESOLVED') AND last_scan_job_id!=?`).run(now,agent.id,id);db.prepare("UPDATE vulnerability_scan_jobs SET status='COMPLETED',progress=100,completed_at=?,heartbeat_at=?,result_summary_json=? WHERE id=?").run(now,now,JSON.stringify({...counts,total:body.findings.length,scanId,...body.summary}),id)})();
  appendAuditEvent(null,"VULNERABILITY_SCAN_COMPLETED","scan_job",id,{agentId:agent.id,target:job.target,total:body.findings.length,newHighRisk:newAlerts.length,...counts,scannerVersion:body.scannerVersion});if(newAlerts.length){const preview=newAlerts.slice(0,10).map(item=>`• ${item.severity} ${item.id} · ${item.packageName}`).join("\n");void dispatchSecurityNotification("VULNERABILITY_NEW",`🔐 Byakugan found ${newAlerts.length} new high-risk security finding(s)\nAgent: ${agent.name}\nTarget: ${job.target}\n${preview}${newAlerts.length>10?`\n…and ${newAlerts.length-10} more`:""}\nUTC: ${now}`).catch(error=>app.log.error(error))}return{ok:true,receivedAt:now};
});

app.post("/api/agent/scan-jobs/:id/failure",{config:{rateLimit:{max:30,timeWindow:"1 minute"}}},async(request,reply)=>{const agent=authenticatedAgent(request);if(!agent)return reply.code(401).send({error:"Invalid or revoked agent token"});const id=Number((request.params as {id:string}).id),body=parse(z.object({code:z.string().max(100),message:z.string().max(1000)}),request.body,reply);if(!body)return;const now=new Date().toISOString(),result=db.prepare("UPDATE vulnerability_scan_jobs SET status='FAILED',completed_at=?,heartbeat_at=?,error_code=?,error_message=? WHERE id=? AND agent_id=? AND status='RUNNING'").run(now,now,body.code,body.message,id,agent.id);if(!result.changes)return reply.code(404).send({error:"Active scan job not found"});appendAuditEvent(null,"VULNERABILITY_SCAN_FAILED","scan_job",id,{agentId:agent.id,code:body.code});void dispatchSecurityNotification("SCAN_FAILED",`⚠️ Byakugan security scan failed\nAgent: ${agent.name}\nJob: #${id}\nCode: ${body.code}\n${body.message}\nUTC: ${now}`).catch(error=>app.log.error(error));return{ok:true}});

app.get("/api/vulnerability-scan-jobs",{preHandler:requireAuth},async()=>db.prepare(`SELECT j.id,j.agent_id AS agentId,a.name AS agentName,a.hostname,j.profile_id AS profileId,j.schedule_id AS scheduleId,j.target_type AS targetType,j.target,j.scanners,j.severity,j.timeout_seconds AS timeoutSeconds,j.status,j.progress,j.requested_at AS requestedAt,j.started_at AS startedAt,j.completed_at AS completedAt,j.error_code AS errorCode,j.error_message AS errorMessage,j.result_summary_json AS resultSummary FROM vulnerability_scan_jobs j JOIN agents a ON a.id=j.agent_id ORDER BY j.requested_at DESC LIMIT 200`).all().map(row=>({...row as Record<string,unknown>,scanners:String((row as {scanners:string}).scanners).split(","),resultSummary:(row as {resultSummary:string|null}).resultSummary?JSON.parse((row as {resultSummary:string}).resultSummary):null})));
app.post("/api/vulnerability-scan-jobs",{preHandler:requireAuth},async(request,reply)=>{const body=parse(scanJobSchema,request.body,reply);if(!body)return;if(!db.prepare("SELECT 1 FROM agents WHERE id=? AND enabled=1").get(body.agentId))return reply.code(404).send({error:"Active agent not found"});const profile=body.profileId?db.prepare("SELECT id,target_type AS targetType,scanners,severity,timeout_seconds AS timeoutSeconds FROM vulnerability_scan_profiles WHERE id=? AND enabled=1").get(body.profileId) as {id:number;targetType:string;scanners:string;severity:string;timeoutSeconds:number}|undefined:undefined;if(body.profileId&&!profile)return reply.code(404).send({error:"Scan profile not found"});const targetType=profile?.targetType??body.targetType,scanners=profile?.scanners??body.scanners.join(","),severity=profile?.severity??body.severity.join(","),timeout=profile?.timeoutSeconds??900;const duplicate=db.prepare("SELECT id FROM vulnerability_scan_jobs WHERE agent_id=? AND target_type=? AND target=? AND status IN ('QUEUED','RUNNING')").get(body.agentId,targetType,body.target) as {id:number}|undefined;if(duplicate)return reply.code(409).send({error:"An active scan already exists for this agent and target",jobId:duplicate.id});const result=db.prepare("INSERT INTO vulnerability_scan_jobs(agent_id,profile_id,target_type,target,scanners,severity,timeout_seconds,requested_by) VALUES(?,?,?,?,?,?,?,?)").run(body.agentId,profile?.id??null,targetType,body.target,scanners,severity,timeout,actor(request)),id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"VULNERABILITY_SCAN_QUEUED","scan_job",id,{agentId:body.agentId,profileId:profile?.id,targetType,target:body.target,scanners:scanners.split(",")});return reply.code(201).send({id,status:"QUEUED"})});
app.post("/api/vulnerability-scan-jobs/:id/cancel",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),now=new Date().toISOString(),result=db.prepare("UPDATE vulnerability_scan_jobs SET status='CANCELLED',completed_at=? WHERE id=? AND status IN ('QUEUED','RUNNING')").run(now,id);if(!result.changes)return reply.code(409).send({error:"Scan job cannot be cancelled"});appendAuditEvent(actor(request),"VULNERABILITY_SCAN_CANCELLED","scan_job",id);return{ok:true}});
app.get("/api/vulnerability-scan-profiles",{preHandler:requireAuth},async()=>db.prepare("SELECT id,name,description,target_type AS targetType,scanners,severity,timeout_seconds AS timeoutSeconds,system_profile AS systemProfile,enabled FROM vulnerability_scan_profiles WHERE enabled=1 ORDER BY system_profile DESC,name").all().map(row=>({...row as Record<string,unknown>,scanners:String((row as {scanners:string}).scanners).split(","),severity:String((row as {severity:string}).severity).split(","),systemProfile:Boolean((row as {systemProfile:number}).systemProfile),enabled:Boolean((row as {enabled:number}).enabled)})));
app.post("/api/vulnerability-scan-profiles",{preHandler:requireAuth},async(request,reply)=>{const body=parse(scanProfileSchema,request.body,reply);if(!body)return;try{const result=db.prepare("INSERT INTO vulnerability_scan_profiles(name,description,target_type,scanners,severity,timeout_seconds) VALUES(?,?,?,?,?,?)").run(body.name,body.description??null,body.targetType,body.scanners.join(","),body.severity.join(","),body.timeoutSeconds),id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"VULNERABILITY_SCAN_PROFILE_CREATED","scan_profile",id,{name:body.name,targetType:body.targetType,scanners:body.scanners});return reply.code(201).send({id})}catch{return reply.code(409).send({error:"A scan profile with this name already exists"})}});
app.delete("/api/vulnerability-scan-profiles/:id",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),profile=db.prepare("SELECT id,name,system_profile AS systemProfile FROM vulnerability_scan_profiles WHERE id=? AND enabled=1").get(id) as {id:number;name:string;systemProfile:number}|undefined;if(!profile)return reply.code(404).send({error:"Active scan profile not found"});if(profile.systemProfile)return reply.code(409).send({error:"Built-in scan profiles cannot be disabled"});const schedule=db.prepare("SELECT id,name FROM vulnerability_scan_schedules WHERE profile_id=? AND enabled=1 LIMIT 1").get(id) as {id:number;name:string}|undefined;if(schedule)return reply.code(409).send({error:`Disable scheduled scan ${schedule.name} before disabling this profile`});db.prepare("UPDATE vulnerability_scan_profiles SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(id);appendAuditEvent(actor(request),"VULNERABILITY_SCAN_PROFILE_DISABLED","scan_profile",id,{name:profile.name});return reply.code(204).send()});
app.get("/api/vulnerability-scan-schedules",{preHandler:requireAuth},async()=>db.prepare(`SELECT s.id,s.name,s.agent_id AS agentId,a.name AS agentName,a.hostname,s.profile_id AS profileId,p.name AS profileName,s.target,s.frequency,s.enabled,s.next_run_at AS nextRunAt,s.last_run_at AS lastRunAt,s.last_job_id AS lastJobId FROM vulnerability_scan_schedules s JOIN agents a ON a.id=s.agent_id JOIN vulnerability_scan_profiles p ON p.id=s.profile_id ORDER BY s.enabled DESC,s.next_run_at`).all().map(row=>({...row as Record<string,unknown>,enabled:Boolean((row as {enabled:number}).enabled)})));
app.post("/api/vulnerability-scan-schedules",{preHandler:requireAuth},async(request,reply)=>{const body=parse(scanScheduleSchema,request.body,reply);if(!body)return;if(!db.prepare("SELECT 1 FROM agents WHERE id=? AND enabled=1").get(body.agentId))return reply.code(404).send({error:"Active agent not found"});if(!db.prepare("SELECT 1 FROM vulnerability_scan_profiles WHERE id=? AND enabled=1").get(body.profileId))return reply.code(404).send({error:"Scan profile not found"});const next=body.firstRunAt??new Date(Date.now()+300000).toISOString(),result=db.prepare("INSERT INTO vulnerability_scan_schedules(name,agent_id,profile_id,target,frequency,next_run_at,created_by) VALUES(?,?,?,?,?,?,?)").run(body.name,body.agentId,body.profileId,body.target,body.frequency,next,actor(request)),id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"VULNERABILITY_SCAN_SCHEDULE_CREATED","scan_schedule",id,{name:body.name,agentId:body.agentId,profileId:body.profileId,target:body.target,frequency:body.frequency,nextRunAt:next});return reply.code(201).send({id,nextRunAt:next})});
app.delete("/api/vulnerability-scan-schedules/:id",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),result=db.prepare("UPDATE vulnerability_scan_schedules SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1").run(id);if(!result.changes)return reply.code(404).send({error:"Active scan schedule not found"});appendAuditEvent(actor(request),"VULNERABILITY_SCAN_SCHEDULE_DISABLED","scan_schedule",id);return reply.code(204).send()});

app.get("/api/agents",{preHandler:requireAuth},async()=>db.prepare(`SELECT a.id,a.name,a.hostname,a.agent_version AS agentVersion,a.last_seen_at AS lastSeenAt,a.enabled,a.created_at AS createdAt,
  s.os_name AS osName,s.os_version AS osVersion,s.kernel,s.pending_update_count AS pendingUpdates,s.security_update_count AS securityUpdates,s.reboot_required AS rebootRequired,
  m.cpu_percent AS cpuPercent,m.memory_percent AS memoryPercent,m.uptime_seconds AS uptimeSeconds,m.disks_json AS disksJson,m.containers_json AS containersJson
  FROM agents a LEFT JOIN asset_snapshots s ON s.id=(SELECT id FROM asset_snapshots WHERE agent_id=a.id ORDER BY observed_at DESC LIMIT 1)
  LEFT JOIN host_metrics m ON m.id=(SELECT id FROM host_metrics WHERE agent_id=a.id ORDER BY observed_at DESC LIMIT 1) ORDER BY a.name`).all().map(row=>({...(row as Record<string,unknown>),enabled:Boolean((row as {enabled:number}).enabled),rebootRequired:Boolean((row as {rebootRequired:number}).rebootRequired)})));

app.post("/api/agents",{preHandler:requireAuth},async(request,reply)=>{
  const body=parse(z.object({name:z.string().trim().min(1).max(100)}),request.body,reply);if(!body)return;
  const token=randomBytes(32).toString("base64url");const hash=createHash("sha256").update(token).digest("hex");
  const result=db.prepare("INSERT INTO agents(name,token_hash) VALUES(?,?)").run(body.name,hash);const id=Number(result.lastInsertRowid);
  appendAuditEvent(actor(request),"AGENT_ENROLLED","agent",id,{name:body.name});return reply.code(201).send({id,name:body.name,token});
});

app.delete("/api/agents/:id",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id);const now=new Date().toISOString();const result=db.prepare("UPDATE agents SET enabled=0,revoked_at=? WHERE id=?").run(now,id);if(!result.changes)return reply.code(404).send({error:"Agent not found"});appendAuditEvent(actor(request),"AGENT_REVOKED","agent",id);return reply.code(204).send();});

app.get("/api/action-required",{preHandler:requireAuth},async()=>db.prepare(`SELECT f.id,f.category,f.severity,f.status,f.title,f.explanation,f.owner,f.due_at AS dueAt,f.resolution_note AS resolutionNote,f.first_detected_at AS firstDetectedAt,f.last_detected_at AS lastDetectedAt,a.name AS agentName,a.hostname
  FROM compliance_findings f LEFT JOIN agents a ON a.id=f.agent_id WHERE f.status IN ('OPEN','ACKNOWLEDGED') ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,f.first_detected_at`).all());

app.put("/api/findings/:id",{preHandler:requireAuth},async(request,reply)=>{
  const id=Number((request.params as {id:string}).id);const body=parse(findingWorkflowSchema,request.body,reply);if(!body)return;
  const current=db.prepare("SELECT id,status FROM compliance_findings WHERE id=?").get(id) as {id:number;status:string}|undefined;
  if(!current)return reply.code(404).send({error:"Finding not found"});const now=new Date().toISOString();
  db.prepare(`UPDATE compliance_findings SET status=?,owner=?,due_at=?,resolution_note=?,resolved_at=?,updated_at=? WHERE id=?`)
    .run(body.status,body.owner??null,body.dueAt??null,body.resolutionNote??null,body.status==="RESOLVED"?now:null,now,id);
  appendAuditEvent(actor(request),"FINDING_WORKFLOW_UPDATED","compliance_finding",id,{previousStatus:current.status,...body});return {ok:true};
});

app.get("/api/backup-evidence",{preHandler:requireAuth},async()=>db.prepare(`SELECT b.id,b.asset_name AS assetName,b.backup_type AS backupType,b.storage_location AS storageLocation,b.status,b.started_at AS startedAt,
  b.completed_at AS completedAt,b.size_bytes AS sizeBytes,b.checksum,b.notes,u.username AS recordedBy,b.created_at AS createdAt
  FROM backup_evidence b LEFT JOIN users u ON u.id=b.recorded_by ORDER BY b.started_at DESC LIMIT 500`).all());
app.post("/api/backup-evidence",{preHandler:requireAuth},async(request,reply)=>{
  const body=parse(backupEvidenceSchema,request.body,reply);if(!body)return;
  const result=db.prepare(`INSERT INTO backup_evidence(asset_name,backup_type,storage_location,status,started_at,completed_at,size_bytes,checksum,notes,recorded_by)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).run(body.assetName,body.backupType,body.storageLocation,body.status,body.startedAt,body.completedAt??null,body.sizeBytes??null,body.checksum??null,body.notes??null,actor(request));
  const id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"BACKUP_EVIDENCE_RECORDED","backup_evidence",id,{assetName:body.assetName,status:body.status,startedAt:body.startedAt});return reply.code(201).send({id});
});
app.get("/api/backup-connectors",{preHandler:requireAuth},async()=>db.prepare(`SELECT c.id,c.name,c.asset_name AS assetName,c.backup_type AS backupType,c.max_age_hours AS maxAgeHours,c.enabled,c.last_received_at AS lastReceivedAt,c.created_at AS createdAt,
  f.status AS findingStatus,f.explanation AS findingExplanation FROM backup_connectors c LEFT JOIN backup_policy_findings f ON f.connector_id=c.id AND f.status='OPEN' ORDER BY c.name`).all().map(row=>({...row as Record<string,unknown>,enabled:Boolean((row as {enabled:number}).enabled)})));
app.post("/api/backup-connectors",{preHandler:requireAuth},async(request,reply)=>{const body=parse(backupConnectorSchema,request.body,reply);if(!body)return;const token=randomBytes(32).toString("base64url"),hash=createHash("sha256").update(token).digest("hex");const result=db.prepare(`INSERT INTO backup_connectors(name,token_hash,asset_name,backup_type,max_age_hours) VALUES(?,?,?,?,?)`).run(body.name,hash,body.assetName,body.backupType,body.maxAgeHours);const id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"BACKUP_CONNECTOR_CREATED","backup_connector",id,{name:body.name,assetName:body.assetName,maxAgeHours:body.maxAgeHours});return reply.code(201).send({id,token})});
app.delete("/api/backup-connectors/:id",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),now=new Date().toISOString();const result=db.prepare("UPDATE backup_connectors SET enabled=0,revoked_at=? WHERE id=?").run(now,id);if(!result.changes)return reply.code(404).send({error:"Connector not found"});appendAuditEvent(actor(request),"BACKUP_CONNECTOR_REVOKED","backup_connector",id);return reply.code(204).send()});
app.post("/api/backup/ingest",{config:{rateLimit:{max:120,timeWindow:"1 minute"}}},async(request,reply)=>{const authorization=request.headers.authorization;if(!authorization?.startsWith("Bearer "))return reply.code(401).send({error:"Connector token required"});const token=authorization.slice(7);if(token.length<32||token.length>256)return reply.code(401).send({error:"Invalid connector token"});const hash=createHash("sha256").update(token).digest("hex");const connector=db.prepare("SELECT id,name,asset_name AS assetName,backup_type AS backupType FROM backup_connectors WHERE token_hash=? AND enabled=1 AND revoked_at IS NULL").get(hash) as {id:number;name:string;assetName:string;backupType:string}|undefined;if(!connector)return reply.code(401).send({error:"Invalid or revoked connector token"});const body=parse(backupIngestSchema,request.body,reply);if(!body)return;const now=new Date().toISOString();const result=db.transaction(()=>{const inserted=db.prepare(`INSERT INTO backup_evidence(connector_id,asset_name,backup_type,storage_location,status,started_at,completed_at,size_bytes,checksum,notes) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(connector.id,connector.assetName,connector.backupType,body.storageLocation,body.status,body.startedAt,body.completedAt??null,body.sizeBytes??null,body.checksum??null,body.notes??null);db.prepare("UPDATE backup_connectors SET last_received_at=? WHERE id=?").run(now,connector.id);if(body.status==="SUCCESS")db.prepare("UPDATE backup_policy_findings SET status='RESOLVED',resolved_at=?,last_detected_at=? WHERE connector_id=? AND status='OPEN'").run(now,now,connector.id);else db.prepare(`INSERT INTO backup_policy_findings(connector_id,severity,status,title,explanation,first_detected_at,last_detected_at) VALUES(?,'HIGH','OPEN','Backup job failed',?,?,?) ON CONFLICT(connector_id) DO UPDATE SET status='OPEN',title='Backup job failed',explanation=excluded.explanation,last_detected_at=excluded.last_detected_at,resolved_at=NULL`).run(connector.id,`${connector.name} reported ${body.status}`,now,now);return Number(inserted.lastInsertRowid)})();appendAuditEvent(null,"BACKUP_EVIDENCE_INGESTED","backup_connector",connector.id,{evidenceId:result,status:body.status,startedAt:body.startedAt});return {ok:true,evidenceId:result,receivedAt:now}});
app.get("/api/restore-tests",{preHandler:requireAuth},async()=>db.prepare(`SELECT r.id,r.backup_evidence_id AS backupEvidenceId,r.asset_name AS assetName,r.test_scope AS testScope,r.result,r.tested_at AS testedAt,
  r.rto_minutes AS rtoMinutes,r.actual_minutes AS actualMinutes,r.evidence_note AS evidenceNote,u.username AS testedBy,r.created_at AS createdAt
  FROM restore_tests r LEFT JOIN users u ON u.id=r.tested_by ORDER BY r.tested_at DESC LIMIT 500`).all());
app.post("/api/restore-tests",{preHandler:requireAuth},async(request,reply)=>{
  const body=parse(restoreTestSchema,request.body,reply);if(!body)return;
  if(body.backupEvidenceId&&!db.prepare("SELECT 1 FROM backup_evidence WHERE id=?").get(body.backupEvidenceId))return reply.code(400).send({error:"Backup evidence not found"});
  const result=db.prepare(`INSERT INTO restore_tests(backup_evidence_id,asset_name,test_scope,result,tested_at,rto_minutes,actual_minutes,evidence_note,tested_by)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(body.backupEvidenceId??null,body.assetName,body.testScope,body.result,body.testedAt,body.rtoMinutes??null,body.actualMinutes??null,body.evidenceNote??null,actor(request));
  const id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"RESTORE_TEST_RECORDED","restore_test",id,{assetName:body.assetName,result:body.result,testedAt:body.testedAt});return reply.code(201).send({id});
});
app.get("/api/vulnerabilities",{preHandler:requireAuth},async(request)=>{
  const query=request.query as {status?:string};const status=query.status??"active";
  const where=status==="all"?"1=1":status==="resolved"?"v.status='RESOLVED'":"v.status!='RESOLVED'";
  return db.prepare(`SELECT v.id,v.vulnerability_id AS vulnerabilityId,v.package_name AS packageName,v.installed_version AS installedVersion,v.fixed_version AS fixedVersion,
    v.kev,v.kev_date_added AS kevDateAdded,v.kev_due_date AS kevDueDate,v.kev_ransomware AS kevRansomware,v.kev_required_action AS kevRequiredAction,v.epss_score AS epssScore,v.epss_percentile AS epssPercentile,v.threat_intel_updated_at AS threatIntelUpdatedAt,
    v.severity,v.title,v.status,v.owner,v.due_at AS dueAt,v.risk_reason AS riskReason,v.risk_expires_at AS riskExpiresAt,v.first_detected_at AS firstDetectedAt,
    v.last_detected_at AS lastDetectedAt,v.resolved_at AS resolvedAt,a.name AS agentName,a.hostname FROM vulnerability_findings v JOIN agents a ON a.id=v.agent_id
    WHERE ${where} ORDER BY v.kev DESC,COALESCE(v.epss_score,0) DESC,CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,v.last_detected_at DESC LIMIT 2000`).all().map((row:any)=>({...row,kev:Boolean(row.kev)}));
});
app.get("/api/threat-intelligence/status",{preHandler:requireAuth},async()=>threatIntelligenceStatus());
app.post("/api/threat-intelligence/sync",{preHandler:requireAuth},async(request,reply)=>{const user=currentUser(request);if(!user||!["ADMIN","OPERATOR"].includes(user.role))return reply.code(403).send({error:"Operator role required"});try{return await syncThreatIntelligence(user.id)}catch(error){return reply.code(502).send({error:error instanceof Error?error.message:"Threat intelligence sync failed"})}});
app.get("/api/vulnerability-scans",{preHandler:requireAuth},async()=>db.prepare(`SELECT s.id,a.name AS agentName,a.hostname,s.scanner,s.target,s.critical_count AS criticalCount,s.high_count AS highCount,s.medium_count AS mediumCount,s.low_count AS lowCount,s.observed_at AS observedAt
  FROM vulnerability_scans s JOIN agents a ON a.id=s.agent_id ORDER BY s.observed_at DESC LIMIT 100`).all());
app.put("/api/vulnerabilities/:id",{preHandler:requireAuth},async(request,reply)=>{
  const id=Number((request.params as {id:string}).id);const body=parse(vulnerabilityWorkflowSchema,request.body,reply);if(!body)return;
  const current=db.prepare("SELECT id,status,vulnerability_id AS vulnerabilityId FROM vulnerability_findings WHERE id=?").get(id) as {id:number;status:string;vulnerabilityId:string}|undefined;
  if(!current)return reply.code(404).send({error:"Vulnerability not found"});const now=new Date().toISOString();
  db.prepare(`UPDATE vulnerability_findings SET status=?,owner=?,due_at=?,risk_reason=?,risk_expires_at=?,resolved_at=? WHERE id=?`)
    .run(body.status,body.owner??null,body.dueAt??null,body.riskReason??null,body.riskExpiresAt??null,body.status==="RESOLVED"?now:null,id);
  appendAuditEvent(actor(request),"VULNERABILITY_WORKFLOW_UPDATED","vulnerability",id,{vulnerabilityId:current.vulnerabilityId,previousStatus:current.status,...body});return {ok:true};
});

app.get("/api/public/status", async () => {
  const title = (db.prepare("SELECT value FROM app_settings WHERE key = 'status_title'").get() as { value?: string } | undefined)?.value || "Byakugan Status";
  const rows = db.prepare(`SELECT p.*,
    (SELECT COUNT(*) FROM heartbeats h WHERE h.project_id = p.id AND h.checked_at >= datetime('now', '-24 hours')) AS checks24h,
    (SELECT COUNT(*) FROM heartbeats h WHERE h.project_id = p.id AND h.status = 'UP' AND h.checked_at >= datetime('now', '-24 hours')) AS up24h
    FROM projects p WHERE p.published = 1 ORDER BY p.name`).all() as Array<ProjectRow & { checks24h: number; up24h: number }>;
  const monitors = rows.map((row) => ({ ...publicProject(row), uptime24h: row.checks24h ? Math.round(row.up24h / row.checks24h * 10000) / 100 : null }));
  const operational = monitors.every((item) => ["UP", "PENDING", "MAINTENANCE"].includes(item.lastStatus));
  return { title, operational, updatedAt: new Date().toISOString(), monitors };
});

app.get("/api/share/:token", async (request, reply) => {
  const token = (request.params as { token: string }).token;
  if (!/^[a-zA-Z0-9_-]{32,64}$/.test(token)) return reply.code(404).send({ error: "Shared dashboard not found" });
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const dashboard = db.prepare("SELECT id, name, updated_at AS updatedAt FROM shared_dashboards WHERE token_hash = ? AND enabled = 1").get(tokenHash) as { id: number; name: string; updatedAt: string } | undefined;
  if (!dashboard) return reply.code(404).send({ error: "Shared dashboard not found" });
  const rows = db.prepare(`SELECT p.id, p.name, p.monitor_type AS monitorType, p.last_status AS lastStatus,
    p.last_checked_at AS lastCheckedAt, p.interval_seconds AS intervalSeconds,
    sp.group_name AS groupName, sp.sort_order AS sortOrder
    FROM shared_dashboard_projects sp JOIN projects p ON p.id = sp.project_id
    WHERE sp.dashboard_id = ? ORDER BY sp.group_name, sp.sort_order, p.name`).all(dashboard.id) as Array<{
      id: number; name: string; monitorType: string; lastStatus: string; lastCheckedAt: string | null; intervalSeconds: number; groupName: string; sortOrder: number;
    }>;
  const cutoff24h = new Date(Date.now() - 86400000).toISOString();
  const heartbeatQuery = db.prepare(`SELECT status, response_time_ms AS responseTimeMs, checked_at AS checkedAt
    FROM heartbeats WHERE project_id = ? ORDER BY checked_at DESC LIMIT 100`);
  const uptimeQuery = db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'UP' THEN 1 ELSE 0 END) AS up,
    AVG(CASE WHEN status = 'UP' THEN response_time_ms END) AS averageResponseMs
    FROM heartbeats WHERE project_id = ? AND checked_at >= ?`);
  const groups = new Map<string, unknown[]>();
  for (const row of rows) {
    const beats = heartbeatQuery.all(row.id).reverse() as Array<{ status: string; responseTimeMs: number; checkedAt: string }>;
    const stats = uptimeQuery.get(row.id, cutoff24h) as { total: number; up: number | null; averageResponseMs: number | null };
    const monitor = { id: row.id, name: row.name, monitorType: row.monitorType, lastStatus: row.lastStatus,
      lastCheckedAt: row.lastCheckedAt, intervalSeconds: row.intervalSeconds,
      uptime24h: stats.total ? Math.round(((stats.up ?? 0) / stats.total) * 10000) / 100 : null,
      averageResponseMs: stats.averageResponseMs === null ? null : Math.round(stats.averageResponseMs * 100) / 100,
      heartbeats: beats };
    if (!groups.has(row.groupName)) groups.set(row.groupName, []);
    groups.get(row.groupName)?.push(monitor);
  }
  return { name: dashboard.name, updatedAt: new Date().toISOString(), groups: [...groups].map(([name, monitors]) => ({ name, monitors })) };
});

app.get("/api/auth/oidc/providers",async()=>db.prepare("SELECT id,name,preset FROM oidc_providers WHERE enabled=1 ORDER BY name").all());
app.get("/api/auth/oidc/:id/start",{config:{rateLimit:{max:20,timeWindow:"5 minutes"}}},async(request,reply)=>{const provider=oidcProvider(Number((request.params as {id:string}).id));if(!provider?.enabled)return reply.code(404).send({error:"SSO provider not found"});try{const redirectUri=`${requestOrigin(request)}/api/auth/oidc/${provider.id}/callback`;return reply.redirect((await authorizationUrl(provider,decrypt(provider.encryptedClientSecret),redirectUri)).href)}catch(error){request.log.error(error);return reply.redirect(`/?sso_error=${encodeURIComponent("Unable to contact identity provider")}`)}});
app.get("/api/auth/oidc/:id/callback",{config:{rateLimit:{max:30,timeWindow:"5 minutes"}}},async(request,reply)=>{const provider=oidcProvider(Number((request.params as {id:string}).id));const query=request.query as Record<string,string|undefined>,pending=query.state?consumeState(query.state):null;if(!provider?.enabled||!pending||pending.providerId!==provider.id)return reply.redirect(`/?sso_error=${encodeURIComponent("SSO request expired or was not initiated here")}`);try{const configuration=await oidcConfiguration(provider,decrypt(provider.encryptedClientSecret));const current=new URL(request.raw.url??"",requestOrigin(request));const tokens=await oidcClient.authorizationCodeGrant(configuration,current,{pkceCodeVerifier:pending.verifier,expectedState:query.state,expectedNonce:pending.nonce,idTokenExpected:true});const claims=tokens.claims();if(!claims?.sub)throw new Error("Identity token has no subject");const usernameValue=claims[provider.usernameClaim],username=typeof usernameValue==="string"?usernameValue.trim():"";if(!username||!allowedEmail(username,provider.allowedDomains))return reply.redirect(`/?sso_error=${encodeURIComponent("This identity is not allowed")}`);let user=db.prepare("SELECT id,enabled FROM users WHERE oidc_provider_id=? AND external_subject=?").get(provider.id,claims.sub) as {id:number;enabled:number}|undefined;if(!user){if(!provider.jitProvisioning)return reply.redirect(`/?sso_error=${encodeURIComponent("Account is not provisioned")}`);const role=chooseRole(claims[provider.groupsClaim],provider.roleMapping,provider.defaultRole);let unique=username;for(let n=1;db.prepare("SELECT 1 FROM users WHERE username=?").get(unique);n++)unique=`${username}#${n}`;const unusable=await argon2.hash(randomBytes(48),{type:argon2.argon2id});const result=db.prepare("INSERT INTO users(username,password_hash,role,auth_source,oidc_provider_id,external_subject,updated_at) VALUES(?,?,?,?,?,?,?)").run(unique,unusable,role,"OIDC",provider.id,claims.sub,new Date().toISOString());user={id:Number(result.lastInsertRowid),enabled:1};appendAuditEvent(user.id,"OIDC_USER_PROVISIONED","user",user.id,{providerId:provider.id,role})}if(!user.enabled)return reply.redirect(`/?sso_error=${encodeURIComponent("Account is disabled")}`);const now=new Date().toISOString();db.prepare("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?").run(now,now,user.id);setSessionCookie(reply,createSession(user.id));appendAuditEvent(user.id,"USER_LOGIN_OIDC","user",user.id,{providerId:provider.id});return reply.redirect("/")}catch(error){request.log.error(error);return reply.redirect(`/?sso_error=${encodeURIComponent("Identity provider rejected the sign-in")}`)}});

app.get("/api/oidc/providers",{preHandler:requireAuth},async(request,reply)=>{if(currentUser(request)?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});return db.prepare(`SELECT id,name,preset,issuer_url AS issuerUrl,client_id AS clientId,scopes,username_claim AS usernameClaim,groups_claim AS groupsClaim,allowed_domains_json AS allowedDomains,role_mapping_json AS roleMapping,default_role AS defaultRole,jit_provisioning AS jitProvisioning,enabled,created_at AS createdAt,updated_at AS updatedAt FROM oidc_providers ORDER BY name`).all().map((row:any)=>({...row,allowedDomains:JSON.parse(row.allowedDomains),roleMapping:JSON.parse(row.roleMapping),jitProvisioning:Boolean(row.jitProvisioning),enabled:Boolean(row.enabled),clientSecretConfigured:true}))});
app.post("/api/oidc/providers",{preHandler:requireAuth},async(request,reply)=>{const admin=currentUser(request);if(admin?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});const body=parse(oidcProviderSchema,request.body,reply);if(!body)return;try{const candidate={id:0,...body,encryptedClientSecret:""} as OidcProvider;await oidcConfiguration(candidate,body.clientSecret)}catch{return reply.code(400).send({error:"OIDC discovery failed. Verify the issuer URL, client ID, and network access."})}const result=db.prepare(`INSERT INTO oidc_providers(name,preset,issuer_url,client_id,encrypted_client_secret,scopes,username_claim,groups_claim,allowed_domains_json,role_mapping_json,default_role,jit_provisioning,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(body.name,body.preset,body.issuerUrl.replace(/\/$/,""),body.clientId,encrypt(body.clientSecret),body.scopes,body.usernameClaim,body.groupsClaim,JSON.stringify(body.allowedDomains),JSON.stringify(body.roleMapping),body.defaultRole,Number(body.jitProvisioning),Number(body.enabled));const id=Number(result.lastInsertRowid);appendAuditEvent(admin.id,"OIDC_PROVIDER_CREATED","oidc_provider",id,{name:body.name,preset:body.preset,issuerUrl:body.issuerUrl,defaultRole:body.defaultRole});return reply.code(201).send({id,callbackUrl:`${requestOrigin(request)}/api/auth/oidc/${id}/callback`})});
app.delete("/api/oidc/providers/:id",{preHandler:requireAuth},async(request,reply)=>{const admin=currentUser(request);if(admin?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});const id=Number((request.params as {id:string}).id),result=db.prepare("UPDATE oidc_providers SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(id);if(!result.changes)return reply.code(404).send({error:"SSO provider not found"});appendAuditEvent(admin.id,"OIDC_PROVIDER_DISABLED","oidc_provider",id);return reply.code(204).send()});

app.get("/api/session", async (request) => {
  const configured = Boolean(db.prepare("SELECT 1 FROM users LIMIT 1").get());
  const user=currentUser(request);return { configured, authenticated:Boolean(user?.enabled),user:user?.enabled?{id:user.id,username:user.username,role:user.role,mfaEnabled:Boolean(user.mfaEnabled),mfaRequired:requiredMfaRoles().includes(user.role),locale:user.locale,timezone:user.timezone}:null };
});

app.post("/api/setup", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (request, reply) => {
  if (db.prepare("SELECT 1 FROM users LIMIT 1").get()) return reply.code(409).send({ error: "Setup is already complete" });
  const body = parse(credentialsSchema, request.body, reply);
  if (!body) return;
  const hash = await argon2.hash(body.password, { type: argon2.argon2id });
  const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(body.username, hash);
  setSessionCookie(reply, createSession(Number(result.lastInsertRowid)));
  return { ok: true };
});

app.post("/api/auth/login", { config: { rateLimit: { max: 8, timeWindow: "5 minutes" } } }, async (request, reply) => {
  const body = parse(credentialsSchema, request.body, reply);
  if (!body) return;
  const user = db.prepare("SELECT id,password_hash,enabled,mfa_enabled AS mfaEnabled FROM users WHERE username = ?").get(body.username) as
    { id: number; password_hash: string;enabled:number;mfaEnabled:number } | undefined;
  if (!user?.enabled || !(await argon2.verify(user.password_hash, body.password))) {
    return reply.code(401).send({ error: "Invalid username or password" });
  }
  if(user.mfaEnabled){const challengeToken=randomBytes(32).toString("base64url");mfaChallenges.set(challengeToken,{userId:user.id,expiresAt:Date.now()+5*60_000});return {mfaRequired:true,challengeToken}}
  db.prepare("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?").run(new Date().toISOString(),new Date().toISOString(),user.id);
  setSessionCookie(reply, createSession(user.id));
  appendAuditEvent(user.id,"USER_LOGIN","user",user.id);
  return { ok: true };
});
app.post("/api/auth/mfa",{config:{rateLimit:{max:8,timeWindow:"5 minutes"}}},async(request,reply)=>{const body=parse(mfaLoginSchema,request.body,reply);if(!body)return;const challenge=mfaChallenges.get(body.challengeToken);mfaChallenges.delete(body.challengeToken);if(!challenge||challenge.expiresAt<Date.now())return reply.code(401).send({error:"MFA challenge expired"});const user=db.prepare("SELECT id,enabled,encrypted_mfa_secret AS encryptedSecret FROM users WHERE id=? AND mfa_enabled=1").get(challenge.userId) as {id:number;enabled:number;encryptedSecret:string}|undefined;if(!user?.enabled||!user.encryptedSecret)return reply.code(401).send({error:"Invalid authentication code"});let recovery=false,valid=verifyMfaCode(decrypt(user.encryptedSecret),body.code);if(!valid&&!/^\d{6}$/.test(body.code)){const hash=recoveryCodeHash(body.code);const row=db.prepare("SELECT id FROM mfa_recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL").get(user.id,hash) as {id:number}|undefined;if(row){recovery=true;valid=Boolean(db.prepare("UPDATE mfa_recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL").run(new Date().toISOString(),row.id).changes)}}if(!valid)return reply.code(401).send({error:"Invalid authentication code"});const now=new Date().toISOString();db.prepare("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?").run(now,now,user.id);setSessionCookie(reply,createSession(user.id));appendAuditEvent(user.id,recovery?"USER_LOGIN_RECOVERY_CODE":"USER_LOGIN_MFA","user",user.id);return {ok:true,recoveryCodeUsed:recovery}});

app.post("/api/auth/logout", async (_request, reply) => {
  clearSessionCookie(reply);
  return { ok: true };
});
app.post("/api/mfa/setup",{preHandler:requireAuth},async(request,reply)=>{const user=currentUser(request);if(!user)return reply.code(401).send({error:"Authentication required"});if(user.mfaEnabled)return reply.code(409).send({error:"Disable existing MFA before starting a new setup"});const secret=createMfaSecret(),uri=mfaUri(secret,user.username);db.transaction(()=>{db.prepare("DELETE FROM mfa_recovery_codes WHERE user_id=?").run(user.id);db.prepare("UPDATE users SET encrypted_mfa_secret=?,mfa_enabled=0,updated_at=? WHERE id=?").run(encrypt(secret),new Date().toISOString(),user.id)})();appendAuditEvent(user.id,"MFA_SETUP_STARTED","user",user.id);return {secret,uri,qrDataUrl:await QRCode.toDataURL(uri,{errorCorrectionLevel:"M",margin:2,width:240})}});
app.post("/api/mfa/enable",{preHandler:requireAuth},async(request,reply)=>{const body=parse(mfaCodeSchema,request.body,reply);if(!body)return;const user=currentUser(request);if(!user)return reply.code(401).send({error:"Authentication required"});const row=db.prepare("SELECT encrypted_mfa_secret AS encryptedSecret FROM users WHERE id=?").get(user.id) as {encryptedSecret:string|null}|undefined;if(!row?.encryptedSecret||!verifyMfaCode(decrypt(row.encryptedSecret),body.code))return reply.code(400).send({error:"Invalid authentication code"});const codes=createRecoveryCodes();db.transaction(()=>{db.prepare("DELETE FROM mfa_recovery_codes WHERE user_id=?").run(user.id);const insert=db.prepare("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)");for(const code of codes)insert.run(user.id,recoveryCodeHash(code));db.prepare("UPDATE users SET mfa_enabled=1,updated_at=? WHERE id=?").run(new Date().toISOString(),user.id)})();appendAuditEvent(user.id,"MFA_ENABLED","user",user.id,{recoveryCodeCount:codes.length});return {ok:true,recoveryCodes:codes}});
app.post("/api/mfa/disable",{preHandler:requireAuth},async(request,reply)=>{const body=parse(mfaCodeSchema,request.body,reply);if(!body)return;const user=currentUser(request);if(!user)return reply.code(401).send({error:"Authentication required"});const row=db.prepare("SELECT encrypted_mfa_secret AS encryptedSecret FROM users WHERE id=? AND mfa_enabled=1").get(user.id) as {encryptedSecret:string}|undefined;if(!row?.encryptedSecret||!verifyMfaCode(decrypt(row.encryptedSecret),body.code))return reply.code(400).send({error:"Invalid authentication code"});db.transaction(()=>{db.prepare("DELETE FROM mfa_recovery_codes WHERE user_id=?").run(user.id);db.prepare("UPDATE users SET mfa_enabled=0,encrypted_mfa_secret=NULL,updated_at=? WHERE id=?").run(new Date().toISOString(),user.id)})();appendAuditEvent(user.id,"MFA_DISABLED","user",user.id);return {ok:true}});
app.post("/api/mfa/recovery-codes",{preHandler:requireAuth},async(request,reply)=>{const body=parse(mfaCodeSchema,request.body,reply);if(!body)return;const user=currentUser(request);if(!user)return reply.code(401).send({error:"Authentication required"});const row=db.prepare("SELECT encrypted_mfa_secret AS encryptedSecret FROM users WHERE id=? AND mfa_enabled=1").get(user.id) as {encryptedSecret:string}|undefined;if(!row?.encryptedSecret||!verifyMfaCode(decrypt(row.encryptedSecret),body.code))return reply.code(400).send({error:"Invalid authentication code"});const codes=createRecoveryCodes();db.transaction(()=>{db.prepare("DELETE FROM mfa_recovery_codes WHERE user_id=?").run(user.id);const insert=db.prepare("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)");for(const code of codes)insert.run(user.id,recoveryCodeHash(code))})();appendAuditEvent(user.id,"MFA_RECOVERY_CODES_REGENERATED","user",user.id,{recoveryCodeCount:codes.length});return {recoveryCodes:codes}});

app.get("/api/users",{preHandler:requireAuth},async(request,reply)=>{
  const user=currentUser(request);if(user?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});
  return db.prepare(`SELECT id,username,role,enabled,mfa_enabled AS mfaEnabled,created_at AS createdAt,updated_at AS updatedAt,last_login_at AS lastLoginAt FROM users ORDER BY username`).all().map(row=>({...row as Record<string,unknown>,enabled:Boolean((row as {enabled:number}).enabled),mfaEnabled:Boolean((row as {mfaEnabled:number}).mfaEnabled)}));
});
app.post("/api/users",{preHandler:requireAuth},async(request,reply)=>{
  const body=parse(userCreateSchema,request.body,reply);if(!body)return;const hash=await argon2.hash(body.password,{type:argon2.argon2id});
  try{const result=db.prepare("INSERT INTO users(username,password_hash,role,updated_at) VALUES(?,?,?,?)").run(body.username,hash,body.role,new Date().toISOString());const id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"USER_CREATED","user",id,{username:body.username,role:body.role});return reply.code(201).send({id});}
  catch{return reply.code(409).send({error:"Username already exists"})}
});
app.put("/api/users/:id",{preHandler:requireAuth},async(request,reply)=>{
  const id=Number((request.params as {id:string}).id);const body=parse(userUpdateSchema,request.body,reply);if(!body)return;const self=actor(request);
  const existing=db.prepare("SELECT id,username,role,enabled FROM users WHERE id=?").get(id) as {id:number;username:string;role:string;enabled:number}|undefined;if(!existing)return reply.code(404).send({error:"User not found"});
  if(id===self&&(!body.enabled||body.role!=="ADMIN"))return reply.code(400).send({error:"You cannot disable or remove your own administrator role"});
  const enabledAdmins=(db.prepare("SELECT COUNT(*) count FROM users WHERE role='ADMIN' AND enabled=1").get() as {count:number}).count;
  if(existing.role==="ADMIN"&&existing.enabled&&enabledAdmins<=1&&(!body.enabled||body.role!=="ADMIN"))return reply.code(400).send({error:"At least one enabled administrator is required"});
  const now=new Date().toISOString();if(body.password){const hash=await argon2.hash(body.password,{type:argon2.argon2id});db.prepare("UPDATE users SET role=?,enabled=?,password_hash=?,updated_at=? WHERE id=?").run(body.role,body.enabled?1:0,hash,now,id)}else db.prepare("UPDATE users SET role=?,enabled=?,updated_at=? WHERE id=?").run(body.role,body.enabled?1:0,now,id);
  appendAuditEvent(actor(request),"USER_UPDATED","user",id,{username:existing.username,previousRole:existing.role,role:body.role,enabled:body.enabled,passwordChanged:Boolean(body.password)});return {ok:true};
});
app.delete("/api/users/:id/mfa",{preHandler:requireAuth},async(request,reply)=>{const admin=currentUser(request);if(admin?.role!=="ADMIN")return reply.code(403).send({error:"Administrator role required"});const id=Number((request.params as {id:string}).id);if(id===admin.id)return reply.code(400).send({error:"Use your Security settings to disable your own MFA"});const target=db.prepare("SELECT id,username,mfa_enabled AS mfaEnabled FROM users WHERE id=?").get(id) as {id:number;username:string;mfaEnabled:number}|undefined;if(!target)return reply.code(404).send({error:"User not found"});db.transaction(()=>{db.prepare("DELETE FROM mfa_recovery_codes WHERE user_id=?").run(id);db.prepare("UPDATE users SET mfa_enabled=0,encrypted_mfa_secret=NULL,updated_at=? WHERE id=?").run(new Date().toISOString(),id)})();appendAuditEvent(admin.id,"MFA_ADMIN_RESET","user",id,{username:target.username,wasEnabled:Boolean(target.mfaEnabled)});return reply.code(204).send()});

app.get("/api/projects", { preHandler: requireAuth }, async () => {
  const rows = db.prepare("SELECT * FROM projects ORDER BY name").all() as ProjectRow[];
  const recent = db.prepare(`SELECT status, response_time_ms AS responseTimeMs, checked_at AS checkedAt
    FROM heartbeats WHERE project_id = ? ORDER BY checked_at DESC LIMIT 48`);
  return rows.map((row) => ({ ...publicProject(row), recentHeartbeats: recent.all(row.id).reverse() }));
});

app.post("/api/projects", { preHandler: requireAuth }, async (request, reply) => {
  const body = parse(projectSchema, request.body, reply);
  if (!body) return;
  const now = new Date().toISOString();
  const result = db.prepare(`INSERT INTO projects
    (name, supabase_url, encrypted_key, interval_seconds, timeout_seconds, retry_count, enabled,
      next_check_at, monitor_type, target, http_method, expected_status, keyword, tcp_host, tcp_port, maintenance,
      dns_record_type, ssl_port, ssl_expiry_days, docker_container, published, database_engine)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(body.name, body.monitorType==="DATABASE"?`${body.databaseEngine} database`:body.supabaseUrl ?? body.target ?? body.dockerContainer ?? `tcp://${body.tcpHost}:${body.tcpPort}`,
      encrypt(body.monitorType==="DATABASE"?body.connectionString??"":body.publishableKey ?? ""), body.intervalSeconds, body.timeoutSeconds, body.retryCount,
      body.enabled ? 1 : 0, now, body.monitorType, body.supabaseUrl ?? body.target ?? null,
      body.httpMethod, body.expectedStatus ?? null, body.keyword ?? null, body.tcpHost ?? null,
      body.tcpPort ?? null, body.maintenance ? 1 : 0, body.dnsRecordType, body.sslPort,
      body.sslExpiryDays, body.dockerContainer ?? null, body.published ? 1 : 0,body.databaseEngine??null);
  const row = db.prepare("SELECT * FROM projects WHERE id = ?").get(result.lastInsertRowid) as ProjectRow;
  appendAuditEvent(actor(request),"MONITOR_CREATED","project",row.id,{name:row.name,monitorType:row.monitor_type,databaseEngine:row.database_engine});
  return reply.code(201).send(publicProject(row));
});

app.patch("/api/projects/:id", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const current = db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as ProjectRow | undefined;
  if (!current) return reply.code(404).send({ error: "Project not found" });
  const body = parse(updateProjectSchema, request.body, reply);
  if (!body) return;
  db.prepare(`UPDATE projects SET name = ?, supabase_url = ?, encrypted_key = ?, interval_seconds = ?,
    timeout_seconds = ?, retry_count = ?, enabled = ?, next_check_at = ?, updated_at = ?, monitor_type = ?,
    target = ?, http_method = ?, expected_status = ?, keyword = ?, tcp_host = ?, tcp_port = ?, maintenance = ?,
    dns_record_type = ?, ssl_port = ?, ssl_expiry_days = ?, docker_container = ?, published = ?, database_engine = ?
    WHERE id = ?`)
    .run(body.name ?? current.name, body.supabaseUrl ?? body.target ?? current.supabase_url,
      body.connectionString?encrypt(body.connectionString):body.publishableKey ? encrypt(body.publishableKey) : current.encrypted_key,
      body.intervalSeconds ?? current.interval_seconds, body.timeoutSeconds ?? current.timeout_seconds,
      body.retryCount ?? current.retry_count, (body.enabled ?? Boolean(current.enabled)) ? 1 : 0,
      new Date().toISOString(), new Date().toISOString(), body.monitorType ?? current.monitor_type,
      body.supabaseUrl ?? body.target ?? current.target, body.httpMethod ?? current.http_method,
      body.expectedStatus === undefined ? current.expected_status : body.expectedStatus,
      body.keyword === undefined ? current.keyword : body.keyword, body.tcpHost ?? current.tcp_host,
      body.tcpPort ?? current.tcp_port, (body.maintenance ?? Boolean(current.maintenance)) ? 1 : 0,
      body.dnsRecordType ?? current.dns_record_type, body.sslPort ?? current.ssl_port,
      body.sslExpiryDays ?? current.ssl_expiry_days, body.dockerContainer ?? current.docker_container,
      (body.published ?? Boolean(current.published)) ? 1 : 0,body.databaseEngine??current.database_engine, id);
  appendAuditEvent(actor(request),"MONITOR_UPDATED","project",id,{monitorType:body.monitorType??current.monitor_type,databaseEngine:body.databaseEngine??current.database_engine,credentialsReplaced:Boolean(body.connectionString||body.publishableKey)});
  return publicProject(db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as ProjectRow);
});

app.get("/api/projects/:id/database-metrics",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),project=db.prepare("SELECT monitor_type FROM projects WHERE id=?").get(id) as {monitor_type:string}|undefined;if(!project)return reply.code(404).send({error:"Project not found"});if(project.monitor_type!=="DATABASE")return reply.code(400).send({error:"This is not a database monitor"});return db.prepare(`SELECT id,engine,connections_used AS connectionsUsed,connections_max AS connectionsMax,database_size_bytes AS databaseSizeBytes,replication_lag_seconds AS replicationLagSeconds,long_running_queries AS longRunningQueries,details_json AS details,observed_at AS observedAt FROM database_metrics WHERE project_id=? ORDER BY observed_at DESC LIMIT 500`).all(id).map((row:any)=>({...row,details:JSON.parse(row.details)}))});

app.delete("/api/projects/:id", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const result = db.prepare("DELETE FROM projects WHERE id = ?").run(id);
  if (!result.changes) return reply.code(404).send({ error: "Project not found" });
  return reply.code(204).send();
});

app.post("/api/projects/:id/run", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  try {
    return await checkProject(id);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to run check";
    return reply.code(message === "Project not found" ? 404 : 409).send({ error: message });
  }
});

app.get("/api/projects/:id/heartbeats", { preHandler: requireAuth }, async (request) => {
  const id = Number((request.params as { id: string }).id);
  const query = request.query as { limit?: string };
  const limit = Math.min(Math.max(Number(query.limit ?? 50), 1), 500);
  return db.prepare(`SELECT id, status, http_status AS httpStatus, response_time_ms AS responseTimeMs,
    attempt, error_message AS errorMessage, checked_at AS checkedAt
    FROM heartbeats WHERE project_id = ? ORDER BY checked_at DESC LIMIT ?`).all(id, limit);
});

app.get("/api/projects/:id/stats", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const project = db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as ProjectRow | undefined;
  if (!project) return reply.code(404).send({ error: "Project not found" });
  const now = Date.now();
  const cutoff24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
  const cutoff30d = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
  const aggregate = (cutoff: string) => db.prepare(`SELECT COUNT(*) AS total,
    SUM(CASE WHEN status = 'UP' THEN 1 ELSE 0 END) AS up,
    AVG(CASE WHEN status = 'UP' THEN response_time_ms END) AS averageResponseMs,
    MIN(response_time_ms) AS minResponseMs, MAX(response_time_ms) AS maxResponseMs
    FROM heartbeats WHERE project_id = ? AND checked_at >= ?`).get(id, cutoff) as {
      total: number; up: number | null; averageResponseMs: number | null; minResponseMs: number | null; maxResponseMs: number | null;
    };
  const day = aggregate(cutoff24h);
  const month = aggregate(cutoff30d);
  const percent = (value: { total: number; up: number | null }) => value.total ? Math.round(((value.up ?? 0) / value.total) * 10000) / 100 : null;
  return {
    currentResponseMs: project.last_checked_at ? (db.prepare("SELECT response_time_ms FROM heartbeats WHERE project_id = ? ORDER BY checked_at DESC LIMIT 1").get(id) as { response_time_ms?: number } | undefined)?.response_time_ms ?? null : null,
    averageResponse24hMs: day.averageResponseMs === null ? null : Math.round(day.averageResponseMs * 100) / 100,
    uptime24h: percent(day), uptime30d: percent(month), checks24h: day.total, checks30d: month.total,
    minResponse24hMs: day.minResponseMs, maxResponse24hMs: day.maxResponseMs
  };
});

app.get("/api/dashboard/summary", { preHandler: requireAuth }, async () => {
  const counts = db.prepare(`SELECT
    COUNT(*) AS total,
    SUM(CASE WHEN enabled = 1 AND last_status = 'UP' THEN 1 ELSE 0 END) AS up,
    SUM(CASE WHEN enabled = 1 AND last_status NOT IN ('UP', 'PENDING') THEN 1 ELSE 0 END) AS down,
    SUM(CASE WHEN enabled = 0 THEN 1 ELSE 0 END) AS disabled
    FROM projects`).get() as Record<string, number>;
  return counts;
});

app.get("/api/settings/status-page", { preHandler: requireAuth }, async () => ({
  title: (db.prepare("SELECT value FROM app_settings WHERE key = 'status_title'").get() as { value?: string } | undefined)?.value || "Byakugan Status"
}));

app.put("/api/settings/status-page", { preHandler: requireAuth }, async (request, reply) => {
  const body = parse(z.object({ title: z.string().trim().min(1).max(100) }), request.body, reply);
  if (!body) return;
  db.prepare(`INSERT INTO app_settings (key, value, updated_at) VALUES ('status_title', ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`).run(body.title);
  return { title: body.title };
});

app.get("/api/share-dashboards", { preHandler: requireAuth }, async () => {
  const pages = db.prepare(`SELECT d.id, d.name, d.token, d.enabled, d.created_at AS createdAt,
    COUNT(sp.project_id) AS projectCount FROM shared_dashboards d
    LEFT JOIN shared_dashboard_projects sp ON sp.dashboard_id = d.id GROUP BY d.id ORDER BY d.created_at DESC`).all() as Array<{ id: number; name: string; token: string; enabled: number; createdAt: string; projectCount: number }>;
  return pages.map((page) => {
    let token = ""; try { token = decrypt(page.token); } catch { token = page.token; }
    return { ...page, token: undefined, enabled: Boolean(page.enabled), sharePath: `/share/${token}` };
  });
});

app.post("/api/share-dashboards", { preHandler: requireAuth }, async (request, reply) => {
  const body = parse(shareDashboardSchema, request.body, reply);
  if (!body) return;
  const uniqueIds = new Set(body.projects.map((item) => item.projectId));
  if (uniqueIds.size !== body.projects.length) return reply.code(400).send({ error: "A monitor can only appear once per shared dashboard" });
  const placeholders = body.projects.map(() => "?").join(",");
  const found = (db.prepare(`SELECT COUNT(*) AS count FROM projects WHERE id IN (${placeholders})`).get(...uniqueIds) as { count: number }).count;
  if (found !== uniqueIds.size) return reply.code(400).send({ error: "One or more monitors do not exist" });
  const token = randomBytes(24).toString("base64url");
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const id = db.transaction(() => {
    const result = db.prepare("INSERT INTO shared_dashboards (name, token, token_hash) VALUES (?, ?, ?)").run(body.name, encrypt(token), tokenHash);
    const dashboardId = Number(result.lastInsertRowid);
    const insert = db.prepare("INSERT INTO shared_dashboard_projects (dashboard_id, project_id, group_name, sort_order) VALUES (?, ?, ?, ?)");
    body.projects.forEach((item, index) => insert.run(dashboardId, item.projectId, item.groupName, index));
    return dashboardId;
  })();
  return reply.code(201).send({ id, name: body.name, token, enabled: true, projectCount: body.projects.length, sharePath: `/share/${token}` });
});

app.delete("/api/share-dashboards/:id", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const result = db.prepare("DELETE FROM shared_dashboards WHERE id = ?").run(id);
  if (!result.changes) return reply.code(404).send({ error: "Shared dashboard not found" });
  return reply.code(204).send();
});

app.get("/api/notifications", { preHandler: requireAuth }, async () => {
  return db.prepare(`SELECT id, name, type, enabled, created_at AS createdAt
    FROM notifications ORDER BY name`).all().map((row) => ({ ...(row as object), enabled: Boolean((row as { enabled: number }).enabled), configured: true }));
});

app.post("/api/notifications", { preHandler: requireAuth }, async (request, reply) => {
  const body = parse(notificationSchema, request.body, reply);
  if (!body) return;
  const configValue = body.type === "TELEGRAM"
    ? { botToken: body.botToken, chatId: body.chatId }
    : { url: body.url };
  const result = db.prepare(`INSERT INTO notifications (name, type, encrypted_config, enabled)
    VALUES (?, ?, ?, ?)`).run(body.name, body.type, encrypt(JSON.stringify(configValue)), body.enabled ? 1 : 0);
  return reply.code(201).send({ id: Number(result.lastInsertRowid), name: body.name, type: body.type, enabled: body.enabled, configured: true });
});

app.delete("/api/notifications/:id", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const result = db.prepare("DELETE FROM notifications WHERE id = ?").run(id);
  if (!result.changes) return reply.code(404).send({ error: "Notification not found" });
  return reply.code(204).send();
});

app.post("/api/notifications/test", { preHandler: requireAuth }, async (request, reply) => {
  const body = parse(notificationSchema, request.body, reply);
  if (!body) return;
  try {
    await testNotification(body.type as NotificationType, { url: body.url, botToken: body.botToken, chatId: body.chatId });
    return { ok: true };
  } catch (error) {
    return reply.code(502).send({ error: error instanceof Error ? error.message : "Notification test failed" });
  }
});

app.get("/api/projects/:id/notifications", { preHandler: requireAuth }, async (request) => {
  const id = Number((request.params as { id: string }).id);
  return db.prepare("SELECT notification_id AS notificationId FROM project_notifications WHERE project_id = ?").all(id);
});

app.put("/api/projects/:id/notifications", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const body = parse(z.object({ notificationIds: z.array(z.number().int().positive()).max(50) }), request.body, reply);
  if (!body) return;
  db.transaction(() => {
    db.prepare("DELETE FROM project_notifications WHERE project_id = ?").run(id);
    const insert = db.prepare("INSERT INTO project_notifications (project_id, notification_id) VALUES (?, ?)");
    for (const notificationId of body.notificationIds) insert.run(id, notificationId);
  })();
  return { ok: true };
});

app.get("/api/incidents", { preHandler: requireAuth }, async () => {
  return db.prepare(`SELECT i.id, i.project_id AS projectId, p.name AS projectName, i.status,
    i.message,i.severity,i.owner,i.root_cause AS rootCause,i.corrective_action AS correctiveAction,i.lessons_learned AS lessonsLearned,
    i.review_status AS reviewStatus,i.reviewed_at AS reviewedAt,ru.username AS reviewedBy,i.started_at AS startedAt, i.resolved_at AS resolvedAt
    FROM incidents i JOIN projects p ON p.id = i.project_id LEFT JOIN users ru ON ru.id=i.reviewed_by ORDER BY i.started_at DESC LIMIT 200`).all();
});
app.put("/api/incidents/:id/review",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),body=parse(incidentReviewSchema,request.body,reply);if(!body)return;const existing=db.prepare("SELECT id,review_status AS reviewStatus FROM incidents WHERE id=?").get(id) as {id:number;reviewStatus:string}|undefined;if(!existing)return reply.code(404).send({error:"Incident not found"});const now=new Date().toISOString(),reviewer=body.reviewStatus==="APPROVED"?actor(request):null;db.prepare(`UPDATE incidents SET severity=?,owner=?,root_cause=?,corrective_action=?,lessons_learned=?,review_status=?,reviewed_by=?,reviewed_at=? WHERE id=?`).run(body.severity,body.owner??null,body.rootCause??null,body.correctiveAction??null,body.lessonsLearned??null,body.reviewStatus,reviewer,reviewer?now:null,id);appendAuditEvent(actor(request),"INCIDENT_REVIEW_UPDATED","incident",id,{previousStatus:existing.reviewStatus,reviewStatus:body.reviewStatus,severity:body.severity,owner:body.owner});return {ok:true}});

app.get("/api/notification-deliveries", { preHandler: requireAuth }, async () => {
  return db.prepare(`SELECT d.id, n.name AS notificationName, p.name AS projectName, d.event,
    d.success, d.error_message AS errorMessage, d.created_at AS createdAt
    FROM notification_deliveries d
    JOIN notifications n ON n.id = d.notification_id
    LEFT JOIN projects p ON p.id = d.project_id
    ORDER BY d.created_at DESC LIMIT 100`).all().map((row) => ({
      ...(row as object), success: Boolean((row as { success: number }).success)
    }));
});

app.get("/api/audit/controls", { preHandler: requireAuth }, async () =>
  db.prepare("SELECT id, code, title, framework, description FROM iso_controls WHERE enabled = 1 ORDER BY code").all());

app.get("/api/audit/settings", { preHandler: requireAuth }, async () => ({
  retentionDays: Number((db.prepare("SELECT value FROM app_settings WHERE key='audit_retention_days'").get() as { value?: string }|undefined)?.value ?? 365)
}));
app.put("/api/audit/settings", { preHandler: requireAuth }, async (request, reply) => {
  const body=parse(z.object({retentionDays:z.number().int().min(90).max(3650)}),request.body,reply);if(!body)return;
  db.prepare(`INSERT INTO app_settings(key,value,updated_at) VALUES('audit_retention_days',?,CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`).run(String(body.retentionDays));
  appendAuditEvent(actor(request),"RETENTION_POLICY_UPDATED","settings","audit_retention_days",{retentionDays:body.retentionDays});return body;
});

app.get("/api/audit/overview", { preHandler: requireAuth }, async () => {
  const assets = db.prepare(`SELECT p.id, p.name, p.monitor_type AS monitorType, p.asset_tag AS assetTag,
    p.asset_owner AS assetOwner, p.environment, p.criticality, p.warning_threshold AS warningThreshold,
    p.critical_threshold AS criticalThreshold, p.threshold_operator AS thresholdOperator,
    p.threshold_duration_seconds AS thresholdDurationSeconds, p.last_status AS lastStatus,
    GROUP_CONCAT(pc.control_id) AS controlIds
    FROM projects p LEFT JOIN project_controls pc ON pc.project_id = p.id GROUP BY p.id ORDER BY p.name`).all().map((row) => {
      const value = row as Record<string, unknown>; return { ...value, controlIds: value.controlIds ? String(value.controlIds).split(",").map(Number) : [] };
    });
  const openIncidents = (db.prepare("SELECT COUNT(*) AS count FROM incidents WHERE resolved_at IS NULL").get() as { count: number }).count;
  const controlsMapped = (db.prepare("SELECT COUNT(DISTINCT control_id) AS count FROM project_controls").get() as { count: number }).count;
  return { assets, openIncidents, controlsMapped, auditChain: verifyAuditChain() };
});

app.put("/api/audit/projects/:id", { preHandler: requireAuth }, async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const body = parse(auditProfileSchema, request.body, reply); if (!body) return;
  if (!db.prepare("SELECT 1 FROM projects WHERE id = ?").get(id)) return reply.code(404).send({ error: "Project not found" });
  db.transaction(() => {
    db.prepare(`UPDATE projects SET asset_tag=?, asset_owner=?, environment=?, criticality=?, warning_threshold=?,
      critical_threshold=?, threshold_operator=?, threshold_duration_seconds=?, updated_at=? WHERE id=?`)
      .run(body.assetTag ?? null, body.assetOwner ?? null, body.environment, body.criticality, body.warningThreshold ?? null,
        body.criticalThreshold ?? null, body.thresholdOperator, body.thresholdDurationSeconds, new Date().toISOString(), id);
    db.prepare("DELETE FROM project_controls WHERE project_id = ?").run(id);
    const insert = db.prepare("INSERT INTO project_controls (project_id, control_id) VALUES (?, ?)");
    for (const controlId of body.controlIds) insert.run(id, controlId);
  })();
  appendAuditEvent(actor(request), "AUDIT_PROFILE_UPDATED", "project", id, { environment: body.environment, criticality: body.criticality, controlIds: body.controlIds });
  return { ok: true };
});

app.get("/api/audit/events", { preHandler: requireAuth }, async (request) => {
  const limit = Math.min(Math.max(Number((request.query as { limit?: string }).limit ?? 200), 1), 2000);
  return db.prepare(`SELECT a.id, u.username AS actor, a.action, a.entity_type AS entityType, a.entity_id AS entityId,
    a.details_json AS detailsJson, a.previous_hash AS previousHash, a.event_hash AS eventHash, a.created_at AS createdAt
    FROM audit_events a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT ?`).all(limit);
});

app.get("/api/audit/verify", { preHandler: requireAuth }, async () => verifyAuditChain());

app.get("/api/audit/report.pdf",{preHandler:requireAuth},async(request,reply)=>{try{const query=request.query as {from?:string;to?:string},period=auditPeriod(query.from,query.to),preferences=reportPreferences(request);const buffer=await createPdfReport(collectAuditReport(period.from,period.to),preferences.locale,preferences.timezone);appendAuditEvent(actor(request),"AUDIT_REPORT_DOWNLOADED","report","PDF",{...period,...preferences,sha256:reportSha256(buffer)});return reply.header("Content-Disposition",`attachment; filename="byakugan-audit-${period.from.slice(0,10)}-${preferences.locale}.pdf"`).type("application/pdf").send(buffer)}catch(error){return reply.code(400).send({error:error instanceof Error?error.message:"Unable to create PDF"})}});
app.get("/api/audit/report.xlsx",{preHandler:requireAuth},async(request,reply)=>{try{const query=request.query as {from?:string;to?:string},period=auditPeriod(query.from,query.to),preferences=reportPreferences(request);const buffer=await createXlsxReport(collectAuditReport(period.from,period.to),preferences.locale,preferences.timezone);appendAuditEvent(actor(request),"AUDIT_REPORT_DOWNLOADED","report","XLSX",{...period,...preferences,sha256:reportSha256(buffer)});return reply.header("Content-Disposition",`attachment; filename="byakugan-audit-${period.from.slice(0,10)}-${preferences.locale}.xlsx"`).type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").send(buffer)}catch(error){return reply.code(400).send({error:error instanceof Error?error.message:"Unable to create XLSX"})}});
app.get("/api/report-delivery-channels",{preHandler:requireAuth},async()=>db.prepare(`SELECT id,name,type,encrypted_config AS encryptedConfig,enabled,created_at AS createdAt,updated_at AS updatedAt FROM report_delivery_channels ORDER BY name`).all().map((row:any)=>{let policy:Record<string,unknown>={};if(row.type==="S3"){try{const value=JSON.parse(decrypt(row.encryptedConfig));policy={wormMode:value.wormMode??"NONE",retentionDays:value.retentionDays??365,legalHold:Boolean(value.legalHold)}}catch{policy={wormMode:"UNKNOWN",retentionDays:null,legalHold:false}}}const{encryptedConfig,...safe}=row;void encryptedConfig;return{...safe,...policy,enabled:Boolean(row.enabled),configured:true}}));
app.post("/api/report-delivery-channels/test",{preHandler:requireAuth},async(request,reply)=>{const body=parse(reportDeliveryChannelSchema,request.body,reply);if(!body)return;try{return await testDeliveryChannel(deliveryConfig(body))}catch(error){return reply.code(400).send({error:`Delivery channel test failed (${deliveryErrorCode(error)})`})}});
app.post("/api/report-delivery-channels",{preHandler:requireAuth},async(request,reply)=>{const body=parse(reportDeliveryChannelSchema,request.body,reply);if(!body)return;const value=deliveryConfig(body);try{await testDeliveryChannel(value)}catch(error){return reply.code(400).send({error:`Delivery channel test failed (${deliveryErrorCode(error)})`})}const result=db.prepare("INSERT INTO report_delivery_channels(name,type,encrypted_config) VALUES(?,?,?)").run(body.name,body.type,encrypt(JSON.stringify(value.config))),id=Number(result.lastInsertRowid);appendAuditEvent(actor(request),"REPORT_DELIVERY_CHANNEL_CREATED","report_delivery_channel",id,{name:body.name,type:body.type});return reply.code(201).send({id})});
app.delete("/api/report-delivery-channels/:id",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id),result=db.prepare("UPDATE report_delivery_channels SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(id);if(!result.changes)return reply.code(404).send({error:"Delivery channel not found"});appendAuditEvent(actor(request),"REPORT_DELIVERY_CHANNEL_DISABLED","report_delivery_channel",id);return reply.code(204).send()});
app.get("/api/report-deliveries",{preHandler:requireAuth},async()=>db.prepare(`SELECT d.id,d.generated_report_id AS generatedReportId,d.schedule_id AS scheduleId,d.status,d.attempts,d.destination,d.object_key AS objectKey,d.error_code AS errorCode,d.worm_mode AS wormMode,d.retain_until AS retainUntil,d.legal_hold AS legalHold,d.object_version_id AS objectVersionId,d.immutable_verified AS immutableVerified,d.delivered_at AS deliveredAt,d.created_at AS createdAt,c.name AS channelName,c.type AS channelType FROM report_deliveries d LEFT JOIN report_delivery_channels c ON c.id=d.channel_id ORDER BY d.id DESC LIMIT 500`).all().map((row:any)=>({...row,legalHold:Boolean(row.legalHold),immutableVerified:Boolean(row.immutableVerified)})));
app.get("/api/report-schedules",{preHandler:requireAuth},async()=>db.prepare(`SELECT s.id,s.name,s.frequency,s.formats,s.period_days AS periodDays,s.enabled,s.next_run_at AS nextRunAt,s.last_run_at AS lastRunAt,s.created_at AS createdAt,(SELECT group_concat(channel_id) FROM report_schedule_channels WHERE schedule_id=s.id) AS channelIds FROM report_schedules s ORDER BY s.name`).all().map((row:any)=>({...row,formats:String(row.formats).split(','),deliveryChannelIds:row.channelIds?String(row.channelIds).split(',').map(Number):[],enabled:Boolean(row.enabled)})));
app.post("/api/report-schedules",{preHandler:requireAuth},async(request,reply)=>{const body=parse(reportScheduleSchema,request.body,reply);if(!body)return;if(body.deliveryChannelIds.length){const placeholders=body.deliveryChannelIds.map(()=>"?").join(","),count=Number((db.prepare(`SELECT COUNT(*) count FROM report_delivery_channels WHERE enabled=1 AND id IN (${placeholders})`).get(...body.deliveryChannelIds) as {count:number}).count);if(count!==new Set(body.deliveryChannelIds).size)return reply.code(400).send({error:"One or more delivery channels are unavailable"})}const interval=body.frequency==="WEEKLY"?7:30,next=new Date(Date.now()+interval*86400000).toISOString();const id=db.transaction(()=>{const result=db.prepare(`INSERT INTO report_schedules(name,frequency,formats,period_days,enabled,next_run_at,created_by) VALUES(?,?,?,?,?,?,?)`).run(body.name,body.frequency,body.formats.join(','),body.periodDays,body.enabled?1:0,next,actor(request)),id=Number(result.lastInsertRowid),insert=db.prepare("INSERT INTO report_schedule_channels(schedule_id,channel_id) VALUES(?,?)");for(const channelId of new Set(body.deliveryChannelIds))insert.run(id,channelId);return id})();appendAuditEvent(actor(request),"REPORT_SCHEDULE_CREATED","report_schedule",id,{name:body.name,frequency:body.frequency,formats:body.formats,deliveryChannelIds:body.deliveryChannelIds});return reply.code(201).send({id})});
app.delete("/api/report-schedules/:id",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id);const result=db.prepare("UPDATE report_schedules SET enabled=0,updated_at=? WHERE id=?").run(new Date().toISOString(),id);if(!result.changes)return reply.code(404).send({error:"Schedule not found"});appendAuditEvent(actor(request),"REPORT_SCHEDULE_DISABLED","report_schedule",id);return reply.code(204).send()});
app.get("/api/generated-reports",{preHandler:requireAuth},async()=>db.prepare(`SELECT id,schedule_id AS scheduleId,format,date_from AS dateFrom,date_to AS dateTo,file_name AS fileName,size_bytes AS sizeBytes,sha256,status,error_message AS errorMessage,created_at AS createdAt FROM generated_reports ORDER BY id DESC LIMIT 200`).all());
app.get("/api/generated-reports/:id/download",{preHandler:requireAuth},async(request,reply)=>{const id=Number((request.params as {id:string}).id);const row=db.prepare("SELECT file_name AS fileName,file_path AS filePath,format FROM generated_reports WHERE id=? AND status='READY'").get(id) as {fileName:string;filePath:string;format:string}|undefined;if(!row)return reply.code(404).send({error:"Report not found"});try{const buffer=await readFile(row.filePath);return reply.header("Content-Disposition",`attachment; filename="${row.fileName.replace(/[^a-zA-Z0-9_.-]/g,'_')}"`).type(row.format==="PDF"?"application/pdf":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").send(buffer)}catch{return reply.code(404).send({error:"Report file is missing"})}});

app.get("/api/audit/workspace",{preHandler:requireAuth},async(request,reply)=>{
  const query=request.query as {from?:string;to?:string};const toDate=query.to?new Date(query.to):new Date();
  const fromDate=query.from?new Date(query.from):new Date(toDate.getTime()-90*86400000);
  if(!Number.isFinite(fromDate.getTime())||!Number.isFinite(toDate.getTime())||fromDate>toDate)return reply.code(400).send({error:"Invalid date range"});
  const from=fromDate.toISOString(),to=toDate.toISOString();
  const count=(sql:string,...args:unknown[])=>Number((db.prepare(sql).get(...args) as {count:number}).count);
  const assets=count("SELECT COUNT(*) AS count FROM projects")+count("SELECT COUNT(*) AS count FROM agents WHERE enabled=1");
  const mappedAssets=count("SELECT COUNT(DISTINCT project_id) AS count FROM project_controls");
  const backupCount=count("SELECT COUNT(*) AS count FROM backup_evidence WHERE started_at BETWEEN ? AND ?",from,to);
  const failedBackups=count("SELECT COUNT(*) AS count FROM backup_evidence WHERE started_at BETWEEN ? AND ? AND status='FAILED'",from,to);
  const restoreCount=count("SELECT COUNT(*) AS count FROM restore_tests WHERE tested_at BETWEEN ? AND ?",from,to);
  const passedRestores=count("SELECT COUNT(*) AS count FROM restore_tests WHERE tested_at BETWEEN ? AND ? AND result='PASS'",from,to);
  const openFindings=count("SELECT COUNT(*) AS count FROM compliance_findings WHERE status IN ('OPEN','ACKNOWLEDGED')")+count("SELECT COUNT(*) AS count FROM vulnerability_findings WHERE status NOT IN ('RESOLVED','RISK_ACCEPTED')");
  const evidenceEvents=count("SELECT COUNT(*) AS count FROM audit_events WHERE created_at BETWEEN ? AND ?",from,to);
  const recentExports=db.prepare(`SELECT id,date_from AS dateFrom,date_to AS dateTo,sha256,created_at AS createdAt FROM evidence_exports ORDER BY id DESC LIMIT 10`).all();
  return {period:{from,to},assets,mappedAssets,backupCount,failedBackups,restoreCount,passedRestores,openFindings,evidenceEvents,auditChain:verifyAuditChain(),recentExports};
});

app.get("/api/audit/export", { preHandler: requireAuth }, async (request, reply) => {
  const query = request.query as { from?: string; to?: string };
  const dateTo = query.to ? new Date(query.to) : new Date();
  const dateFrom = query.from ? new Date(query.from) : new Date(dateTo.getTime() - 90 * 86400000);
  if (!Number.isFinite(dateFrom.getTime()) || !Number.isFinite(dateTo.getTime()) || dateFrom > dateTo) return reply.code(400).send({ error: "Invalid date range" });
  const from = dateFrom.toISOString(); const to = dateTo.toISOString();
  const assets = db.prepare(`SELECT id, name, monitor_type AS monitor_type, asset_tag, asset_owner, environment, criticality,
    last_status, last_checked_at FROM projects ORDER BY name`).all() as Array<Record<string, unknown>>;
  const heartbeats = db.prepare(`SELECT h.id, p.name AS asset, h.status, h.http_status, h.response_time_ms, h.attempt,
    h.checked_at FROM heartbeats h JOIN projects p ON p.id=h.project_id WHERE h.checked_at BETWEEN ? AND ? ORDER BY h.checked_at`).all(from, to) as Array<Record<string, unknown>>;
  const incidentsExport = db.prepare(`SELECT i.id,p.name AS asset,i.status,i.severity,i.owner,i.message,i.root_cause,i.corrective_action,i.lessons_learned,i.review_status,i.started_at,i.resolved_at
    FROM incidents i JOIN projects p ON p.id=i.project_id WHERE i.started_at BETWEEN ? AND ? ORDER BY i.started_at`).all(from, to) as Array<Record<string, unknown>>;
  const mappings = db.prepare(`SELECT p.name AS asset, c.framework, c.code, c.title, pc.evidence_note
    FROM project_controls pc JOIN projects p ON p.id=pc.project_id JOIN iso_controls c ON c.id=pc.control_id ORDER BY c.code,p.name`).all() as Array<Record<string, unknown>>;
  const events = db.prepare(`SELECT a.id,u.username AS actor,a.action,a.entity_type,a.entity_id,a.details_json,a.previous_hash,a.event_hash,a.created_at
    FROM audit_events a LEFT JOIN users u ON u.id=a.actor_user_id WHERE a.created_at BETWEEN ? AND ? ORDER BY a.id`).all(from, to) as Array<Record<string, unknown>>;
  const agentAssets=db.prepare(`SELECT a.id,a.name,a.hostname,a.agent_version,a.last_seen_at,s.os_name,s.os_version,s.kernel,s.architecture,s.cpu_model,s.cpu_count,
    s.total_memory_bytes,s.installed_package_count,s.pending_update_count,s.security_update_count,s.reboot_required,s.docker_available,s.container_count,s.observed_at
    FROM agents a LEFT JOIN asset_snapshots s ON s.id=(SELECT id FROM asset_snapshots WHERE agent_id=a.id ORDER BY observed_at DESC LIMIT 1) ORDER BY a.name`).all() as Array<Record<string,unknown>>;
  const hostMetrics=db.prepare(`SELECT a.name AS agent,a.hostname,m.cpu_percent,m.memory_percent,m.swap_percent,m.load_1,m.load_5,m.load_15,m.uptime_seconds,m.disks_json,m.containers_json,m.observed_at
    FROM host_metrics m JOIN agents a ON a.id=m.agent_id WHERE m.observed_at BETWEEN ? AND ? ORDER BY m.observed_at`).all(from,to) as Array<Record<string,unknown>>;
  const databaseMetrics=db.prepare(`SELECT p.name AS asset,m.engine,m.connections_used,m.connections_max,m.database_size_bytes,m.replication_lag_seconds,m.long_running_queries,m.details_json,m.observed_at FROM database_metrics m JOIN projects p ON p.id=m.project_id WHERE m.observed_at BETWEEN ? AND ? ORDER BY m.observed_at`).all(from,to) as Array<Record<string,unknown>>;
  const reportDeliveryEvidence=db.prepare(`SELECT d.id,s.name AS schedule,c.name AS channel,c.type,d.status,d.attempts,d.destination,d.object_key,d.error_code,d.worm_mode,d.retain_until,d.legal_hold,d.object_version_id,d.immutable_verified,d.delivered_at,d.created_at FROM report_deliveries d LEFT JOIN report_schedules s ON s.id=d.schedule_id LEFT JOIN report_delivery_channels c ON c.id=d.channel_id WHERE d.created_at BETWEEN ? AND ? ORDER BY d.created_at`).all(from,to) as Array<Record<string,unknown>>;
  const findingsExport=db.prepare(`SELECT f.id,a.name AS agent,a.hostname,f.finding_key,f.category,f.severity,f.status,f.title,f.explanation,f.owner,f.due_at,f.resolution_note,f.first_detected_at,f.last_detected_at,f.resolved_at
    FROM compliance_findings f LEFT JOIN agents a ON a.id=f.agent_id WHERE f.first_detected_at<=? AND (f.resolved_at IS NULL OR f.resolved_at>=?) ORDER BY f.first_detected_at`).all(to,from) as Array<Record<string,unknown>>;
  const backups=db.prepare(`SELECT b.id,b.asset_name,b.backup_type,b.storage_location,b.status,b.started_at,b.completed_at,b.size_bytes,b.checksum,b.notes,u.username AS recorded_by
    FROM backup_evidence b LEFT JOIN users u ON u.id=b.recorded_by WHERE b.started_at BETWEEN ? AND ? ORDER BY b.started_at`).all(from,to) as Array<Record<string,unknown>>;
  const restores=db.prepare(`SELECT r.id,r.backup_evidence_id,r.asset_name,r.test_scope,r.result,r.tested_at,r.rto_minutes,r.actual_minutes,r.evidence_note,u.username AS tested_by
    FROM restore_tests r LEFT JOIN users u ON u.id=r.tested_by WHERE r.tested_at BETWEEN ? AND ? ORDER BY r.tested_at`).all(from,to) as Array<Record<string,unknown>>;
  const vulnerabilityScans=db.prepare(`SELECT s.id,a.name AS agent,a.hostname,s.scanner,s.target,s.critical_count,s.high_count,s.medium_count,s.low_count,s.observed_at
    FROM vulnerability_scans s JOIN agents a ON a.id=s.agent_id WHERE s.observed_at BETWEEN ? AND ? ORDER BY s.observed_at`).all(from,to) as Array<Record<string,unknown>>;
  const vulnerabilities=db.prepare(`SELECT v.id,a.name AS agent,a.hostname,v.vulnerability_id,v.package_name,v.installed_version,v.fixed_version,v.severity,v.title,v.status,v.owner,v.due_at,v.risk_reason,v.risk_expires_at,v.kev,v.kev_date_added,v.kev_due_date,v.kev_ransomware,v.kev_required_action,v.epss_score,v.epss_percentile,v.threat_intel_updated_at,v.first_detected_at,v.last_detected_at,v.resolved_at
    FROM vulnerability_findings v JOIN agents a ON a.id=v.agent_id WHERE v.first_detected_at<=? AND (v.resolved_at IS NULL OR v.resolved_at>=?) ORDER BY v.severity,v.vulnerability_id`).all(to,from) as Array<Record<string,unknown>>;
  const files: Record<string, string> = { "assets.csv": csv(assets), "heartbeats.csv": csv(heartbeats), "incidents.csv": csv(incidentsExport),
    "control-mapping.csv": csv(mappings), "audit-trail.csv": csv(events),"agent-assets.csv":csv(agentAssets),"host-metrics.csv":csv(hostMetrics),
    "compliance-findings.csv":csv(findingsExport),"database-metrics.csv":csv(databaseMetrics),"report-deliveries.csv":csv(reportDeliveryEvidence),"backup-evidence.csv":csv(backups),"restore-tests.csv":csv(restores),
    "vulnerability-scans.csv":csv(vulnerabilityScans),"vulnerabilities.csv":csv(vulnerabilities) };
  const retentionDays=Number((db.prepare("SELECT value FROM app_settings WHERE key='audit_retention_days'").get() as {value?:string}|undefined)?.value??365);
  const manifest = { generatedAt: new Date().toISOString(), period: { from, to }, retentionPolicyDays:retentionDays, auditChain: verifyAuditChain(),
    files: Object.fromEntries(Object.entries(files).map(([name, content]) => [name, { bytes: Buffer.byteLength(content), sha256: createHash("sha256").update(content).digest("hex") }])) };
  files["manifest.json"] = JSON.stringify(manifest, null, 2);
  const packageHash = createHash("sha256").update(Object.entries(files).map(([name, content]) => `${name}:${createHash("sha256").update(content).digest("hex")}`).join("\n")).digest("hex");
  files["manifest.sha256"] = `${packageHash}  evidence-package\n`;
  db.prepare("INSERT INTO evidence_exports (requested_by,date_from,date_to,sha256) VALUES (?,?,?,?)").run(actor(request), from, to, packageHash);
  appendAuditEvent(actor(request), "EVIDENCE_EXPORTED", "evidence_package", packageHash.slice(0, 16), { from, to, packageHash });
  const archive = new archiver.ZipArchive({ zlib: { level: 9 } });
  for (const [name, content] of Object.entries(files)) archive.append(content, { name });
  void archive.finalize();
  return reply.header("Content-Disposition", `attachment; filename="byakugan-audit-${from.slice(0,10)}-${to.slice(0,10)}.zip"`).type("application/zip").send(archive);
});

const webRoot = join(process.cwd(), "dist-web");
if (existsSync(webRoot)) {
  app.get("/logo.png", async (_request, reply) => {
    try {
      return reply.type("image/png").header("Cache-Control", "public, max-age=86400").send(await readFile(join(webRoot, "logo.png")));
    } catch {
      return reply.code(404).send({ error: "Logo not found" });
    }
  });
  app.get("/byakugan-eye-white-v3.png", async (_request, reply) => {
    try {
      return reply.type("image/png").header("Cache-Control", "public, max-age=31536000, immutable").send(await readFile(join(webRoot, "byakugan-eye-white-v3.png")));
    } catch {
      return reply.code(404).send({ error: "Brand logo not found" });
    }
  });
  app.get("/byakugan-eye-original-v4.png", async (_request, reply) => {
    try {
      return reply.type("image/png").header("Cache-Control", "public, max-age=31536000, immutable").send(await readFile(join(webRoot, "byakugan-eye-original-v4.png")));
    } catch {
      return reply.code(404).send({ error: "Brand logo not found" });
    }
  });
  app.get("/byakugan-login-guardian.png", async (_request, reply) => {
    try {
      return reply.type("image/png").header("Cache-Control", "public, max-age=3600").send(await readFile(join(webRoot, "byakugan-login-guardian.png")));
    } catch {
      return reply.code(404).send({ error: "Login illustration not found" });
    }
  });
  app.get("/assets/*", async (request, reply) => {
    const asset = (request.params as { "*": string })["*"];
    if (!/^[a-zA-Z0-9_.-]+$/.test(asset)) return reply.code(404).send({ error: "Not found" });
    const type = asset.endsWith(".css") ? "text/css" : asset.endsWith(".js") ? "text/javascript" : "application/octet-stream";
    try {
      return reply.type(type).send(await readFile(join(webRoot, "assets", asset)));
    } catch {
      return reply.code(404).send({ error: "Not found" });
    }
  });
  app.setNotFoundHandler(async (request, reply) => {
    if (request.url.startsWith("/api/")) return reply.code(404).send({ error: "Not found" });
    const html = await readFile(join(webRoot, "index.html"), "utf8");
    return reply.type("text/html").send(html);
  });
}

app.addHook("onClose", async () => stopScheduler());
if(!config.maintenanceMode)startScheduler();

try {
  await app.listen({ host: config.host, port: config.port });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
