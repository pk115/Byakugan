<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { api, ApiError } from "./api";
import LogsView from "./LogsView.vue";
import DataManagement from "./DataManagement.vue";
import FindingDetails from "./FindingDetails.vue";
import IncidentDetails from "./IncidentDetails.vue";
import { incidentGuidance } from "./incident-guidance";
import ServerEvidenceExport from "./ServerEvidenceExport.vue";
import { findingGuidance } from "./finding-guidance";
import AppIcon from "./AppIcon.vue";
import CertificateInfo from "./CertificateInfo.vue";
import MonitorSummary from "./MonitorSummary.vue";
import { ui } from "./ui-copy";
import { locale, setLocale, t, type Locale } from "./i18n";

type Session = { configured: boolean; authenticated: boolean; user?:{id:number;username:string;role:"ADMIN"|"OPERATOR"|"AUDITOR"|"VIEWER";mfaEnabled:boolean;mfaRequired:boolean;locale:Locale;timezone:string}|null };
type RegionalSettings={supportedLocales:Locale[];supportedTimezones:string[];systemLocale:Locale;applicationTimezone:string;serverTimezone:string;serverNow:string;userLocale:Locale;userTimezone:string};
type Certificate = {applicable?:boolean;expiresAt:string|null;checkedAt:string|null;valid:boolean|null;error:string|null};
type Project = { certificate?:Certificate;
  id: number; name: string; supabaseUrl: string; intervalSeconds: number; timeoutSeconds: number;
  retryCount: number; enabled: boolean; lastStatus: string; lastMessage: string | null;
  lastCheckedAt: string | null; nextCheckAt: string | null;
  monitorType: "SUPABASE" | "HTTP" | "TCP" | "PING" | "DNS" | "SSL" | "DOCKER" | "DATABASE" | "WEBSOCKET"; target: string | null; httpMethod: string;
  expectedStatus: number | null; keyword: string | null; ignoreTlsErrors: boolean; tcpHost: string | null; tcpPort: number | null;
  maintenance: boolean;
  dnsRecordType: string; sslPort: number; sslExpiryDays: number; dockerContainer: string | null; published: boolean;
  databaseEngine:"POSTGRESQL"|"MYSQL"|"SQLSERVER"|"MONGODB"|null;connectionConfigured:boolean;
  recentHeartbeats?: Array<{ status: string; responseTimeMs: number; checkedAt: string }>;
};
type PublicStatus = { title: string; operational: boolean; updatedAt: string; monitors: Array<Pick<Project,"id"|"name"|"monitorType"|"lastStatus"|"lastCheckedAt"> & MonitorStats> };
type Notification = { id: number; name: string; type: "WEBHOOK" | "DISCORD" | "TELEGRAM"; enabled: boolean; helpDesk?: boolean; configured: boolean };
type HealthLevel = "NORMAL" | "WARNING" | "CRITICAL" | "NO_DATA";
type HealthItem = { no: number; nameTh: string; nameEn: string; checkTh: string; frequencyTh: string; unit: string; level: HealthLevel; enabled: boolean;
  warningValue: number | null; criticalValue: number | null; durationSeconds: number; thresholds: { normal: string; warning: string; critical: string };
  subjects: Array<{ subjectKey: string; label: string; note?: string | null; level: HealthLevel; value: number | null; since: string }> };
type HealthStatus = { items: HealthItem[]; expectedLogSources: string[]; summary: { normal: number; warning: number; critical: number; noData: number } };
type Incident = { id:number;projectId:number|null;monitorType?:string|null;healthPolicyNo?:number|null;healthMetricKey?:string|null;projectName:string;status:string;message:string|null;severity:string;owner:string|null;rootCause:string|null;correctiveAction:string|null;lessonsLearned:string|null;reviewStatus:string;reviewedAt:string|null;reviewedBy:string|null;startedAt:string;resolvedAt:string|null;closedAt:string|null };
type Delivery = { id: number; notificationName: string; projectName: string | null; event: string; success: boolean; errorMessage: string | null; createdAt: string };
type Heartbeat = {
  id: number; status: string; httpStatus: number | null; responseTimeMs: number;
  attempt: number; errorMessage: string | null; checkedAt: string;
};
type MonitorStats = { certificate?:Certificate; currentResponseMs: number | null; averageResponse24hMs: number | null; uptime24h: number | null;
  uptime30d: number | null; checks24h: number; checks30d: number; minResponse24hMs: number | null; maxResponse24hMs: number | null };
type ShareDashboard = { id: number; name: string; token: string; enabled: boolean; createdAt: string; projectCount: number; sharePath: string };
type SharedMonitor = MonitorStats & { id: number; name: string; monitorType: string; lastStatus: string; lastCheckedAt: string | null;
  intervalSeconds: number; uptime24h: number | null; averageResponseMs: number | null; heartbeats: Array<{status:string;responseTimeMs:number;checkedAt:string}> };
type SharedPage = { name: string; updatedAt: string; groups: Array<{ name: string; monitors: SharedMonitor[] }> };
type IsoControl = { id:number; code:string; title:string; framework:string; description:string|null };
type AuditAsset = { id:number; name:string; monitorType:string; assetTag:string|null; assetOwner:string|null; environment:string; criticality:string;
  warningThreshold:number|null; criticalThreshold:number|null; thresholdOperator:string; thresholdDurationSeconds:number; lastStatus:string; controlIds:number[] };
type AuditOverview = { assets:AuditAsset[]; openIncidents:number; controlsMapped:number; auditChain:{valid:boolean;events:number;headHash?:string} };
type AgentHost={id:number;name:string;hostname:string|null;agentVersion:string|null;lastSeenAt:string|null;enabled:boolean;osName:string|null;osVersion:string|null;pendingUpdates:number|null;securityUpdates:number|null;rebootRequired:boolean;cpuPercent:number|null;memoryPercent:number|null;uptimeSeconds:number|null};
type Finding={id:number;findingKey?:string;lastDetectedAt?:string;category:string;severity:string;status:string;title:string;explanation:string;agentName:string|null;hostname:string|null;owner:string|null;dueAt:string|null;resolutionNote?:string|null;firstDetectedAt:string};
type BackupEvidence={id:number;assetName:string;backupType:string;storageLocation:string;status:string;startedAt:string;completedAt:string|null;sizeBytes:number|null;checksum:string|null;notes:string|null;recordedBy:string|null};
type RestoreTest={id:number;backupEvidenceId:number|null;assetName:string;testScope:string;result:string;testedAt:string;rtoMinutes:number|null;actualMinutes:number|null;evidenceNote:string|null;testedBy:string|null};
type AuditWorkspace={period:{from:string;to:string};assets:number;mappedAssets:number;backupCount:number;failedBackups:number;restoreCount:number;passedRestores:number;openFindings:number;evidenceEvents:number;auditChain:{valid:boolean;events:number};recentExports:Array<{id:number;dateFrom:string;dateTo:string;sha256:string;createdAt:string}>};
type Vulnerability={id:number;vulnerabilityId:string;packageName:string;installedVersion:string;fixedVersion:string|null;severity:string;title:string|null;status:string;owner:string|null;dueAt:string|null;riskReason:string|null;riskExpiresAt:string|null;firstDetectedAt:string;lastDetectedAt:string;agentName:string;hostname:string|null;kev:boolean;kevDateAdded:string|null;kevDueDate:string|null;kevRansomware:string|null;kevRequiredAction:string|null;epssScore:number|null;epssPercentile:number|null;threatIntelUpdatedAt:string|null};
type ThreatIntelStatus={id:number;status:string;cisaCatalogVersion:string|null;cisaReleasedAt:string|null;cveCount:number;kevMatches:number;epssMatches:number;errorCode:string|null;startedAt:string;completedAt:string|null};
type VulnerabilityScan={id:number;agentName:string;hostname:string|null;scanner:string;target:string;criticalCount:number;highCount:number;mediumCount:number;lowCount:number;observedAt:string};
type VulnerabilityScanJob={id:number;agentId:number;agentName:string;hostname:string|null;targetType:"FILESYSTEM"|"ROOTFS"|"IMAGE";target:string;scanners:string[];severity:string;status:string;progress:number;requestedAt:string;startedAt:string|null;completedAt:string|null;errorCode:string|null;errorMessage:string|null;resultSummary:Record<string,number|boolean>|null};
type ScanJobDetail=VulnerabilityScanJob&{findings:Array<{id:string;packageName:string;installedVersion:string;fixedVersion:string|null;severity:string;title:string|null;type:string;resourcePath:string|null;primaryUrl:string|null;status:string}>};
type ScanProfile={id:number;name:string;description:string|null;targetType:"FILESYSTEM"|"ROOTFS"|"IMAGE";scanners:string[];severity:string[];timeoutSeconds:number;systemProfile:boolean;enabled:boolean};
type ScanSchedule={id:number;name:string;agentId:number;agentName:string;hostname:string|null;profileId:number;profileName:string;target:string;frequency:"DAILY"|"WEEKLY";enabled:boolean;nextRunAt:string;lastRunAt:string|null;lastJobId:number|null};
type AppUser={id:number;username:string;role:"ADMIN"|"OPERATOR"|"AUDITOR"|"VIEWER";enabled:boolean;mfaEnabled:boolean;createdAt:string;updatedAt:string|null;lastLoginAt:string|null};
type ReportSchedule={id:number;name:string;frequency:string;formats:string[];periodDays:number;deliveryChannelIds:number[];enabled:boolean;nextRunAt:string;lastRunAt:string|null};type GeneratedReport={id:number;scheduleId:number|null;format:string;dateFrom:string;dateTo:string;fileName:string;sizeBytes:number;sha256:string;status:string;errorMessage:string|null;createdAt:string};
type ReportDeliveryChannel={id:number;name:string;type:"SMTP"|"S3";enabled:boolean;configured:boolean;wormMode?:string;retentionDays?:number|null;legalHold?:boolean;createdAt:string};type ReportDelivery={id:number;generatedReportId:number|null;scheduleId:number|null;status:string;attempts:number;destination:string|null;objectKey:string|null;errorCode:string|null;wormMode:string|null;retainUntil:string|null;legalHold:boolean;objectVersionId:string|null;immutableVerified:boolean;deliveredAt:string|null;createdAt:string;channelName:string|null;channelType:string|null};
type BackupConnector={id:number;name:string;assetName:string;backupType:string;maxAgeHours:number;enabled:boolean;lastReceivedAt:string|null;findingStatus:string|null;findingExplanation:string|null};
type DatabaseMetric={id:number;engine:string;connectionsUsed:number|null;connectionsMax:number|null;databaseSizeBytes:number|null;replicationLagSeconds:number|null;longRunningQueries:number|null;details:Record<string,unknown>;observedAt:string};
type OidcProvider={id:number;name:string;preset:string;issuerUrl?:string;clientId?:string;defaultRole?:AppUser["role"];jitProvisioning?:boolean;enabled?:boolean;callbackUrl?:string};

const session = ref<Session | null>(null);
const projects = ref<Project[]>([]);
const notifications = ref<Notification[]>([]);
const incidents = ref<Incident[]>([]);
const deliveries = ref<Delivery[]>([]);
const shareDashboards = ref<ShareDashboard[]>([]);
const auditOverview = ref<AuditOverview|null>(null); const isoControls = ref<IsoControl[]>([]);
const agents=ref<AgentHost[]>([]);const findings=ref<Finding[]>([]);const enrollmentToken=ref("");const agentPlatform=ref<"linux"|"windows">("linux");
const backups=ref<BackupEvidence[]>([]);const restoreTests=ref<RestoreTest[]>([]);const auditWorkspace=ref<AuditWorkspace|null>(null);
const vulnerabilities=ref<Vulnerability[]>([]);const vulnerabilityScans=ref<VulnerabilityScan[]>([]);
const threatIntelStatus=ref<ThreatIntelStatus|null>(null);
const vulnerabilityScanJobs=ref<VulnerabilityScanJob[]>([]);
const selectedScanJob=ref<ScanJobDetail|null>(null);
const scanProfiles=ref<ScanProfile[]>([]);const scanSchedules=ref<ScanSchedule[]>([]);
const users=ref<AppUser[]>([]);
const reportSchedules=ref<ReportSchedule[]>([]);const generatedReports=ref<GeneratedReport[]>([]);
const reportDeliveryChannels=ref<ReportDeliveryChannel[]>([]);const reportDeliveries=ref<ReportDelivery[]>([]);
const backupConnectors=ref<BackupConnector[]>([]);const backupConnectorToken=ref("");
const loginProviders=ref<OidcProvider[]>([]);const oidcProviders=ref<OidcProvider[]>([]);const showOidcForm=ref(false);
const mfaChallenge=ref("");const mfaCode=ref("");const mfaSetup=ref<{secret:string;uri:string;qrDataUrl:string}|null>(null);const mfaRecoveryCodes=ref<string[]>([]);const showMfaForm=ref(false);
const auditRetentionDays=ref(365);
const error = ref("");
const busy = ref(false);
const showProjectForm = ref(false);
const showNotificationForm = ref(false);
const showShareForm = ref(false);
const showAuditForm = ref(false);
const showAgentForm=ref(false);
const selectedFinding=ref<Finding|null>(null);
const showFindingForm=ref(false);const showBackupForm=ref(false);const showRestoreForm=ref(false);
const showVulnerabilityForm=ref(false);
const showScanJobForm=ref(false);
const showScanScheduleForm=ref(false);
const showScanProfileForm=ref(false);
const showUserForm=ref(false);
const showReportScheduleForm=ref(false);
const showReportDeliveryForm=ref(false);
const selectedIncident=ref<Incident|null>(null);
const showBackupConnectorForm=ref(false);const showIncidentForm=ref(false);
const activeView = ref<"threats" | "certificates" | "health" | "dashboard" | "actions" | "incidents" | "agents" | "vulnerabilities" | "heartbeats" | "logs" | "notifications" | "shares" | "audit" | "users" | "settings" | "detail">("dashboard");
const logAgentId = ref(0);
const canReadLogs = computed(() => ["ADMIN","OPERATOR","AUDITOR"].includes(session.value?.user?.role??""));
function openLogs(agentId = 0) { logAgentId.value = agentId; activeView.value = "logs"; }
const findingFilter = ref("OPEN");
const filteredFindings = computed(() => findings.value.filter(item => findingFilter.value === "ALL" || item.status === findingFilter.value));
const openFindings = computed(() => findings.value.filter(item => item.status === "OPEN"));
const pendingIncidents = computed(() => incidents.value.filter(item => item.reviewStatus !== "APPROVED" && !item.closedAt));
const editingId = ref<number | null>(null);
const selected = ref<Project | null>(null);
const heartbeats = ref<Heartbeat[]>([]);
const monitorStats = ref<MonitorStats | null>(null);
const databaseMetrics=ref<DatabaseMetric[]>([]);
const running = ref(new Set<number>());
const copiedSetupSql = ref(false);
const isPublicPage = window.location.pathname.startsWith("/status");
const isSharePage = window.location.pathname.startsWith("/share/");
const shareToken = isSharePage ? window.location.pathname.split("/")[2] : "";
const publicStatus = ref<PublicStatus | null>(null);
const sharedPage = ref<SharedPage | null>(null);
const statusTitle = ref("Byakugan Status");
const regional=ref<RegionalSettings|null>(null);
const mfaRequiredRoles=ref<Array<AppUser["role"]>>([]);
const mfaPolicyRoles:Array<AppUser["role"]>=["ADMIN","OPERATOR","AUDITOR","VIEWER"];
const regionalForm=reactive({userLocale:locale.value as Locale,userTimezone:"SYSTEM",systemLocale:"th-TH" as Locale,applicationTimezone:"Asia/Bangkok"});
const browserTimezone=Intl.DateTimeFormat().resolvedOptions().timeZone||"UTC";
const appOrigin=window.location.origin;
const agentInstallCommand=computed(()=>agentPlatform.value==="windows"
  ? `$installer = Join-Path $env:TEMP "byakugan-install.ps1"; Invoke-WebRequest "https://raw.githubusercontent.com/pk115/Byakugan/main/agent-windows/install.ps1" -OutFile $installer; & $installer -Url "${appOrigin}" -Token "${enrollmentToken.value}"`
  : `curl -fsSLo /tmp/byakugan-agent-install.sh https://raw.githubusercontent.com/pk115/Byakugan/main/agent/install.sh && sudo sh /tmp/byakugan-agent-install.sh --url '${appOrigin}' --token '${enrollmentToken.value}'`);
let pollTimer: number | undefined;

const setupSql = `create table if not exists public.supapulse_heartbeat (
  id smallint primary key,
  value text not null
);

insert into public.supapulse_heartbeat (id, value)
values (1, 'alive')
on conflict (id) do update set value = excluded.value;

alter table public.supapulse_heartbeat enable row level security;

drop policy if exists "Allow SupaPulse heartbeat read"
on public.supapulse_heartbeat;

drop policy if exists "Allow Byakugan heartbeat read"
on public.supapulse_heartbeat;

create policy "Allow Byakugan heartbeat read"
on public.supapulse_heartbeat
for select
to anon
using (id = 1);

grant usage on schema public to anon;
grant select on public.supapulse_heartbeat to anon;

notify pgrst, 'reload schema';`;

const credentials = reactive({ username: "", password: "" });
const form = reactive({
  name: "", monitorType: "SUPABASE" as Project["monitorType"], supabaseUrl: "", publishableKey: "",
  target: "", httpMethod: "GET", ignoreTlsErrors: false, expectedStatus: null as number | null, keyword: "",
  tcpHost: "", tcpPort: null as number | null, intervalSeconds: 21600,
  timeoutSeconds: 15, retryCount: 2, enabled: true, maintenance: false, notificationIds: [] as number[]
  ,dnsRecordType: "A", sslPort: 443, sslExpiryDays: 14, dockerContainer: "", published: false
  ,databaseEngine:"POSTGRESQL" as NonNullable<Project["databaseEngine"]>,connectionString:""
});
const notificationForm = reactive({ name: "", type: "DISCORD" as Notification["type"], url: "", botToken: "", chatId: "", enabled: true });
const shareForm = reactive({ name: "", selections: {} as Record<number, { selected: boolean; groupName: string }> });
const auditForm = reactive({ id:0, name:"", assetTag:"", assetOwner:"", environment:"Production", criticality:"Medium",
  warningThreshold:null as number|null, criticalThreshold:null as number|null, thresholdOperator:">=", thresholdDurationSeconds:0, controlIds:[] as number[] });
const agentForm=reactive({name:""});
const findingForm=reactive({id:0,title:"",agentName:"",hostname:"",status:"OPEN",owner:"",dueAt:"",resolutionNote:""});
const backupForm=reactive({assetName:"",backupType:"DATABASE",storageLocation:"",status:"SUCCESS",startedAt:"",completedAt:"",sizeBytes:null as number|null,checksum:"",notes:""});
const restoreForm=reactive({backupEvidenceId:null as number|null,assetName:"",testScope:"Full recovery validation",result:"PASS",testedAt:"",rtoMinutes:null as number|null,actualMinutes:null as number|null,evidenceNote:""});
const vulnerabilityForm=reactive({id:0,title:"",status:"OPEN",owner:"",dueAt:"",riskReason:"",riskExpiresAt:""});
const scanJobForm=reactive({agentId:0,profileId:0,targetType:"FILESYSTEM" as VulnerabilityScanJob["targetType"],target:"/",scanners:["vuln"] as string[],severity:["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"] as string[]});
const scanScheduleForm=reactive({name:"Daily security scan",agentId:0,profileId:0,target:"/",frequency:"DAILY" as "DAILY"|"WEEKLY",firstRunAt:""});
const scanProfileForm=reactive({name:"",description:"",targetType:"FILESYSTEM" as ScanProfile["targetType"],scanners:["vuln"] as string[],severity:["HIGH","CRITICAL"] as string[],timeoutSeconds:900});
const userForm=reactive({id:0,username:"",password:"",role:"VIEWER" as AppUser["role"],enabled:true,mfaEnabled:false});
const reportScheduleForm=reactive({name:"Monthly ISO evidence pack",frequency:"MONTHLY",formats:["PDF","XLSX"] as string[],periodDays:30,deliveryChannelIds:[] as number[],enabled:true});
const reportDeliveryForm=reactive({name:"",type:"SMTP" as "SMTP"|"S3",host:"",port:587,secure:false,username:"",password:"",from:"",recipients:"",endpoint:"",region:"ap-southeast-1",bucket:"",prefix:"byakugan-audit",accessKeyId:"",secretAccessKey:"",forcePathStyle:false,wormMode:"NONE" as "NONE"|"GOVERNANCE"|"COMPLIANCE",retentionDays:365,legalHold:false});
const backupConnectorForm=reactive({name:"",assetName:"",backupType:"DATABASE",maxAgeHours:24});
const incidentForm=reactive({id:0,title:"",severity:"MEDIUM",owner:"",rootCause:"",correctiveAction:"",lessonsLearned:"",reviewStatus:"PENDING",closedAt:null as string|null});
const oidcForm=reactive({name:"",preset:"GENERIC",issuerUrl:"",clientId:"",clientSecret:"",scopes:"openid email profile",usernameClaim:"email",groupsClaim:"groups",allowedDomains:"",roleMapping:"{}",defaultRole:"VIEWER" as AppUser["role"],jitProvisioning:true,enabled:true});
const auditRange=reactive({from:new Date(Date.now()-90*86400000).toISOString().slice(0,10),to:new Date().toISOString().slice(0,10)});

const totals = computed(() => ({
  all: projects.value.length,
  up: projects.value.filter((item) => item.enabled && item.lastStatus === "UP").length,
  attention: projects.value.filter((item) => item.enabled && !["UP", "PENDING"].includes(item.lastStatus)).length,
  pending: projects.value.filter((item) => item.enabled && item.lastStatus === "PENDING").length
}));
const canWrite=computed(()=>["ADMIN","OPERATOR"].includes(session.value?.user?.role??""));const isAdmin=computed(()=>session.value?.user?.role==="ADMIN");
const statusTimeline = computed(() => [...heartbeats.value].reverse().slice(-48));
const chartBeats = computed(() => [...heartbeats.value].reverse().slice(-100));
const chartPoints = computed(() => {
  const values = chartBeats.value.map((item) => item.responseTimeMs);
  if (!values.length) return "";
  const max = Math.max(...values, 1); const min = Math.min(...values); const range = Math.max(max - min, 1);
  return values.map((value, index) => `${values.length === 1 ? 50 : index / (values.length - 1) * 1000},${210 - ((value - min) / range) * 175}`).join(" ");
});

async function loadSession() {
  session.value = await api<Session>("/api/session");
  loginProviders.value=await api<OidcProvider[]>("/api/auth/oidc/providers");
  if(session.value.user?.locale)setLocale(session.value.user.locale);
  if(session.value.user?.mfaRequired&&!session.value.user.mfaEnabled){await startMfaSetup();return}
  if (session.value.authenticated) await Promise.all([loadProjects(), loadNotifications(), loadIncidents(), loadDeliveries(), loadStatusSettings(), loadRegional(), loadMfaPolicy(), loadShareDashboards(), loadAudit(),loadInfrastructure(),loadVulnerabilities(),loadUsers(),loadOidcProviders(),loadHealth()]);
}

async function authenticate(setup: boolean) {
  error.value = "";
  busy.value = true;
  try {
    const result=await api<{mfaRequired?:boolean;challengeToken?:string}>(setup ? "/api/setup" : "/api/auth/login", {
      method: "POST", body: JSON.stringify(credentials)
    });
    if(result.mfaRequired&&result.challengeToken){mfaChallenge.value=result.challengeToken;mfaCode.value="";return}
    session.value = await api<Session>("/api/session");
    if(session.value.user?.mfaRequired&&!session.value.user.mfaEnabled){await startMfaSetup();return}
    await Promise.all([loadProjects(), loadNotifications(), loadIncidents(), loadDeliveries(), loadShareDashboards(), loadAudit(),loadInfrastructure(),loadVulnerabilities(),loadUsers(),loadRegional(),loadHealth()]);
  } catch (value) {
    error.value = value instanceof Error ? value.message : "Authentication failed";
  } finally { busy.value = false; }
}
async function completeMfa(){busy.value=true;error.value="";try{await api("/api/auth/mfa",{method:"POST",body:JSON.stringify({challengeToken:mfaChallenge.value,code:mfaCode.value})});mfaChallenge.value="";session.value=await api<Session>("/api/session");await Promise.all([loadProjects(),loadNotifications(),loadIncidents(),loadDeliveries(),loadShareDashboards(),loadAudit(),loadInfrastructure(),loadVulnerabilities(),loadUsers(),loadRegional(),loadHealth()])}catch(value){error.value=value instanceof Error?value.message:"MFA failed"}finally{busy.value=false}}

async function logout() {
  await api("/api/auth/logout", { method: "POST" });
  projects.value = [];
  session.value = { configured: true, authenticated: false };
}

async function loadProjects() {
  try { projects.value = await api<Project[]>("/api/projects"); }
  catch (value) { if (value instanceof ApiError && value.status === 401) await loadSession(); }
}

async function loadNotifications() {
  notifications.value = await api<Notification[]>("/api/notifications");
}
async function loadIncidents() { incidents.value = await api<Incident[]>("/api/incidents"); }
async function loadDeliveries() { deliveries.value = await api<Delivery[]>("/api/notification-deliveries"); }
async function loadShareDashboards() { shareDashboards.value = await api<ShareDashboard[]>("/api/share-dashboards"); }
function auditQuery(){return `from=${encodeURIComponent(new Date(`${auditRange.from}T00:00:00.000Z`).toISOString())}&to=${encodeURIComponent(new Date(`${auditRange.to}T23:59:59.999Z`).toISOString())}`}
async function loadAudit() { const [overview,controls,settings,workspace,backupRows,restoreRows,schedules,reports,connectors,channels,deliveryRows]=await Promise.all([api<AuditOverview>("/api/audit/overview"),api<IsoControl[]>("/api/audit/controls"),api<{retentionDays:number}>("/api/audit/settings"),api<AuditWorkspace>(`/api/audit/workspace?${auditQuery()}`),api<BackupEvidence[]>("/api/backup-evidence"),api<RestoreTest[]>("/api/restore-tests"),api<ReportSchedule[]>("/api/report-schedules"),api<GeneratedReport[]>("/api/generated-reports"),api<BackupConnector[]>("/api/backup-connectors"),api<ReportDeliveryChannel[]>("/api/report-delivery-channels"),api<ReportDelivery[]>("/api/report-deliveries")]);auditOverview.value=overview;isoControls.value=controls;auditRetentionDays.value=settings.retentionDays;auditWorkspace.value=workspace;backups.value=backupRows;restoreTests.value=restoreRows;reportSchedules.value=schedules;generatedReports.value=reports;backupConnectors.value=connectors;reportDeliveryChannels.value=channels;reportDeliveries.value=deliveryRows; }
const health = ref<HealthStatus | null>(null);
const healthEditing = ref<number | null>(null);
const healthRunning = ref(false);
const healthRunResult=ref<{checkedAt:string;checkedMonitors:number;skippedMonitors:number;errors:unknown[]}|null>(null);
const healthRunMessage=computed(()=>{const result=healthRunResult.value;if(!result)return "";return thai.value?`ตรวจเสร็จ ${displayDate(result.checkedAt)} · ตรวจ ${result.checkedMonitors} มอนิเตอร์ · กำลังตรวจอยู่แล้ว ${result.skippedMonitors} · ข้อผิดพลาด ${result.errors.length}`:`Checked ${displayDate(result.checkedAt)} · ${result.checkedMonitors} monitors · ${result.skippedMonitors} already running · ${result.errors.length} errors`;});
async function runHealthNow() {
  healthRunning.value=true; error.value=""; healthRunResult.value=null;
  try {
    const result=await api<{checkedAt:string;checkedMonitors:number;skippedMonitors:number;errors:unknown[];health:HealthStatus}>("/api/health/run",{method:"POST"});
    health.value=result.health;
    healthRunResult.value=result;
    await Promise.all([loadProjects(),loadIncidents(),loadInfrastructure()]);
  } catch(value) {error.value=value instanceof Error?value.message:"Health check failed";}
  finally {healthRunning.value=false;}
}
const thai = computed(() => locale.value === "th-TH");
const unitText = (value: number | null, unit: string) => (value === null ? "—" : `${value}${unit === "%" || unit === "x" ? "" : " "}${ui(unit)}`);
function healthThreshold(value:string){return value.replace(/\b(days|min|s)\b/g,unit=>ui(unit))}
const logSourcesText = ref("");
async function loadHealth() { health.value = await api<HealthStatus>("/api/health"); if (document.activeElement?.id !== "log-sources") logSourcesText.value = health.value.expectedLogSources.join(", "); }
async function saveLogSources() {
  busy.value = true; error.value = "";
  try { await api("/api/health/log-sources", { method: "PUT", body: JSON.stringify({ sources: logSourcesText.value.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) }) }); await loadHealth(); }
  catch (value) { error.value = value instanceof Error ? value.message : "Unable to save log sources"; } finally { busy.value = false; }
}
async function saveHealthPolicy(item: HealthItem) {
  busy.value = true; error.value = "";
  try { await api(`/api/health/policies/${item.no}`, { method: "PUT", body: JSON.stringify({ warningValue: item.warningValue, criticalValue: item.criticalValue, durationSeconds: item.durationSeconds, enabled: item.enabled }) }); healthEditing.value = null; await loadHealth(); }
  catch (value) { error.value = value instanceof Error ? value.message : "Unable to save policy"; } finally { busy.value = false; }
}
async function toggleHelpDesk(item: Notification) { await api(`/api/notifications/${item.id}/help-desk`, { method: "PUT", body: JSON.stringify({ helpDesk: !item.helpDesk }) }); await loadNotifications(); }
async function loadInfrastructure(){[agents.value,findings.value]=await Promise.all([api<AgentHost[]>("/api/agents"),api<Finding[]>("/api/action-required")]);}
async function loadVulnerabilities(){[vulnerabilities.value,vulnerabilityScans.value,vulnerabilityScanJobs.value,scanProfiles.value,scanSchedules.value,threatIntelStatus.value]=await Promise.all([api<Vulnerability[]>("/api/vulnerabilities"),api<VulnerabilityScan[]>("/api/vulnerability-scans"),api<VulnerabilityScanJob[]>("/api/vulnerability-scan-jobs"),api<ScanProfile[]>("/api/vulnerability-scan-profiles"),api<ScanSchedule[]>("/api/vulnerability-scan-schedules"),api<ThreatIntelStatus|null>("/api/threat-intelligence/status")]);}
async function syncThreatIntel(){busy.value=true;error.value="";try{await api("/api/threat-intelligence/sync",{method:"POST"});await loadVulnerabilities()}catch(value){error.value=value instanceof Error?value.message:"Unable to synchronize threat intelligence"}finally{busy.value=false}}
async function loadUsers(){if(isAdmin.value)users.value=await api<AppUser[]>("/api/users")}
async function loadOidcProviders(){if(isAdmin.value)oidcProviders.value=await api<OidcProvider[]>("/api/oidc/providers")}
function openOidcCreate(){Object.assign(oidcForm,{name:"",preset:"GENERIC",issuerUrl:"",clientId:"",clientSecret:"",scopes:"openid email profile",usernameClaim:"email",groupsClaim:"groups",allowedDomains:"",roleMapping:"{}",defaultRole:"VIEWER",jitProvisioning:true,enabled:true});showOidcForm.value=true}
async function saveOidcProvider(){busy.value=true;error.value="";try{const roleMapping=JSON.parse(oidcForm.roleMapping||"{}");const result=await api<{callbackUrl:string}>("/api/oidc/providers",{method:"POST",body:JSON.stringify({...oidcForm,allowedDomains:oidcForm.allowedDomains.split(",").map(x=>x.trim()).filter(Boolean),roleMapping})});showOidcForm.value=false;await loadOidcProviders();alert(thai.value?`บันทึก SSO แล้ว นำ Callback URL นี้ไปลงทะเบียนกับผู้ให้บริการ:\n${result.callbackUrl}`:`SSO provider saved. Register this callback URL in your IdP:\n${result.callbackUrl}`)}catch(value){error.value=value instanceof Error?value.message:"Unable to save SSO provider"}finally{busy.value=false}}
async function disableOidcProvider(item:OidcProvider){if(!confirm(thai.value?`ปิดผู้ให้บริการ SSO ${item.name} หรือไม่?`:`Disable SSO provider ${item.name}?`))return;await api(`/api/oidc/providers/${item.id}`,{method:"DELETE"});await loadOidcProviders()}
function openAgentCreate(){agentForm.name="";enrollmentToken.value="";showAgentForm.value=true}
async function createAgent(){busy.value=true;try{const value=await api<{token:string}>("/api/agents",{method:"POST",body:JSON.stringify(agentForm)});enrollmentToken.value=value.token;await loadInfrastructure()}finally{busy.value=false}}
async function revokeAgent(item:AgentHost){const action=item.lastSeenAt?"Revoke and archive":"Remove unused enrollment";if(!confirm(thai.value?`${ui(action)} ${item.name} หรือไม่? รายการจะถูกซ่อนแต่ยังเก็บหลักฐานออดิทเดิมไว้`:`${action} ${item.name}? The row will disappear, while existing audit evidence remains preserved.`))return;try{await api(`/api/agents/${item.id}`,{method:"DELETE"});await Promise.all([loadInfrastructure(),loadVulnerabilities()])}catch(value){error.value=value instanceof Error?value.message:"Unable to remove agent"}}
async function copyAgentToken(){await navigator.clipboard.writeText(enrollmentToken.value)}
async function copyAgentInstallCommand(){await navigator.clipboard.writeText(agentInstallCommand.value)}
function editFinding(item:Finding){selectedFinding.value=item;Object.assign(findingForm,{id:item.id,title:findingTitle(item),agentName:item.agentName??"",hostname:item.hostname??"",status:item.status,owner:item.owner??"",dueAt:item.dueAt?.slice(0,16)??"",resolutionNote:item.resolutionNote??""});showFindingForm.value=true}
async function saveFinding(){busy.value=true;error.value="";try{await api(`/api/findings/${findingForm.id}`,{method:"PUT",body:JSON.stringify({status:findingForm.status,owner:findingForm.owner||null,dueAt:findingForm.dueAt?new Date(findingForm.dueAt).toISOString():null,resolutionNote:findingForm.resolutionNote||null})});showFindingForm.value=false;await Promise.all([loadInfrastructure(),loadAudit()])}catch(value){error.value=value instanceof Error?value.message:"Unable to save finding"}finally{busy.value=false}}
function openBackupCreate(){Object.assign(backupForm,{assetName:"",backupType:"DATABASE",storageLocation:"",status:"SUCCESS",startedAt:new Date().toISOString().slice(0,16),completedAt:new Date().toISOString().slice(0,16),sizeBytes:null,checksum:"",notes:""});showBackupForm.value=true}
async function saveBackup(){busy.value=true;try{await api("/api/backup-evidence",{method:"POST",body:JSON.stringify({...backupForm,startedAt:new Date(backupForm.startedAt).toISOString(),completedAt:backupForm.completedAt?new Date(backupForm.completedAt).toISOString():null,checksum:backupForm.checksum||null,notes:backupForm.notes||null})});showBackupForm.value=false;await loadAudit()}finally{busy.value=false}}
function openRestoreCreate(){Object.assign(restoreForm,{backupEvidenceId:null,assetName:"",testScope:"Full recovery validation",result:"PASS",testedAt:new Date().toISOString().slice(0,16),rtoMinutes:null,actualMinutes:null,evidenceNote:""});showRestoreForm.value=true}
async function saveRestore(){busy.value=true;try{await api("/api/restore-tests",{method:"POST",body:JSON.stringify({...restoreForm,testedAt:new Date(restoreForm.testedAt).toISOString(),evidenceNote:restoreForm.evidenceNote||null})});showRestoreForm.value=false;await loadAudit()}finally{busy.value=false}}
function editVulnerability(item:Vulnerability){Object.assign(vulnerabilityForm,{id:item.id,title:`${item.vulnerabilityId} · ${item.packageName}`,status:item.status,owner:item.owner??"",dueAt:item.dueAt?.slice(0,16)??"",riskReason:item.riskReason??"",riskExpiresAt:item.riskExpiresAt?.slice(0,16)??""});showVulnerabilityForm.value=true}
async function saveVulnerability(){busy.value=true;try{await api(`/api/vulnerabilities/${vulnerabilityForm.id}`,{method:"PUT",body:JSON.stringify({status:vulnerabilityForm.status,owner:vulnerabilityForm.owner||null,dueAt:vulnerabilityForm.dueAt?new Date(vulnerabilityForm.dueAt).toISOString():null,riskReason:vulnerabilityForm.riskReason||null,riskExpiresAt:vulnerabilityForm.riskExpiresAt?new Date(vulnerabilityForm.riskExpiresAt).toISOString():null})});showVulnerabilityForm.value=false;await loadVulnerabilities()}finally{busy.value=false}}
function compatibleScanProfiles(agentId:number){const agent=agents.value.find(x=>x.id===agentId),windows=/windows/i.test(agent?.osName??"");return scanProfiles.value.filter(profile=>!(windows&&profile.targetType==="ROOTFS"))}
function ensureCompatibleScanProfile(){const profile=compatibleScanProfiles(scanJobForm.agentId).find(x=>x.id===scanJobForm.profileId)??compatibleScanProfiles(scanJobForm.agentId)[0];if(profile)applyScanProfile(profile.id)}
function openScanJob(){const activeAgent=agents.value.find(x=>x.enabled);if(!activeAgent){activeView.value="agents";openAgentCreate();return}const profile=compatibleScanProfiles(activeAgent.id)[0];Object.assign(scanJobForm,{agentId:activeAgent.id,profileId:profile?.id,targetType:profile?.targetType??"FILESYSTEM",target:profile?.targetType==="IMAGE"?"alpine:latest":"/",scanners:profile?.scanners??["vuln"],severity:profile?.severity??["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"]});showScanJobForm.value=true}
async function createScanJob(){busy.value=true;error.value="";try{await api("/api/vulnerability-scan-jobs",{method:"POST",body:JSON.stringify(scanJobForm)});showScanJobForm.value=false;await loadVulnerabilities()}catch(value){error.value=value instanceof Error?value.message:"Unable to queue scan"}finally{busy.value=false}}
async function cancelScanJob(item:VulnerabilityScanJob){if(!confirm(thai.value?`ยกเลิกงานสแกน #${item.id} หรือไม่?`:`Cancel scan job #${item.id}?`))return;await api(`/api/vulnerability-scan-jobs/${item.id}/cancel`,{method:"POST"});await loadVulnerabilities()}
async function archiveScanJob(item:VulnerabilityScanJob){if(!confirm(thai.value?`ซ่อนงานสแกน #${item.id} จากรายการหรือไม่? ระบบยังเก็บหลักฐานออดิทไว้`:`Remove scan job #${item.id} from this list? Audit evidence will be preserved.`))return;await api(`/api/vulnerability-scan-jobs/${item.id}`,{method:"DELETE"});await loadVulnerabilities()}
async function showScanJobResult(item:VulnerabilityScanJob){selectedScanJob.value=await api<ScanJobDetail>(`/api/vulnerability-scan-jobs/${item.id}`)}
function applyScanProfile(profileId:number){const profile=scanProfiles.value.find(x=>x.id===profileId);if(!profile)return;Object.assign(scanJobForm,{profileId:profile.id,targetType:profile.targetType,target:profile.targetType==="IMAGE"?"alpine:latest":"/",scanners:[...profile.scanners],severity:[...profile.severity]})}
function openScanSchedule(){const activeAgent=agents.value.find(x=>x.enabled);if(!activeAgent){activeView.value="agents";openAgentCreate();return}const profile=scanProfiles.value[0];Object.assign(scanScheduleForm,{name:"Daily security scan",agentId:activeAgent.id,profileId:profile?.id??0,target:profile?.targetType==="IMAGE"?"alpine:latest":"/",frequency:"DAILY",firstRunAt:new Date(Date.now()+300000).toISOString().slice(0,16)});showScanScheduleForm.value=true}
function applyScheduleProfile(profileId:number){const profile=scanProfiles.value.find(x=>x.id===profileId);scanScheduleForm.target=profile?.targetType==="IMAGE"?"alpine:latest":"/"}
async function createScanSchedule(){busy.value=true;error.value="";try{await api("/api/vulnerability-scan-schedules",{method:"POST",body:JSON.stringify({...scanScheduleForm,firstRunAt:scanScheduleForm.firstRunAt?new Date(scanScheduleForm.firstRunAt).toISOString():undefined})});showScanScheduleForm.value=false;await loadVulnerabilities()}catch(value){error.value=value instanceof Error?value.message:"Unable to create schedule"}finally{busy.value=false}}
async function disableScanSchedule(item:ScanSchedule){if(!confirm(thai.value?`ลบตารางสแกน ${item.name} หรือไม่? ยังเก็บหลักฐานสแกนเดิมไว้`:`Delete schedule ${item.name}? Existing scan evidence will be preserved.`))return;try{await api(`/api/vulnerability-scan-schedules/${item.id}`,{method:"DELETE"});await loadVulnerabilities()}catch(value){error.value=value instanceof Error?value.message:"Unable to delete schedule"}}
function openScanProfile(){Object.assign(scanProfileForm,{name:"",description:"",targetType:"FILESYSTEM",scanners:["vuln"],severity:["HIGH","CRITICAL"],timeoutSeconds:900});error.value="";showScanProfileForm.value=true}
async function createScanProfile(){busy.value=true;error.value="";try{await api("/api/vulnerability-scan-profiles",{method:"POST",body:JSON.stringify(scanProfileForm)});showScanProfileForm.value=false;await loadVulnerabilities()}catch(value){error.value=value instanceof Error?value.message:"Unable to create scan profile"}finally{busy.value=false}}
async function disableScanProfile(item:ScanProfile){if(item.systemProfile||!confirm(thai.value?`ลบโปรไฟล์ที่สร้างเอง ${item.name} หรือไม่? ยังเก็บหลักฐานเดิมไว้`:`Delete custom profile ${item.name}? Existing scan evidence will be preserved.`))return;try{await api(`/api/vulnerability-scan-profiles/${item.id}`,{method:"DELETE"});await loadVulnerabilities()}catch(value){error.value=value instanceof Error?value.message:"Unable to delete scan profile"}}
function openUserCreate(){Object.assign(userForm,{id:0,username:"",password:"",role:"VIEWER",enabled:true,mfaEnabled:false});showUserForm.value=true}
function editUser(item:AppUser){Object.assign(userForm,{id:item.id,username:item.username,password:"",role:item.role,enabled:item.enabled,mfaEnabled:item.mfaEnabled});showUserForm.value=true}
async function saveUser(){busy.value=true;error.value="";try{if(userForm.id)await api(`/api/users/${userForm.id}`,{method:"PUT",body:JSON.stringify({role:userForm.role,enabled:userForm.enabled,...(userForm.password?{password:userForm.password}:{})})});else await api("/api/users",{method:"POST",body:JSON.stringify({username:userForm.username,password:userForm.password,role:userForm.role})});showUserForm.value=false;await loadUsers()}catch(value){error.value=value instanceof Error?value.message:"Unable to save user"}finally{busy.value=false}}
function exportAuditUrl(){return `/api/audit/export?${auditQuery()}`}
function auditReportUrl(format:"pdf"|"xlsx"){return `/api/audit/report.${format}?${auditQuery()}`}
function openReportSchedule(){Object.assign(reportScheduleForm,{name:"Monthly ISO evidence pack",frequency:"MONTHLY",formats:["PDF","XLSX"],periodDays:30,deliveryChannelIds:[],enabled:true});showReportScheduleForm.value=true}
async function saveReportSchedule(){busy.value=true;try{await api("/api/report-schedules",{method:"POST",body:JSON.stringify(reportScheduleForm)});showReportScheduleForm.value=false;await loadAudit()}finally{busy.value=false}}
async function disableReportSchedule(item:ReportSchedule){if(!confirm(thai.value?`ปิดตารางรายงาน ${item.name} หรือไม่?`:`Disable schedule ${item.name}?`))return;await api(`/api/report-schedules/${item.id}`,{method:"DELETE"});await loadAudit()}
function deliveryPayload(){return reportDeliveryForm.type==="SMTP"?{name:reportDeliveryForm.name,type:"SMTP",host:reportDeliveryForm.host,port:reportDeliveryForm.port,secure:reportDeliveryForm.secure,username:reportDeliveryForm.username||undefined,password:reportDeliveryForm.password||undefined,from:reportDeliveryForm.from,recipients:reportDeliveryForm.recipients.split(",").map(x=>x.trim()).filter(Boolean)}:{name:reportDeliveryForm.name,type:"S3",endpoint:reportDeliveryForm.endpoint||undefined,region:reportDeliveryForm.region,bucket:reportDeliveryForm.bucket,prefix:reportDeliveryForm.prefix,accessKeyId:reportDeliveryForm.accessKeyId,secretAccessKey:reportDeliveryForm.secretAccessKey,forcePathStyle:reportDeliveryForm.forcePathStyle,wormMode:reportDeliveryForm.wormMode,retentionDays:reportDeliveryForm.retentionDays,legalHold:reportDeliveryForm.legalHold}}
function openReportDelivery(){Object.assign(reportDeliveryForm,{name:"",type:"SMTP",host:"",port:587,secure:false,username:"",password:"",from:"",recipients:"",endpoint:"",region:"ap-southeast-1",bucket:"",prefix:"byakugan-audit",accessKeyId:"",secretAccessKey:"",forcePathStyle:false,wormMode:"NONE",retentionDays:365,legalHold:false});showReportDeliveryForm.value=true}
async function testReportDelivery(){busy.value=true;error.value="";try{const result=await api<{destination:string}>("/api/report-delivery-channels/test",{method:"POST",body:JSON.stringify(deliveryPayload())});alert(thai.value?`เชื่อมต่อสำเร็จ: ${result.destination}`:`Connection successful: ${result.destination}`)}catch(value){error.value=value instanceof Error?value.message:"Channel test failed"}finally{busy.value=false}}
async function saveReportDelivery(){busy.value=true;error.value="";try{await api("/api/report-delivery-channels",{method:"POST",body:JSON.stringify(deliveryPayload())});showReportDeliveryForm.value=false;await loadAudit()}catch(value){error.value=value instanceof Error?value.message:"Unable to save delivery channel"}finally{busy.value=false}}
async function disableReportDelivery(item:ReportDeliveryChannel){if(!confirm(thai.value?`ปิดช่องทางส่งรายงาน ${item.name} หรือไม่?`:`Disable delivery channel ${item.name}?`))return;await api(`/api/report-delivery-channels/${item.id}`,{method:"DELETE"});await loadAudit()}
function openBackupConnector(){Object.assign(backupConnectorForm,{name:"",assetName:"",backupType:"DATABASE",maxAgeHours:24});backupConnectorToken.value="";showBackupConnectorForm.value=true}
async function saveBackupConnector(){busy.value=true;try{const value=await api<{token:string}>("/api/backup-connectors",{method:"POST",body:JSON.stringify(backupConnectorForm)});backupConnectorToken.value=value.token;await loadAudit()}finally{busy.value=false}}
async function revokeBackupConnector(item:BackupConnector){if(!confirm(thai.value?`เพิกถอนตัวเชื่อม ${item.name} หรือไม่?`:`Revoke connector ${item.name}?`))return;await api(`/api/backup-connectors/${item.id}`,{method:"DELETE"});await loadAudit()}
function editIncident(item:Incident){selectedIncident.value=item;Object.assign(incidentForm,{id:item.id,title:`${item.projectName} · ${displayDate(item.startedAt)}`,severity:item.severity,owner:item.owner??"",rootCause:item.rootCause??"",correctiveAction:item.correctiveAction??"",lessonsLearned:item.lessonsLearned??"",reviewStatus:item.reviewStatus,closedAt:item.closedAt});showIncidentForm.value=true}
async function saveIncident(closeCase=false){busy.value=true;error.value="";try{const{id,title,closedAt,...body}=incidentForm;void title;void closedAt;await api(`/api/incidents/${id}/review`,{method:"PUT",body:JSON.stringify({...body,closeCase,reviewStatus:closeCase?"APPROVED":body.reviewStatus,owner:body.owner||null,rootCause:body.rootCause||null,correctiveAction:body.correctiveAction||null,lessonsLearned:body.lessonsLearned||null})});showIncidentForm.value=false;await Promise.all([loadIncidents(),loadAudit()])}catch(value){error.value=value instanceof Error?value.message:"Unable to save incident"}finally{busy.value=false}}
async function startMfaSetup(){mfaSetup.value=await api<{secret:string;uri:string;qrDataUrl:string}>("/api/mfa/setup",{method:"POST"});mfaRecoveryCodes.value=[];mfaCode.value="";showMfaForm.value=true}
async function enableMfa(){const result=await api<{recoveryCodes:string[]}>("/api/mfa/enable",{method:"POST",body:JSON.stringify({code:mfaCode.value})});mfaRecoveryCodes.value=result.recoveryCodes;session.value=await api<Session>("/api/session");await Promise.all([loadProjects(),loadNotifications(),loadIncidents(),loadDeliveries(),loadStatusSettings(),loadRegional(),loadMfaPolicy(),loadShareDashboards(),loadAudit(),loadInfrastructure(),loadVulnerabilities(),loadUsers(),loadRegional(),loadHealth()])}
async function copyRecoveryCodes(){await navigator.clipboard.writeText(mfaRecoveryCodes.value.join("\n"))}
async function regenerateRecoveryCodes(){const code=prompt("Enter the current 6-digit authenticator code");if(!code)return;const result=await api<{recoveryCodes:string[]}>("/api/mfa/recovery-codes",{method:"POST",body:JSON.stringify({code})});mfaSetup.value={secret:"",uri:"",qrDataUrl:""};mfaRecoveryCodes.value=result.recoveryCodes;showMfaForm.value=true}
async function resetUserMfa(){if(!userForm.id||!confirm(thai.value?`รีเซ็ต MFA ของ ${userForm.username} หรือไม่? ตัวยืนยันและรหัสกู้คืนเดิมจะใช้ไม่ได้`:`Reset MFA for ${userForm.username}? Existing authenticator and recovery codes will stop working.`))return;await api(`/api/users/${userForm.id}/mfa`,{method:"DELETE"});userForm.mfaEnabled=false;await loadUsers()}
async function loadMfaPolicy(){if(!isAdmin.value)return;mfaRequiredRoles.value=(await api<{requiredRoles:Array<AppUser["role"]> }>("/api/security/mfa-policy")).requiredRoles}
async function saveMfaPolicy(){await api("/api/security/mfa-policy",{method:"PUT",body:JSON.stringify({requiredRoles:mfaRequiredRoles.value})});alert(ui("MFA enforcement policy saved"))}
async function disableMfa(){const code=prompt("Enter the current 6-digit authenticator code");if(!code)return;await api("/api/mfa/disable",{method:"POST",body:JSON.stringify({code})});session.value=await api<Session>("/api/session")}
async function saveAuditSettings(){await api("/api/audit/settings",{method:"PUT",body:JSON.stringify({retentionDays:auditRetentionDays.value})});await loadAudit();alert(ui("Audit retention policy saved"));}
function openAuditProfile(asset:AuditAsset){ Object.assign(auditForm,{...asset,assetTag:asset.assetTag??"",assetOwner:asset.assetOwner??""});showAuditForm.value=true; }
async function saveAuditProfile(){busy.value=true;try{const {id,name,...body}=auditForm;void name;await api(`/api/audit/projects/${id}`,{method:"PUT",body:JSON.stringify(body)});showAuditForm.value=false;await loadAudit();}catch(value){error.value=value instanceof Error?value.message:"Unable to save audit profile"}finally{busy.value=false}}

function openShareCreate() {
  shareForm.name = ""; shareForm.selections = {};
  for (const project of projects.value) shareForm.selections[project.id] = { selected: false, groupName: "Services" };
  showShareForm.value = true;
}
async function saveShareDashboard() {
  const selectedProjects = projects.value.filter((project) => shareForm.selections[project.id]?.selected)
    .map((project) => ({ projectId: project.id, groupName: shareForm.selections[project.id].groupName || "Services" }));
  if (!selectedProjects.length) { error.value = "Select at least one monitor"; return; }
  busy.value = true; error.value = "";
  try { await api("/api/share-dashboards", { method: "POST", body: JSON.stringify({ name: shareForm.name, projects: selectedProjects }) }); showShareForm.value = false; await loadShareDashboards(); }
  catch (value) { error.value = value instanceof Error ? value.message : "Unable to create shared dashboard"; }
  finally { busy.value = false; }
}
async function removeShareDashboard(page: ShareDashboard) {
  if (!confirm(thai.value?`เพิกถอนแดชบอร์ด ${page.name} หรือไม่? ลิงก์จะใช้ไม่ได้ทันที`:`Revoke shared dashboard ${page.name}? The link will stop working immediately.`)) return;
  await api(`/api/share-dashboards/${page.id}`, { method: "DELETE" }); await loadShareDashboards();
}
async function copyShareLink(page: ShareDashboard) {
  try { await navigator.clipboard.writeText(`${window.location.origin}${page.sharePath}`); }
  catch { prompt("Copy shared link", `${window.location.origin}${page.sharePath}`); }
}

function resetForm() {
  editingId.value = null;
  Object.assign(form, { name: "", monitorType: "SUPABASE", supabaseUrl: "", publishableKey: "",
    target: "", httpMethod: "GET", ignoreTlsErrors: false, expectedStatus: null, keyword: "", tcpHost: "", tcpPort: null,
    intervalSeconds: 21600, timeoutSeconds: 15, retryCount: 2, enabled: true, maintenance: false,
    notificationIds: [] });
  Object.assign(form, { dnsRecordType: "A", sslPort: 443, sslExpiryDays: 14, dockerContainer: "", published: false,databaseEngine:"POSTGRESQL",connectionString:"" });
}

function openCreate() { resetForm(); copiedSetupSql.value = false; showProjectForm.value = true; }
async function openEdit(project: Project) {
  editingId.value = project.id;
  const links = await api<Array<{ notificationId: number }>>(`/api/projects/${project.id}/notifications`);
  Object.assign(form, { name: project.name, monitorType: project.monitorType, supabaseUrl: project.monitorType === "SUPABASE" ? project.supabaseUrl : "", publishableKey: "",
    target: project.target ?? "", httpMethod: project.httpMethod, expectedStatus: project.expectedStatus,
    ignoreTlsErrors: project.ignoreTlsErrors, keyword: project.keyword ?? "", tcpHost: project.tcpHost ?? "", tcpPort: project.tcpPort,
    intervalSeconds: project.intervalSeconds, timeoutSeconds: project.timeoutSeconds,
    retryCount: project.retryCount, enabled: project.enabled, maintenance: project.maintenance,
    notificationIds: links.map((link) => link.notificationId) });
  Object.assign(form, { dnsRecordType: project.dnsRecordType, sslPort: project.sslPort, sslExpiryDays: project.sslExpiryDays,
    dockerContainer: project.dockerContainer ?? "", published: project.published,databaseEngine:project.databaseEngine??"POSTGRESQL",connectionString:"" });
  showProjectForm.value = true;
}

async function saveProject() {
  error.value = "";
  busy.value = true;
  try {
    const body: Record<string, unknown> = { ...form };
    delete body.notificationIds;
    if (form.monitorType !== "SUPABASE") { delete body.supabaseUrl; delete body.publishableKey; }
    if (form.monitorType !== "HTTP") { delete body.target; delete body.expectedStatus; delete body.keyword; delete body.ignoreTlsErrors; }
    if (form.monitorType !== "TCP") { delete body.tcpHost; delete body.tcpPort; }
    if (!["HTTP", "PING", "DNS", "SSL", "WEBSOCKET"].includes(form.monitorType)) delete body.target;
    if (form.monitorType !== "DNS") delete body.dnsRecordType;
    if (form.monitorType !== "SSL") { delete body.sslPort; delete body.sslExpiryDays; }
    if (form.monitorType !== "DOCKER") delete body.dockerContainer;
    if(form.monitorType!=="DATABASE"){delete body.databaseEngine;delete body.connectionString}
    if(editingId.value&&form.monitorType==="DATABASE"&&!form.connectionString)delete body.connectionString;
    if (editingId.value && !form.publishableKey) delete body.publishableKey;
    const saved = await api<Project>(editingId.value ? `/api/projects/${editingId.value}` : "/api/projects", {
      method: editingId.value ? "PATCH" : "POST", body: JSON.stringify(body)
    });
    await api(`/api/projects/${saved.id}/notifications`, { method: "PUT", body: JSON.stringify({ notificationIds: form.notificationIds }) });
    showProjectForm.value = false;
    resetForm();
    await loadProjects();
  } catch (value) { error.value = value instanceof Error ? value.message : "Unable to save project"; }
  finally { busy.value = false; }
}

function openNotificationCreate() {
  Object.assign(notificationForm, { name: "", type: "DISCORD", url: "", botToken: "", chatId: "", enabled: true });
  showNotificationForm.value = true;
}

async function testNotificationChannel() {
  error.value = "";
  busy.value = true;
  try {
    await api("/api/notifications/test", { method: "POST", body: JSON.stringify(notificationForm) });
    alert(ui("Test notification sent successfully"));
  } catch (value) { error.value = value instanceof Error ? value.message : "Notification test failed"; }
  finally { busy.value = false; }
}

async function saveNotification() {
  error.value = "";
  busy.value = true;
  try {
    await api("/api/notifications", { method: "POST", body: JSON.stringify(notificationForm) });
    showNotificationForm.value = false;
    await Promise.all([loadNotifications(), loadDeliveries()]);
  } catch (value) { error.value = value instanceof Error ? value.message : "Unable to save notification"; }
  finally { busy.value = false; }
}

async function removeNotification(item: Notification) {
  if (!confirm(thai.value?`ลบช่องทางแจ้งเตือน ${item.name} หรือไม่?`:`Delete notification channel ${item.name}?`)) return;
  await api(`/api/notifications/${item.id}`, { method: "DELETE" });
  await loadNotifications();
}

async function runProject(project: Project) {
  const next = new Set(running.value); next.add(project.id); running.value = next;
  try {
    await api(`/api/projects/${project.id}/run`, { method: "POST" });
    await Promise.all([loadProjects(), loadIncidents(), loadDeliveries()]);
    if (selected.value?.id === project.id) {
      selected.value = projects.value.find((item) => item.id === project.id) ?? selected.value;
      [heartbeats.value, monitorStats.value] = await Promise.all([
        api<Heartbeat[]>(`/api/projects/${project.id}/heartbeats?limit=500`), api<MonitorStats>(`/api/projects/${project.id}/stats`)
      ]);
      if(project.monitorType==="DATABASE")databaseMetrics.value=await api<DatabaseMetric[]>(`/api/projects/${project.id}/database-metrics`);
    }
  }
  catch (value) { error.value = value instanceof Error ? value.message : "Check failed"; }
  finally { const done = new Set(running.value); done.delete(project.id); running.value = done; }
}

async function removeProject(project: Project) {
  if (!confirm(thai.value?`ลบ ${project.name} พร้อมประวัติผลตรวจหรือไม่?`:`Delete ${project.name} and its heartbeat history?`)) return;
  await api(`/api/projects/${project.id}`, { method: "DELETE" });
  await loadProjects();
}

async function showHistory(project: Project) {
  selected.value = project;
  copiedSetupSql.value = false;
  [heartbeats.value, monitorStats.value] = await Promise.all([
    api<Heartbeat[]>(`/api/projects/${project.id}/heartbeats?limit=500`),
    api<MonitorStats>(`/api/projects/${project.id}/stats`)
  ]);
  databaseMetrics.value=project.monitorType==="DATABASE"?await api<DatabaseMetric[]>(`/api/projects/${project.id}/database-metrics`):[];
  activeView.value = "detail";
}

async function refreshMonitorDetail(){
  const project=selected.value;if(activeView.value!=="detail"||!project)return;
  const [beats,stats]=await Promise.all([api<Heartbeat[]>(`/api/projects/${project.id}/heartbeats?limit=500`),api<MonitorStats>(`/api/projects/${project.id}/stats`)]);
  if(activeView.value==="detail"&&selected.value?.id===project.id){heartbeats.value=beats;monitorStats.value=stats;selected.value=projects.value.find(item=>item.id===project.id)??selected.value;}
}
function monitorTarget(project: Project) {
  if (project.monitorType === "TCP") return `${project.tcpHost}:${project.tcpPort}`;
  if (project.monitorType === "DOCKER") return project.dockerContainer || "Docker container";
  if(project.monitorType==="DATABASE")return `${project.databaseEngine} database · credentials encrypted`;
  return project.target || project.supabaseUrl;
}

function formatMetric(value: number | null | undefined, suffix = "") { return value === null || value === undefined ? "—" : `${value}${suffix}`; }

function formatInterval(seconds: number) {
  if (seconds < 60) return `${seconds} ${ui("s")}`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} ${ui("min")}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} ${ui("h")}`;
  return `${Math.round(seconds / 60)} ${ui("min")}`;
}

function sparklinePoints(beats: SharedMonitor["heartbeats"]) {
  const recent = beats.slice(-60); if (!recent.length) return "";
  const values = recent.map((beat) => beat.responseTimeMs); const min = Math.min(...values); const max = Math.max(...values); const range = Math.max(max - min, 1);
  return values.map((value, index) => `${values.length === 1 ? 0 : index / (values.length - 1) * 500},${90 - (value - min) / range * 70}`).join(" ");
}

async function copySetupSql() {
  try {
    await navigator.clipboard.writeText(setupSql);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = setupSql;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
  copiedSetupSql.value = true;
  window.setTimeout(() => { copiedSetupSql.value = false; }, 2500);
}

function sqlEditorUrl(project: { supabaseUrl: string }) {
  try {
    const projectRef = new URL(project.supabaseUrl).hostname.split(".")[0];
    return `https://supabase.com/dashboard/project/${projectRef}/sql/new`;
  } catch {
    return "https://supabase.com/dashboard";
  }
}

function relative(value: string | null) {
  if (!value) return locale.value==="th-TH"?"ไม่เคย":"Never";
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  return new Intl.RelativeTimeFormat(locale.value,{numeric:"auto"}).format(-Math.round(Math.abs(seconds)<60?seconds:Math.abs(seconds)<3600?seconds/60:seconds/3600),Math.abs(seconds)<60?"second":Math.abs(seconds)<3600?"minute":"hour");
}
function displayDateOnly(value:string|null){if(!value)return "—";const timezone=regionalForm.userTimezone==="SYSTEM"?regionalForm.applicationTimezone:regionalForm.userTimezone;return new Intl.DateTimeFormat(locale.value,{dateStyle:"medium",calendar:"gregory",timeZone:timezone}).format(new Date(value))}
function displayDate(value:string|null){if(!value)return "—";const timezone=regionalForm.userTimezone==="SYSTEM"?regionalForm.applicationTimezone:regionalForm.userTimezone;return new Intl.DateTimeFormat(locale.value,{dateStyle:"medium",timeStyle:"medium",calendar:"gregory",timeZone:timezone}).format(new Date(value))}
function findingTranslationKey(item:Finding){const keys:Record<string,string>={"CPU usage is critical":"cpu","Memory usage is critical":"memory","Disk usage exceeds policy":"disk","Security updates are pending":"securityUpdates","Server reboot is required":"reboot","Container is stopped":"container"};return keys[item.title]}
function findingTitle(item:Finding){const key=findingTranslationKey(item);return key?t(`actions.titles.${key}`):item.title}
function findingExplanation(item:Finding){if(locale.value!=="th-TH")return item.explanation;const cpu=item.explanation.match(/^CPU is ([\d.]+)% \(threshold ([\d.]+)%\)$/),memory=item.explanation.match(/^Memory is ([\d.]+)% \(threshold ([\d.]+)%\)$/),updates=item.explanation.match(/^(\d+) security update\(s\) pending$/);if(cpu)return`CPU ใช้งาน ${cpu[1]}% (ค่าเกณฑ์ ${cpu[2]}%)`;if(memory)return`หน่วยความจำใช้งาน ${memory[1]}% (ค่าเกณฑ์ ${memory[2]}%)`;if(updates)return`มีอัปเดตความปลอดภัยรอติดตั้ง ${updates[1]} รายการ`;const key=findingTranslationKey(item);return key?t(`actions.details.${key}`):item.explanation}

onMounted(async () => {
  const ssoError=new URLSearchParams(window.location.search).get("sso_error");if(ssoError){error.value=ssoError;history.replaceState({},"",window.location.pathname)}
  if (isSharePage) { sharedPage.value = await api<SharedPage>(`/api/share/${shareToken}`); pollTimer=window.setInterval(()=>{void api<SharedPage>(`/api/share/${shareToken}`).then(value=>sharedPage.value=value).catch(()=>undefined)},30000); return; }
  if (isPublicPage) { publicStatus.value = await api<PublicStatus>("/api/public/status"); pollTimer=window.setInterval(()=>{void api<PublicStatus>("/api/public/status").then(value=>publicStatus.value=value).catch(()=>undefined)},30000); return; }
  await loadSession();
  pollTimer = window.setInterval(() => { if (session.value?.authenticated) { void loadProjects().then(refreshMonitorDetail).catch(()=>undefined); void loadInfrastructure(); void loadIncidents(); if(activeView.value==="vulnerabilities")void loadVulnerabilities(); if(activeView.value==="health"&&healthEditing.value===null)void loadHealth(); } }, 15_000);
});

const languageSaving=ref(false);
async function changeLanguage(value:Locale){
  const previous=locale.value;languageSaving.value=true;
  try{if(session.value?.authenticated){await api("/api/settings/preferences",{method:"PUT",body:JSON.stringify({locale:value,timezone:regionalForm.userTimezone})});if(session.value.user)session.value.user.locale=value;regionalForm.userLocale=value;}setLocale(value);error.value="";}
  catch(e){setLocale(previous);error.value=e instanceof Error?e.message:"Unable to change language";}
  finally{languageSaving.value=false;}
}
function hasCertificate(project:Project){if(project.monitorType==='SSL')return true;try{return ['https:','wss:'].includes(new URL(project.monitorType==='SUPABASE'?project.supabaseUrl:project.target??'').protocol)}catch{return false}}
const certificateProjects=computed(()=>projects.value.filter(hasCertificate));
function openCertificateCreate(){openCreate();form.monitorType='SSL';}
async function loadStatusSettings() {
  const value = await api<{ title: string }>("/api/settings/status-page"); statusTitle.value = value.title;
}
async function loadRegional(){regional.value=await api<RegionalSettings>("/api/settings/regional");Object.assign(regionalForm,{userLocale:regional.value.userLocale,userTimezone:regional.value.userTimezone,systemLocale:regional.value.systemLocale,applicationTimezone:regional.value.applicationTimezone});setLocale(regional.value.userLocale)}
async function savePreferences(){await api("/api/settings/preferences",{method:"PUT",body:JSON.stringify({locale:regionalForm.userLocale,timezone:regionalForm.userTimezone})});setLocale(regionalForm.userLocale);if(session.value?.user){session.value.user.locale=regionalForm.userLocale;session.value.user.timezone=regionalForm.userTimezone}alert(t("settings.saved"))}
async function saveRegionalDefaults(){await api("/api/settings/regional",{method:"PUT",body:JSON.stringify({locale:regionalForm.systemLocale,timezone:regionalForm.applicationTimezone})});await loadRegional();alert(t("settings.saved"))}
async function saveStatusSettings() {
  await api("/api/settings/status-page", { method: "PUT", body: JSON.stringify({ title: statusTitle.value }) });
  alert(ui("Public status page settings saved"));
}
onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer); });
</script>

<template>
  <main v-if="isSharePage" class="shared-shell">
    <label class="guest-language">{{ locale==='th-TH'?'ภาษา':'Language' }} <select :value="locale" @change="setLocale(($event.target as HTMLSelectElement).value as Locale)"><option value="th-TH">ไทย</option><option value="en-US">English</option></select></label>
    <section v-if="sharedPage" class="shared-page">
      <header class="public-head"><div class="brand brand-large"><img src="/byakugan-eye-original-v4.png?v=4" alt="Byakugan">Byakugan</div><span>{{ ui("Shared monitoring dashboard") }}</span></header>
      <div class="shared-title"><div><h1>{{ sharedPage.name }}</h1><p>{{ ui("Live service health without exposing private project configuration.") }}</p></div><small>{{ ui("Updated") }} {{ relative(sharedPage.updatedAt) }}</small></div>
      <section v-for="group in sharedPage.groups" :key="group.name" class="shared-group">
        <h2>{{ group.name }}</h2>
        <article v-for="monitor in group.monitors" :key="monitor.id" class="shared-monitor-card">
          <div class="shared-monitor-head"><span :class="['status-dot', monitor.lastStatus.toLowerCase()]"></span><span><strong>{{ monitor.name }}</strong><small>{{ monitor.monitorType }} {{ ui("monitor") }}</small></span><div class="shared-stat"><strong>{{ formatMetric(monitor.uptime24h, '%') }}</strong><small>{{ ui("24h uptime") }}</small></div><div class="shared-stat"><strong>{{ formatMetric(monitor.averageResponseMs, ' ms') }}</strong><small>{{ ui("average") }}</small></div><span :class="['status-pill', monitor.lastStatus.toLowerCase()]">{{ ui(monitor.lastStatus) }}</span></div>
          <MonitorSummary :stats="monitor" />
          <div class="shared-timeline"><span v-for="(beat,index) in monitor.heartbeats.slice(-48)" :key="`${beat.checkedAt}-${index}`" :class="['share-bar',beat.status.toLowerCase()]" :title="`${beat.status} · ${beat.responseTimeMs} ms · ${displayDate(beat.checkedAt)}`"></span></div>
          <div v-if="sparklinePoints(monitor.heartbeats)" class="shared-sparkline"><svg viewBox="0 0 500 105" preserveAspectRatio="none"><line v-for="y in [20,55,90]" :key="y" x1="0" :y1="y" x2="500" :y2="y"/><polyline :points="sparklinePoints(monitor.heartbeats)"/></svg><div><span>{{ monitor.heartbeats.length ? relative(monitor.heartbeats[0].checkedAt) : '' }}</span><span>{{ ui("Now") }}</span></div></div>
        </article>
      </section>
      <div v-if="!sharedPage.groups.length" class="empty"><h2>{{ ui("No shared monitors") }}</h2></div>
      <footer>{{ ui("Powered by Byakugan · URLs and credentials are hidden") }}</footer>
    </section>
  </main>

  <main v-else-if="isPublicPage" class="public-status-shell">
    <label class="guest-language">{{ locale==='th-TH'?'ภาษา':'Language' }} <select :value="locale" @change="setLocale(($event.target as HTMLSelectElement).value as Locale)"><option value="th-TH">ไทย</option><option value="en-US">English</option></select></label>
    <section v-if="publicStatus" class="public-status-page">
      <header class="public-head"><div class="brand brand-large"><img src="/byakugan-eye-original-v4.png?v=4" alt="Byakugan">Byakugan</div><span>{{ ui("Public status page") }}</span></header>
      <section :class="['overall-banner', publicStatus.operational ? 'operational' : 'outage']">
        <strong>{{ ui(publicStatus.operational ? 'All systems operational' : 'Some systems are experiencing issues') }}</strong>
        <small>{{ ui("Updated") }} {{ relative(publicStatus.updatedAt) }}</small>
      </section>
      <h1>{{ publicStatus.title }}</h1>
      <section class="public-monitor-list">
        <article v-for="monitor in publicStatus.monitors" :key="monitor.id" class="public-monitor">
          <span :class="['status-dot', monitor.lastStatus.toLowerCase()]"></span>
          <span><strong>{{ monitor.name }}</strong><small>{{ monitor.monitorType }}</small></span>
          <span :class="['status-pill', monitor.lastStatus.toLowerCase()]">{{ ui(monitor.lastStatus) }}</span>
          <MonitorSummary class="public-monitor-summary" :stats="monitor" />
        </article>
        <div v-if="!publicStatus.monitors.length" class="empty"><h2>{{ ui("No public monitors") }}</h2><p>{{ ui("The administrator has not published any monitors yet.") }}</p></div>
      </section>
      <footer>{{ ui("Powered by Byakugan · Open source monitoring") }}</footer>
    </section>
  </main>

  <main v-else-if="session && !session.authenticated" class="auth-shell">
    <label class="guest-language">{{ locale==='th-TH'?'ภาษา':'Language' }} <select :value="locale" @change="setLocale(($event.target as HTMLSelectElement).value as Locale)"><option value="th-TH">ไทย</option><option value="en-US">English</option></select></label>
    <section class="auth-visual" aria-hidden="true">
      <img src="/byakugan-login-guardian.png" alt="">
      <div class="auth-visual-copy"><span>{{ ui("ALL-SEEING OPERATIONS") }}</span><strong>{{ ui("Observe. Detect. Prove.") }}</strong><p>{{ ui("Infrastructure monitoring, vulnerability management, and audit evidence from one quiet control plane.") }}</p></div>
    </section>
    <section class="auth-card">
      <div class="brand brand-large"><img src="/byakugan-eye-original-v4.png?v=4" alt="">Byakugan</div>
      <p class="muted">{{ ui("Infrastructure visibility and audit evidence, in one quiet place.") }}</p>
      <form v-if="!mfaChallenge" @submit.prevent="authenticate(!session.configured)">
        <label>{{ ui("Username") }}<input v-model="credentials.username" autocomplete="username" required minlength="3"></label>
        <label>{{ ui("Password") }}<input v-model="credentials.password" type="password" :autocomplete="session.configured ? 'current-password' : 'new-password'" required minlength="10"></label>
        <p v-if="error" class="error-banner">{{ error }}</p>
        <button class="primary wide" :disabled="busy">{{ ui(session.configured ? "Sign in" : "Create administrator") }}</button>
      </form>
      <template v-if="session.configured&&loginProviders.length&&!mfaChallenge"><div class="auth-divider"><span>{{ ui("or sign in with SSO") }}</span></div><a v-for="provider in loginProviders" :key="provider.id" class="secondary wide button-link sso-button" :href="`/api/auth/oidc/${provider.id}/start`">{{ provider.name }} · {{ provider.preset }}</a></template>
      <form v-else @submit.prevent="completeMfa"><label>{{ ui("Authenticator or recovery code") }}<input v-model="mfaCode" required maxlength="14" autocomplete="one-time-code" autofocus></label><p class="field-note">{{ ui("Enter the 6-digit authenticator code or a one-time recovery code.") }}</p><p v-if="error" class="error-banner">{{ error }}</p><button class="primary wide" :disabled="busy">{{ ui("Verify and sign in") }}</button><button type="button" class="secondary wide" @click="mfaChallenge=''">{{ ui("Back") }}</button></form>
    </section>
  </main>

  <div v-else-if="session" class="app-shell">
    <aside>
      <div class="brand"><img src="/byakugan-eye-original-v4.png?v=4" alt="">Byakugan</div>
      <nav>
        <span class="nav-section">{{ t('nav.overview') }}</span>
        <button :class="{ active: activeView === 'dashboard' }" @click="activeView = 'dashboard'"><span><AppIcon name="monitor" /></span> {{ t('nav.monitors') }}</button>
        <button :class="{ active: activeView === 'actions' }" @click="activeView = 'actions'"><span><AppIcon name="alert" /></span> {{ t('nav.actions') }} <b v-if="openFindings.length" class="nav-badge">{{ openFindings.length }}</b></button>
        <span class="nav-section">{{ t('nav.monitoring') }}</span>
        <button :class="{ active: activeView === 'health' }" @click="activeView = 'health'; loadHealth()"><span><AppIcon name="health" /></span> {{ ui("Health Check") }} <b v-if="health && (health.summary.critical || health.summary.warning)" :class="['nav-badge', health.summary.critical ? 'lvl-critical-badge' : '']">{{ health.summary.critical + health.summary.warning }}</b></button>
        <button :class="{ active: activeView === 'certificates' }" @click="activeView='certificates'; loadProjects()"><span><AppIcon name="lock" /></span>{{ thai?'ใบรับรอง SSL/TLS':'SSL/TLS Certificates' }}</button>
        <button :class="{ active: activeView === 'heartbeats' }" @click="activeView = 'heartbeats'"><span><AppIcon name="clock" /></span> {{ t('nav.heartbeats') }}</button>
        <button :class="{ active: activeView === 'agents' }" @click="activeView = 'agents'"><span><AppIcon name="server" /></span> {{ t('nav.agents') }}</button>
        <button :class="{ active: activeView === 'incidents' }" @click="activeView = 'incidents'"><span><AppIcon name="incident" /></span> {{ t('nav.incidents') }} <b v-if="pendingIncidents.length" class="nav-badge">{{ pendingIncidents.length }}</b></button>
        <button :class="{ active: activeView === 'vulnerabilities' }" @click="activeView = 'vulnerabilities'"><span><AppIcon name="shield" /></span> {{ t('nav.vulnerabilities') }} <b v-if="vulnerabilities.length" class="nav-badge">{{ vulnerabilities.length }}</b></button>
        <button :class="{ active: activeView === 'notifications' }" @click="activeView = 'notifications'"><span><AppIcon name="bell" /></span> {{ t('nav.notifications') }}</button>
        <button v-if="canReadLogs" :class="{ active: activeView === 'threats' }" @click="activeView = 'threats'"><span><AppIcon name="shield" /></span> {{ thai ? 'ภัยคุกคาม' : 'Threats' }}</button>
        <button v-if="canReadLogs" :class="{ active: activeView === 'logs' }" @click="openLogs()"><span><AppIcon name="logs" /></span> {{ thai ? 'บันทึกเหตุการณ์' : 'Event logs' }}</button>
        <span class="nav-section">{{ t('nav.status') }}</span>
        <button :class="{ active: activeView === 'shares' }" @click="activeView = 'shares'"><span><AppIcon name="external" /></span> {{ t('nav.shares') }}</button>
        <span class="nav-section nav-audit">{{ t('nav.audit') }}</span>
        <button :class="{ active: activeView === 'audit' }" @click="activeView = 'audit'"><span><AppIcon name="audit" /></span> {{ t('nav.auditWorkspace') }}</button>
        <span class="nav-section">{{ t('nav.admin') }}</span>
        <button v-if="isAdmin" :class="{ active: activeView === 'users' }" @click="activeView = 'users'"><span><AppIcon name="users" /></span> {{ t('nav.users') }}</button>
        <button :class="{ active: activeView === 'settings' }" @click="activeView = 'settings'"><span><AppIcon name="settings" /></span> {{ t('nav.settings') }}</button>
      </nav>
      <div class="sidebar-footer"><label class="language-switch">{{ locale==='th-TH'?'ภาษา':'Language' }}<select :value="locale" :disabled="languageSaving" @change="changeLanguage(($event.target as HTMLSelectElement).value as Locale)"><option value="th-TH">ไทย</option><option value="en-US">English</option></select></label><span class="user-identity">{{ session.user?.username }} · {{ session.user?.role }}</span><span>v2.3.0</span><button class="link" @click="logout">{{ ui("Sign out") }}</button></div>
    </aside>

    <section class="content">
      <template v-if="activeView === 'dashboard'">
      <header><div><h1>{{ t('page.projects') }}</h1><p>{{ t('page.projectsSub') }}</p></div><button v-if="canWrite" class="primary" @click="openCreate"><AppIcon name="plus" /> {{ t('page.addProject') }}</button></header>
      <p v-if="error" class="error-banner dismissible">{{ error }} <button @click="error = ''"><AppIcon name="x" /></button></p>

      <div class="metrics">
        <article><span>{{ ui("All projects") }}</span><strong>{{ totals.all }}</strong></article>
        <article><span>{{ ui("Operational") }}</span><strong class="green">{{ totals.up }}</strong></article>
        <article><span>{{ ui("Needs attention") }}</span><strong class="red">{{ totals.attention }}</strong></article>
        <article><span>{{ ui("Pending") }}</span><strong>{{ totals.pending }}</strong></article>
      </div>

      <section class="panel">
        <div v-if="!projects.length" class="empty">
          <div class="empty-icon"><AppIcon name="monitor" /></div><h2>{{ t('page.emptyProjects') }}</h2>
          <p>{{ t('page.emptyProjectsSub') }}</p>
          <button v-if="canWrite" class="primary" @click="openCreate">{{ ui("Add your first project") }}</button>
        </div>
        <div v-else class="project-list">
          <article v-for="project in projects" :key="project.id" class="project-row">
            <button class="project-main" @click="showHistory(project)">
              <span :class="['status-dot', project.lastStatus.toLowerCase()]"></span>
              <span><strong>{{ project.name }}</strong><small>{{ project.supabaseUrl }}</small><small v-if="project.lastMessage && project.lastStatus !== 'UP'" class="project-error">{{ project.lastMessage }}</small></span>
            </button>
            <div class="project-meta"><small>{{ ui("Last check") }}</small><span>{{ relative(project.lastCheckedAt) }}</span></div>
            <div class="project-meta"><small>{{ ui("Interval") }}</small><span>{{ formatInterval(project.intervalSeconds) }}</span></div>
            <div class="dashboard-timeline">
              <div class="mini-bars"><span v-for="(beat, index) in project.recentHeartbeats" :key="`${beat.checkedAt}-${index}`" :class="['mini-bar', beat.status.toLowerCase()]" :title="`${beat.status} · ${beat.responseTimeMs} ms · ${displayDate(beat.checkedAt)}`"></span><span v-if="!project.recentHeartbeats?.length" class="mini-empty">{{ ui("No history") }}</span></div>
              <div class="mini-labels"><span>{{ project.recentHeartbeats?.length ? relative(project.recentHeartbeats[0].checkedAt) : '—' }}</span><span>{{ ui("Now") }}</span></div>
            </div>
            <span :class="['status-pill', project.lastStatus.toLowerCase()]">{{ ui(project.lastStatus) }}</span>
            <div v-if="canWrite" class="actions">
              <button :title="ui('Run now')" :disabled="running.has(project.id) || !project.enabled" @click="runProject(project)"><AppIcon :name="running.has(project.id)?'refresh':'play'" :class="{'icon-spin':running.has(project.id)}" /></button>
              <button :title="ui('Edit')" @click="openEdit(project)"><AppIcon name="edit" /></button>
              <button :title="ui('Delete')" @click="removeProject(project)"><AppIcon name="trash" /></button>
            </div>
          </article>
        </div>
      </section>
      </template>

      <template v-else-if="activeView === 'certificates'">
        <header><div><h1>{{ thai?'ใบรับรอง SSL/TLS':'SSL/TLS Certificates' }}</h1><p>{{ thai?'รวม HTTPS, WSS, Supabase และ SSL Monitor ตรวจโฮสต์ตามที่ตั้งไว้ ไม่ใช่ปลายทางหลัง Redirect':'Certificates for configured HTTPS, WSS, Supabase and SSL targets, before redirects.' }}</p></div><button v-if="canWrite" class="primary" @click="openCertificateCreate"><AppIcon name="plus" />{{ thai?'เพิ่มมอนิเตอร์ใบรับรอง':'Add certificate monitor' }}</button></header>
        <p class="workflow-note">{{ thai?'วันคงเหลือจากใบรับรองจริง ไม่ได้คำนวณย้อนจากจำนวนวัน การอ่านใบรับรองไม่ได้ปิดการตรวจ TLS ของเว็บ กดตรวจตอนนี้เพื่อเก็บข้อมูลใหม่ การแจ้งเตือนใกล้หมดอายุประเมินผ่าน Health Check ตามเกณฑ์ที่ตั้ง':'Expiry comes from the served certificate, not an estimate from rounded days. Inspection does not disable service TLS verification. Run now for fresh data; expiry warnings use configured Health Check policy.' }}</p>
        <section class="panel"><div v-if="!certificateProjects.length" class="empty">{{ thai?'ยังไม่มีปลายทาง HTTPS/TLS เพิ่ม HTTP แบบ https:// หรือ SSL Monitor เพื่อเริ่มตรวจ':'No HTTPS/TLS targets. Add an HTTPS HTTP monitor or an SSL monitor.' }}</div><div v-else class="certificate-list"><article v-for="project in certificateProjects" :key="project.id" class="certificate-row"><button class="link" @click="showHistory(project)">{{ project.name }}</button><CertificateInfo :certificate="project.certificate" /><span>{{ relative(project.certificate?.checkedAt??null) }}</span><button v-if="canWrite" class="secondary" :disabled="running.has(project.id)||!project.enabled" @click="runProject(project)">{{ thai?'ตรวจตอนนี้':'Run now' }}</button></article></div></section>
      </template>

      <template v-else-if="activeView === 'actions'">
        <header><div><h1>{{ t('page.actions') }}</h1><p>{{ t('page.actionsSub') }}</p></div></header>
        <div class="metrics"><article><span>{{ t('actions.openFindings') }}</span><strong :class="openFindings.length?'red':'green'">{{ openFindings.length }}</strong></article><article><span>{{ t('actions.critical') }}</span><strong class="red">{{ findings.filter(x=>x.severity==='CRITICAL').length }}</strong></article><article><span>{{ t('actions.patch') }}</span><strong>{{ findings.filter(x=>x.category==='PATCH').length }}</strong></article><article><span>{{ t('actions.health') }}</span><strong>{{ findings.filter(x=>x.category==='HEALTH').length }}</strong></article></div>
        <p class="workflow-note">{{ thai ? 'รับทราบ = มีผู้ดูแลแล้ว ไม่ใช่แก้ไขแล้ว ตัวเลขเมนูนับเฉพาะรายการ OPEN; เมื่อระบบตรวจว่าปัญหาหาย จะปิดให้อัตโนมัติ หากความรุนแรงสูงขึ้น หรือกดแก้ไขแล้วแต่ต้นเหตุยังอยู่ ระบบจะเปิดรายการให้ตรวจอีกครั้ง' : 'Acknowledged means owned, not fixed. The badge counts OPEN findings only. Recovery resolves active findings automatically; a manually resolved finding can reopen if the problem persists.' }}</p><div class="workflow-filters"><button v-for="state in ['OPEN','ACKNOWLEDGED','ALL']" :key="state" :class="['secondary',{selected:findingFilter===state}]" @click="findingFilter=state">{{ state==='ALL'?(thai?'ทั้งหมดที่ยังไม่แก้ไข':'All active'):t(`actions.statuses.${state}`) }} ({{ findings.filter(x=>state==='ALL'||x.status===state).length }})</button></div><p v-if="error" class="error-banner" role="alert">{{ error }}</p><section class="panel page-panel"><div v-if="!filteredFindings.length" class="empty"><div class="empty-icon"><AppIcon name="check" /></div><h2>{{ t('page.noActions') }}</h2><p>{{ findingFilter==='OPEN' && findings.length ? (thai ? 'รายการที่รับทราบแล้วอยู่ในแท็บรับทราบ' : 'Acknowledged findings are available in their tab') : t('actions.emptySub') }}</p></div><div v-else class="finding-list"><button v-for="item in filteredFindings" :key="item.id" class="finding-row finding-button" @click="editFinding(item)"><span :class="['severity-mark',item.severity.toLowerCase()]"></span><span><strong>{{ findingTitle(item) }}</strong><small>{{ findingExplanation(item) }}</small><small class="finding-next-step">{{ thai ? "เริ่มตรวจ: " : "Start here: " }}{{ findingGuidance(item,thai).steps[0] }}</small><small>{{ thai ? "กดดูรายละเอียดและวิธีดำเนินการ" : "View details and recommended actions" }}</small><small class="finding-asset"><AppIcon name="server" /> {{ t('actions.asset') }}: <b>{{ item.hostname||item.agentName||t('actions.unknownAsset') }}</b><template v-if="item.hostname&&item.agentName&&item.hostname!==item.agentName"> · {{ t('actions.agent') }}: {{ item.agentName }}</template></small></span><span><small>{{ t('actions.owner') }}</small>{{ item.owner||t('actions.unassigned') }}</span><span><small>{{ t('actions.status') }}</small>{{ t(`actions.statuses.${item.status}`) }}</span><span :class="['criticality',item.severity.toLowerCase()]">{{ t(`actions.severities.${item.severity}`) }}</span><time>{{ item.dueAt?t('actions.due')+' '+displayDateOnly(item.dueAt):relative(item.firstDetectedAt) }}</time></button></div></section>
      </template>

      <template v-else-if="activeView === 'incidents'">
        <header><div><h1>{{ t('page.incidents') }}</h1><p>{{ t('page.incidentsSub') }}</p></div></header><section class="usage-guide"><article><b>{{ ui("1 · Monitor transition") }}</b><span>{{ ui("Incident จะถูกสร้างเมื่อมอนิเตอร์เปลี่ยนจาก UP/PENDING เป็น DOWN หรือ PAUSED") }}</span></article><article><b>{{ ui("2 · Automatic recovery") }}</b><span>{{ ui("เมื่อมอนิเตอร์กลับมา UP ระบบจะบันทึกเวลาสิ้นสุดเหตุการณ์ให้อัตโนมัติ") }}</span></article><article><b>{{ ui("3 · ISO review") }}</b><span>{{ ui("ผู้ดูแลบันทึกสาเหตุราก การแก้ไข และบทเรียน แล้วอนุมัติเป็นหลักฐานออดิท") }}</span></article></section><section class="incident-scope-note"><strong>{{ ui("ขอบเขต:") }}</strong> {{ ui("หน้านี้รวมเหตุบริการล่มและ Health Check ระดับ Critical; รับทราบปัญหาที่ “รายการที่ต้องดำเนินการ” และดูผลสแกนที่ “ช่องโหว่”") }}</section><div class="metrics"><article><span>{{ ui("Total incidents") }}</span><strong>{{ incidents.length }}</strong></article><article><span>{{ thai ? 'เคสที่ยังไม่ปิด' : 'Open cases' }}</span><strong class="red">{{ incidents.filter(x=>!x.closedAt).length }}</strong></article><article><span>{{ ui("Pending review") }}</span><strong>{{ pendingIncidents.length }}</strong></article><article><span>{{ thai ? 'ปิดเคสแล้ว' : 'Closed cases' }}</span><strong class="green">{{ incidents.filter(x=>x.closedAt).length }}</strong></article></div>
        <section class="panel page-panel"><div v-if="!incidents.length" class="empty"><div class="empty-icon"><AppIcon name="check" /></div><h2>{{ ui("ยังไม่มีเหตุการณ์บริการล่ม") }}</h2><p>{{ ui("ข้อมูลจะปรากฏอัตโนมัติเมื่อมอนิเตอร์ที่เคยทำงานปกติเปลี่ยนเป็น DOWN หรือ PAUSED") }}</p></div><div v-else class="incident-list"><button v-for="item in incidents" :key="item.id" class="incident-row" @click="editIncident(item)"><span :class="['severity-mark',item.severity.toLowerCase()]"></span><span><strong>{{ item.projectName }}</strong><small>{{ item.message }}</small><small>{{ thai ? "ความเสี่ยง: " : "Risk: " }}{{ incidentGuidance(item,thai).risk }}</small><small>{{ thai ? "กดอ่านความหมายและแนวทางตรวจสอบ" : "View explanation and investigation guidance" }}</small></span><span><small>{{ ui("Service") }}</small>{{ ui(item.resolvedAt?'RECOVERED':item.status) }}</span><span><small>{{ ui("Owner") }}</small>{{ item.owner||ui('Unassigned') }}</span><span><small>{{ thai ? 'เคส / การทบทวน' : 'Case / review' }}</small>{{ ui(item.closedAt?'CLOSED':item.reviewStatus) }}</span><time>{{ displayDate(item.startedAt) }}</time></button></div></section>
      </template>

      <template v-else-if="activeView === 'health'">
        <header><div><h1>{{ thai ? 'ตารางมาตรฐาน Health Check' : 'Health Check standard' }}</h1><p>{{ thai ? 'ประเมินอัตโนมัติ: Warning แจ้ง Help desk, Critical เปิด Incident Process' : 'Evaluated automatically: Warning notifies the Help desk, Critical opens an incident.' }}</p></div><div class="detail-actions"><button v-if="canWrite" class="primary" :disabled="healthRunning" @click="runHealthNow"><AppIcon :name="healthRunning?'refresh':'play'" :class="{'icon-spin':healthRunning}" />{{ healthRunning?(thai?'กำลังตรวจ…':'Checking…'):(thai?'ตรวจตอนนี้':'Check now') }}</button><a class="secondary button-link" href="/api/health/report" download><AppIcon name="download" /> PDF</a></div></header>
        <p v-if="error" class="error-banner dismissible">{{ error }} <button @click="error = ''"><AppIcon name="x" /></button></p>
        <div v-if="health" class="metrics"><article><span>{{ ui("Normal") }}</span><strong class="green">{{ health.summary.normal }}</strong></article><article><span>{{ ui("Warning") }}</span><strong class="amber">{{ health.summary.warning }}</strong></article><article><span>{{ ui("Critical") }}</span><strong class="red">{{ health.summary.critical }}</strong></article><article><span>{{ thai ? 'ยังไม่มีข้อมูล' : 'No data' }}</span><strong>{{ health.summary.noData }}</strong></article></div>
        <p class="workflow-note">{{ thai ? 'ตรวจตอนนี้จะเช็กมอนิเตอร์ที่เปิดใช้อีกครั้ง และประเมินข้อมูล Agent/Logs/Backup ล่าสุด ข้อมูล CPU/RAM รอรอบส่งจาก Agent; ระบบยังแจ้ง Critical หากต้นเหตุยังไม่ถูกแก้ไข' : 'Check now probes enabled monitors and evaluates the latest Agent, log and backup data. CPU/RAM wait for the agent reporting interval. Active problems remain Critical until corrected.' }}</p><p v-if="healthRunMessage" class="workflow-result" role="status">{{ healthRunMessage }}</p><section class="panel page-panel health-panel"><div v-if="!health" class="empty"><h2>…</h2></div><div v-else class="health-table">
          <div class="health-head"><span>#</span><span>{{ thai ? 'รายการ' : 'Item' }}</span><span>{{ thai ? 'ดำเนินการตรวจเช็ค' : 'Check' }}</span><span class="h-normal">{{ ui("Normal") }}</span><span class="h-warning">{{ ui("Warning") }}</span><span class="h-critical">{{ ui("Critical") }}</span><span>{{ thai ? 'ความถี่' : 'Frequency' }}</span><span>{{ thai ? 'ผลล่าสุด' : 'Latest' }}</span></div>
          <template v-for="item in health.items" :key="item.no">
            <div :class="['health-row', { disabled: !item.enabled }]"><span>{{ item.no }}</span><span><strong>{{ thai ? item.nameTh : item.nameEn }}</strong></span><span class="muted-cell">{{ ui(item.checkTh) }}</span><span class="h-normal">{{ healthThreshold(item.thresholds.normal) }}</span><span class="h-warning">{{ healthThreshold(item.thresholds.warning) }}</span><span class="h-critical">{{ healthThreshold(item.thresholds.critical) }}<small v-if="item.no===8">{{ thai?'TLS ไม่ผ่านก็เป็นวิกฤต':'Invalid TLS is also Critical' }}</small></span><span>{{ ui(item.frequencyTh) }}</span>
              <span class="health-result"><b :class="['lvl', 'lvl-' + item.level.toLowerCase()]">{{ item.enabled ? ui(item.level==='NO_DATA'?'No data':item.level) : (thai?'ปิด':'OFF') }}</b><small v-for="s in item.subjects.slice(0, 3)" :key="s.subjectKey">{{ s.label }}{{ s.note && s.note !== 'stale' ? ' (' + s.note + ')' : '' }}: {{ unitText(s.value, item.unit) }}</small><button v-if="isAdmin" class="icon-button" :title="thai ? 'แก้เกณฑ์' : 'Edit thresholds'" @click="healthEditing = healthEditing === item.no ? null : item.no"><AppIcon name="edit" /></button></span></div>
            <div v-if="healthEditing === item.no" class="health-edit"><label>{{ ui("Warning") }}<input v-model.number="item.warningValue" type="number" step="any"></label><label>{{ ui("Critical") }}<input v-model.number="item.criticalValue" type="number" step="any"></label><label>{{ thai ? 'ต่อเนื่อง (วินาที)' : 'Duration (s)' }}<input v-model.number="item.durationSeconds" type="number" min="0" max="86400"></label><label class="check"><input v-model="item.enabled" type="checkbox"> {{ thai ? 'เปิดใช้งาน' : 'Enabled' }}</label><button class="primary" :disabled="busy" @click="saveHealthPolicy(item)">{{ thai ? 'บันทึก' : 'Save' }}</button><button class="secondary" @click="healthEditing = null; loadHealth()">{{ thai ? 'ยกเลิก' : 'Cancel' }}</button></div>
          </template>
        </div></section>
        <section v-if="isAdmin && health" class="panel page-panel health-sources"><label>{{ thai ? 'แหล่ง log ที่ต้องส่งต่อเนื่อง (ข้อ 7) — คั่นด้วยจุลภาค เช่น host, nginx, vpn' : 'Log sources expected continuously (item 7) — comma separated, e.g. host, nginx, vpn' }}<input id="log-sources" v-model="logSourcesText" placeholder="host, nginx, vpn, firewall, db"></label><button class="primary" :disabled="busy" @click="saveLogSources">{{ thai ? 'บันทึก' : 'Save' }}</button></section>
      </template>

      <LogsView v-else-if="activeView === 'threats' && canReadLogs" key="threats" threats :timezone="regionalForm.userTimezone==='SYSTEM'?regionalForm.applicationTimezone:regionalForm.userTimezone" />
      <LogsView v-else-if="activeView === 'logs' && canReadLogs" :key="logAgentId" :initial-agent-id="logAgentId" :timezone="regionalForm.userTimezone==='SYSTEM'?regionalForm.applicationTimezone:regionalForm.userTimezone" />

      <template v-else-if="activeView === 'agents'">
        <header><div><h1>{{ t('page.agents') }}</h1><p>{{ t('page.agentsSub') }}</p></div><button v-if="canWrite" class="primary" @click="openAgentCreate"><AppIcon name="plus" /> {{ t('page.add') }}</button></header>
        <section class="usage-guide"><article><b>{{ ui("1 · Enroll") }}</b><span>{{ ui("กด “เพิ่ม” ตั้งชื่อเครื่อง แล้วคัดลอก token ซึ่งแสดงเพียงครั้งเดียว") }}</span></article><article><b>{{ ui("2 · Install") }}</b><span>{{ ui("เลือกติดตั้ง Agent แบบ Linux Docker หรือ Windows PowerShell แล้วกำหนด URL กับ token") }}</span></article><article><b>{{ ui("3 · Collect") }}</b><span>{{ ui("เมื่อ Agent เชื่อมต่อ ระบบจะแสดง CPU, RAM, patch, Docker และหลักฐาน Audit") }}</span></article></section>
        <section class="panel page-panel"><div v-if="!agents.length" class="empty"><div class="empty-icon"><AppIcon name="server" /></div><h2>{{ ui("No server agents") }}</h2><p>{{ ui("Enroll a Linux or Windows server to begin automatic ISO evidence collection.") }}</p><button v-if="canWrite" class="primary" @click="openAgentCreate">{{ ui("Enroll first server") }}</button></div><div v-else class="agent-list"><article v-for="item in agents" :key="item.id" class="agent-row"><span :class="['status-dot',item.enabled&&item.lastSeenAt?'up':'down']"></span><span><strong>{{ item.hostname||item.name }}</strong><small>{{ item.osName||'Waiting for first evidence' }} {{ item.osVersion||'' }}</small></span><span><small>CPU</small>{{ formatMetric(item.cpuPercent,'%') }}</span><span><small>{{ ui("Memory") }}</small>{{ formatMetric(item.memoryPercent,'%') }}</span><span><small>{{ ui("Security updates") }}</small>{{ item.securityUpdates??'—' }}</span><span><small>{{ ui("Last evidence") }}</small>{{ relative(item.lastSeenAt) }}</span><div class="agent-row-actions"><button v-if="canReadLogs" class="secondary" @click="openLogs(item.id)">{{ thai ? 'ดู Log' : 'View logs' }}</button><button v-if="canWrite" class="icon-button" :title="item.lastSeenAt?'Revoke and archive agent':'Remove unused enrollment'" @click="revokeAgent(item)"><AppIcon name="trash" /></button></div></article></div></section>
        <section class="security-note"><strong>{{ thai ? 'ข้อมูลที่ Agent ส่ง' : 'Agent collection' }}</strong><p>{{ thai ? 'Agent ส่งข้อมูลเครื่อง metrics และ log เหตุการณ์ที่รองรับ ส่วนผลสแกนส่งตามงานที่สั่ง ดูเหตุการณ์รายเครื่องได้จากปุ่ม “ดู Log”' : 'The agent sends inventory, metrics and supported event logs. Scan findings are uploaded for configured scan jobs. Select View logs to inspect events for a machine.' }}</p></section>
      </template>

      <template v-else-if="activeView === 'vulnerabilities'">
        <header><div><h1>{{ t('page.vulnerabilities') }}</h1><p>{{ t('page.vulnerabilitiesSub') }}</p></div><div v-if="canWrite" class="detail-actions"><button class="secondary" :disabled="busy" @click="syncThreatIntel"><AppIcon name="refresh" /> {{ ui("Threat intel") }}</button><button class="secondary" @click="openScanProfile"><AppIcon name="plus" /> {{ ui("Profile") }}</button><button class="secondary" @click="openScanSchedule"><AppIcon name="clock" /> {{ ui("Schedule") }}</button><button class="primary" @click="openScanJob"><AppIcon name="shield" /> {{ ui("Scan now") }}</button></div></header>
        <section class="usage-guide"><article><b>{{ ui("1 · Agent") }}</b><span>{{ ui("ต้องมี Linux หรือ Windows Agent ที่ออนไลน์และติดตั้ง Trivy ก่อน") }}</span></article><article><b>{{ ui("2 · Profile") }}</b><span>{{ ui("เลือกแม่แบบ BUILT-IN หรือสร้างเอง; แม่แบบระบบลบไม่ได้ แต่ Custom ลบได้") }}</span></article><article><b>{{ ui("3 · Run") }}</b><span>{{ ui("Scan now ทำครั้งเดียว ส่วน Schedule ทำซ้ำอัตโนมัติ; ผลจะสร้าง CVE และแจ้งเตือน") }}</span></article></section>
        <section class="panel scan-profiles-panel"><div class="section-title"><div><h2>{{ ui("Scan profiles") }}</h2><span>{{ ui("Reusable policies · BUILT-IN profiles are protected") }}</span></div><span>{{ scanProfiles.length }} {{ ui("profiles") }}</span></div><div class="profile-grid"><article v-for="profile in scanProfiles" :key="profile.id" class="profile-card"><div><strong>{{ profile.name }}</strong><b v-if="profile.systemProfile" :title="ui('System profiles are protected and cannot be deleted')">{{ ui("BUILT-IN") }}</b><button v-else-if="canWrite" class="icon-button" :title="ui('Delete custom profile')" @click="disableScanProfile(profile)"><AppIcon name="trash" /></button></div><p>{{ profile.description||ui('Custom security scan profile') }}</p><small>{{ profile.targetType }} · {{ profile.scanners.join(' + ') }}</small><small>{{ profile.severity.join(', ') }} {{ ui("· timeout") }} {{ Math.round(profile.timeoutSeconds/60) }} min</small></article></div></section>
        <div class="metrics"><article><span>{{ ui("Active CVEs") }}</span><strong :class="vulnerabilities.length?'red':'green'">{{ vulnerabilities.length }}</strong></article><article><span>{{ ui("Known exploited (KEV)") }}</span><strong class="red">{{ vulnerabilities.filter(x=>x.kev).length }}</strong></article><article><span>EPSS ≥ 10%</span><strong>{{ vulnerabilities.filter(x=>(x.epssScore||0)>=.1).length }}</strong></article><article><span>{{ ui("Threat intelligence") }}</span><strong class="metric-small">{{ threatIntelStatus?.completedAt?relative(threatIntelStatus.completedAt):'Not synchronized' }}</strong></article></div>
        <section class="panel scan-jobs-panel"><div class="section-title"><div><h2>{{ ui("Scan jobs") }}</h2><span>{{ ui("Agent-executed Trivy scans · click a completed job to inspect its evidence") }}</span></div><span>{{ vulnerabilityScanJobs.filter(x=>['QUEUED','RUNNING'].includes(x.status)).length }} {{ ui("active") }}</span></div><div v-if="!vulnerabilityScanJobs.length" class="empty compact">{{ ui("No scan jobs have been queued.") }}</div><div v-else class="scan-job-list"><article v-for="job in vulnerabilityScanJobs.slice(0,20)" :key="job.id" :class="['scan-job-row',{'has-result':job.status==='COMPLETED'}]" @click="job.status==='COMPLETED'&&showScanJobResult(job)"><span :class="['status-dot',job.status==='COMPLETED'?'up':job.status==='FAILED'?'down':'paused']"></span><span><strong>#{{ job.id }} · {{ job.agentName }}</strong><small>{{ job.targetType }} · {{ job.target }} · {{ job.scanners.join(', ') }}</small><small v-if="job.errorMessage" class="scan-error" :title="job.errorMessage">{{ job.errorMessage }}</small></span><span><small>{{ ui("Status") }}</small>{{ ui(job.status) }}<small v-if="job.resultSummary">{{ Number(job.resultSummary.total||0) }} {{ ui("findings") }}</small></span><span class="scan-progress"><i :style="{width:`${job.progress}%`}"></i><small>{{ job.progress }}%<template v-if="job.status==='COMPLETED'"> {{ ui("· ดูผล") }}</template></small></span><time>{{ relative(job.requestedAt) }}</time><button v-if="canWrite&&['QUEUED','RUNNING'].includes(job.status)" class="icon-button" :title="ui('Cancel active scan')" @click.stop="cancelScanJob(job)"><AppIcon name="x" /></button><button v-else-if="canWrite" class="icon-button" :title="ui('Remove from list (audit evidence is preserved)')" @click.stop="archiveScanJob(job)"><AppIcon name="trash" /></button></article></div></section>
        <section class="panel scan-schedules-panel"><div class="section-title"><div><h2>{{ ui("Scheduled scans") }}</h2><span>{{ ui("Automatic execution · deleting keeps historical evidence") }}</span></div><span>{{ scanSchedules.length }} {{ ui("enabled") }}</span></div><div v-if="!scanSchedules.length" class="empty compact">{{ ui("No scheduled scans configured.") }}</div><div v-else class="schedule-list"><article v-for="schedule in scanSchedules" :key="schedule.id" class="schedule-row"><span class="status-dot up"></span><span><strong>{{ schedule.name }}</strong><small>{{ schedule.agentName }} · {{ schedule.profileName }} · {{ schedule.target }}</small></span><span><small>{{ ui("Frequency") }}</small>{{ schedule.frequency }}</span><span><small>{{ ui("Next run") }}</small>{{ relative(schedule.nextRunAt) }}</span><button v-if="canWrite" class="icon-button" :title="ui('Delete schedule')" @click="disableScanSchedule(schedule)"><AppIcon name="trash" /></button></article></div></section>
        <section class="intel-provenance"><span><strong>CISA KEV</strong> {{ ui("known exploitation") }}</span><span><strong>FIRST EPSS</strong> {{ ui("30-day exploitation probability") }}</span><span>{{ ui("Status:") }} <strong>{{ threatIntelStatus?.status||'NOT SYNCHRONIZED' }}</strong><template v-if="threatIntelStatus?.cisaCatalogVersion"> {{ ui("· Catalog") }} {{ threatIntelStatus.cisaCatalogVersion }}</template></span></section>
        <section class="panel page-panel"><div v-if="!vulnerabilities.length" class="empty"><div class="empty-icon"><AppIcon name="shield" /></div><h2>{{ ui("No active vulnerabilities") }}</h2><p>{{ ui("Install the Byakugan Agent with Trivy to ingest vulnerability evidence.") }}</p></div><div v-else class="vulnerability-list"><button v-for="item in vulnerabilities" :key="item.id" class="vulnerability-row" :disabled="!canWrite" @click="editVulnerability(item)"><span :class="['severity-mark',item.severity.toLowerCase()]"></span><span><strong>{{ item.vulnerabilityId }} <b v-if="item.kev" class="intel-badge kev">KEV</b></strong><small>{{ item.title||'No advisory title' }}</small></span><span><small>{{ ui("Package") }}</small>{{ item.packageName }} {{ item.installedVersion }}</span><span><small>{{ ui("Threat likelihood") }}</small><b v-if="item.epssScore!==null" :class="['intel-badge',(item.epssScore||0)>=.1?'elevated':'']">EPSS {{ ((item.epssScore||0)*100).toFixed(1) }}%</b><em v-else>{{ ui("Not scored") }}</em></span><span><small>{{ ui("Asset") }}</small>{{ item.hostname||item.agentName }}</span><span :class="['criticality',item.severity.toLowerCase()]">{{ ui(item.severity) }}</span><span><small>{{ ui("Workflow") }}</small>{{ ui(item.status) }}</span></button></div></section>
        <section class="security-note"><strong>{{ ui("Scanner safety") }}</strong><p>{{ ui("Install Trivy on Agent 0.3, then use Scan now. Jobs are pulled over outbound HTTPS and restricted to Trivy filesystem, rootfs, and image scans. Secret values and file contents are never uploaded.") }}</p></section>
      </template>

      <template v-else-if="activeView === 'heartbeats'">
        <header><div><h1>{{ t('page.heartbeats') }}</h1><p>{{ t('page.heartbeatsSub') }}</p></div></header>
        <section class="panel page-panel">
          <div v-if="!projects.length" class="empty"><div class="empty-icon"><AppIcon name="clock" /></div><h2>{{ ui("No heartbeat data") }}</h2><p>{{ ui("Add a project to begin monitoring.") }}</p></div>
          <div v-else class="heartbeat-overview">
            <button v-for="project in projects" :key="project.id" class="heartbeat-project" @click="showHistory(project)">
              <span :class="['status-dot', project.lastStatus.toLowerCase()]"></span>
              <span class="heartbeat-name"><strong>{{ project.name }}</strong><small>{{ project.lastMessage || project.supabaseUrl }}</small></span>
              <span>{{ relative(project.lastCheckedAt) }}</span>
              <span :class="['status-pill', project.lastStatus.toLowerCase()]">{{ ui(project.lastStatus) }}</span>
              <span class="chevron"><AppIcon name="chevron" /></span>
            </button>
          </div>
        </section>
        <section v-if="incidents.length" class="panel secondary-panel">
          <div class="section-title"><h2>{{ ui("Incident history") }}</h2><span>{{ incidents.length }} {{ ui("recent") }}</span></div>
          <div class="event-list"><article v-for="incident in incidents" :key="incident.id" class="event-row"><span :class="['status-dot', incident.resolvedAt ? 'up' : 'down']"></span><span><strong>{{ incident.projectName }}</strong><small>{{ incident.message }}</small></span><span>{{ incident.resolvedAt ? 'RESOLVED' : incident.status }}</span><time>{{ displayDate(incident.startedAt) }}</time></article></div>
        </section>
      </template>

      <template v-else-if="activeView === 'detail' && selected">
        <header class="detail-header">
          <div><button class="back-button" @click="activeView = 'dashboard'"><AppIcon name="left" /> {{ ui("Back to monitors") }}</button><h1>{{ selected.name }}</h1><p><span class="monitor-kind">{{ selected.monitorType }}</span> {{ monitorTarget(selected) }}</p></div>
          <div class="detail-actions"><button class="secondary" :disabled="running.has(selected.id)" @click="runProject(selected)"><AppIcon :name="running.has(selected.id)?'refresh':'play'" :class="{'icon-spin':running.has(selected.id)}" />{{ ui(running.has(selected.id) ? 'Checking…' : 'Run now') }}</button><button class="secondary" @click="openEdit(selected)"><AppIcon name="edit" /> {{ ui("Edit") }}</button></div>
        </header>

        <section class="detail-status-card">
          <div class="timeline-wrap"><div class="timeline-bars"><span v-for="beat in statusTimeline" :key="beat.id" :class="['timeline-bar', beat.status.toLowerCase()]" :title="`${beat.status} · ${beat.responseTimeMs} ms · ${displayDate(beat.checkedAt)}`"></span><span v-if="!statusTimeline.length" class="muted">{{ ui("No checks recorded yet") }}</span></div><div class="timeline-labels"><span>{{ ui(statusTimeline.length ? relative(statusTimeline[0].checkedAt) : 'No history') }}</span><span>{{ ui("Now") }}</span></div><small>{{ ui("Checks every") }} {{ formatInterval(selected.intervalSeconds) }}</small></div>
          <span :class="['detail-state', selected.lastStatus.toLowerCase()]">{{ ui(selected.lastStatus === 'UP' ? 'Operational' : selected.lastStatus) }}</span>
        </section>

        <MonitorSummary :stats="monitorStats" />
        <p class="workflow-note">{{ thai?'Uptime คำนวณจากสัดส่วนผลตรวจ UP ไม่ใช่เวลาหยุดจริงทุกวินาที ค่าเฉลี่ย Response ใช้ผลตรวจ UP; ข้อมูลน้อยยังไม่ยืนยัน SLA ครบช่วงเวลา':'Uptime is the fraction of UP checks, not continuous wall-clock availability. Average response uses successful checks; sparse samples do not establish full-period SLA.' }}</p>
        <section v-if="selected.monitorType==='DATABASE'" class="panel database-metric-panel"><div class="section-title"><div><h2>{{ ui("Database health") }}</h2><span>{{ selected.databaseEngine }} {{ ui("· read-only telemetry") }}</span></div><span v-if="databaseMetrics[0]">{{ relative(databaseMetrics[0].observedAt) }}</span></div><div v-if="databaseMetrics[0]" class="detail-metrics database-health-grid"><article><small>{{ ui("Connections") }}</small><strong>{{ formatMetric(databaseMetrics[0].connectionsUsed) }} / {{ formatMetric(databaseMetrics[0].connectionsMax) }}</strong><span>{{ ui("Used / configured maximum") }}</span></article><article><small>{{ ui("Database size") }}</small><strong>{{ databaseMetrics[0].databaseSizeBytes===null?'—':`${(databaseMetrics[0].databaseSizeBytes/1073741824).toFixed(2)} GB` }}</strong><span>{{ ui("Latest observation") }}</span></article><article><small>{{ ui("Replication lag") }}</small><strong>{{ formatMetric(databaseMetrics[0].replicationLagSeconds,' s') }}</strong><span>{{ ui("When available") }}</span></article><article><small>{{ ui("Long-running queries") }}</small><strong>{{ formatMetric(databaseMetrics[0].longRunningQueries) }}</strong><span>{{ ui("Running longer than 30 seconds") }}</span></article></div><div v-else class="empty compact">{{ ui("Run this monitor to collect database telemetry.") }}</div></section>

        <section class="detail-chart-card">
          <div class="section-title"><div><h2>{{ ui("Response time") }}</h2><span>{{ ui("Latest") }} {{ chartBeats.length }} {{ ui("checks") }}</span></div><strong>{{ formatMetric(monitorStats?.averageResponse24hMs, thai?' ms เฉลี่ย':' ms avg') }}</strong></div>
          <div v-if="chartPoints" class="response-chart"><svg viewBox="0 0 1000 240" preserveAspectRatio="none" role="img" :aria-label="ui('Response time chart')"><defs><linearGradient id="chartFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#42df9d" stop-opacity=".42"/><stop offset="1" stop-color="#42df9d" stop-opacity="0"/></linearGradient></defs><line v-for="y in [35,79,123,167,210]" :key="y" x1="0" :y1="y" x2="1000" :y2="y" class="chart-grid"/><polygon :points="`0,220 ${chartPoints} 1000,220`" fill="url(#chartFill)"/><polyline :points="chartPoints" class="chart-line"/></svg><div class="chart-axis"><span>{{ chartBeats[0] ? new Date(chartBeats[0].checkedAt).toLocaleTimeString(locale, {hour:'2-digit', minute:'2-digit',timeZone:regionalForm.userTimezone==='SYSTEM'?regionalForm.applicationTimezone:regionalForm.userTimezone}) : '' }}</span><span>{{ ui("Now") }}</span></div></div>
          <div v-else class="empty compact">{{ ui("Run the monitor to begin drawing its response chart.") }}</div>
        </section>

        <section class="panel detail-history"><div class="section-title"><h2>{{ ui("Recent checks") }}</h2><span>{{ ui("Latest 500") }}</span></div><div class="history-list"><div v-for="beat in heartbeats.slice(0, 20)" :key="beat.id" class="history-row"><span :class="['status-dot', beat.status.toLowerCase()]"></span><strong>{{ ui(beat.status) }}</strong><span>{{ beat.responseTimeMs }} ms</span><span>{{ beat.httpStatus ? `HTTP ${beat.httpStatus}` : selected.monitorType }}</span><time>{{ displayDate(beat.checkedAt) }}</time></div></div></section>
      </template>

      <template v-else-if="activeView === 'notifications'">
        <header><div><h1>{{ t('page.notifications') }}</h1><p>{{ t('page.notificationsSub') }}</p></div><button class="primary" @click="openNotificationCreate"><AppIcon name="plus" /> {{ t('page.add') }}</button></header>
        <section class="panel page-panel">
          <div v-if="!notifications.length" class="empty"><div class="empty-icon"><AppIcon name="bell" /></div><h2>{{ ui("No notification channels") }}</h2><p>{{ ui("Add Telegram, Discord, or a generic webhook.") }}</p><button class="primary" @click="openNotificationCreate">{{ ui("Add your first channel") }}</button></div>
          <div v-else class="notification-list">
            <article v-for="item in notifications" :key="item.id" class="notification-row">
              <span class="notification-icon"><AppIcon :name="item.type==='TELEGRAM'?'send':item.type==='DISCORD'?'chat':'webhook'" /></span>
              <span><strong>{{ item.name }}</strong><small>{{ item.type }} {{ ui("· credentials stored encrypted") }}</small></span>
              <span :class="['status-pill', item.enabled ? 'up' : 'disabled']">{{ item.enabled ? 'ENABLED' : 'DISABLED' }}</span>
              <button v-if="isAdmin" :class="['secondary', 'help-desk-toggle', { on: item.helpDesk }]" :title="thai ? 'ช่องทางที่รับ Warning จาก Health Check' : 'Receives Health Check warnings'" @click="toggleHelpDesk(item)"><AppIcon v-if="item.helpDesk" name="check" /> {{ ui("Help desk") }}</button>
              <button class="icon-button" :title="ui('Delete')" @click="removeNotification(item)"><AppIcon name="trash" /></button>
            </article>
          </div>
        </section>
        <section v-if="deliveries.length" class="panel secondary-panel">
          <div class="section-title"><h2>{{ ui("Delivery history") }}</h2><span>{{ ui("Latest 100") }}</span></div>
          <div class="event-list"><article v-for="delivery in deliveries" :key="delivery.id" class="event-row"><span :class="['status-dot', delivery.success ? 'up' : 'down']"></span><span><strong>{{ delivery.notificationName }}</strong><small>{{ delivery.projectName || 'Test' }} · {{ delivery.errorMessage || delivery.event }}</small></span><span>{{ delivery.success ? 'SENT' : 'FAILED' }}</span><time>{{ displayDate(delivery.createdAt) }}</time></article></div>
        </section>
      </template>

      <template v-else-if="activeView === 'shares'">
        <header><div><h1>{{ t('page.shares') }}</h1><p>{{ t('page.sharesSub') }}</p></div><button class="primary" @click="openShareCreate"><AppIcon name="plus" /> {{ t('page.create') }}</button></header>
        <p v-if="error" class="error-banner">{{ error }}</p>
        <section class="panel page-panel">
          <div v-if="!shareDashboards.length" class="empty"><div class="empty-icon"><AppIcon name="external" /></div><h2>{{ ui("No shared dashboards") }}</h2><p>{{ ui("Create a private-link dashboard without exposing monitor targets or credentials.") }}</p><button class="primary" @click="openShareCreate">{{ ui("Create first share") }}</button></div>
          <div v-else class="share-admin-list"><article v-for="page in shareDashboards" :key="page.id" class="share-admin-row"><span><strong>{{ page.name }}</strong><small>{{ page.projectCount }} {{ ui("monitors · unguessable read-only link") }}</small></span><span :class="['status-pill',page.enabled?'up':'disabled']">{{ page.enabled?'ACTIVE':'DISABLED' }}</span><button class="secondary" @click="copyShareLink(page)">{{ ui("Copy link") }}</button><a class="secondary button-link" :href="page.sharePath" target="_blank">{{ ui("Open") }} <AppIcon name="external" /></a><button class="icon-button" :title="ui('Revoke link')" @click="removeShareDashboard(page)"><AppIcon name="trash" /></button></article></div>
        </section>
        <section class="security-note"><strong>{{ ui("Safe sharing") }}</strong><p>{{ ui("Shared APIs return only monitor name, type, status, uptime, response time, and heartbeat history. Supabase URLs, hostnames, container names, keys, and internal error messages are excluded.") }}</p></section>
      </template>

      <template v-else-if="activeView === 'audit' && auditOverview">
        <header><div><h1>{{ t('page.audit') }}</h1><p>{{ t('page.auditSub') }}</p></div><a class="primary button-link" :href="exportAuditUrl()">{{ t('page.exportEvidence') }}</a></header>
        <section v-if="auditWorkspace" class="audit-workspace"><div class="section-title"><div><h2>{{ ui("Audit workspace") }}</h2><p>{{ ui("Choose the audit period. The same scope is used for coverage and every report.") }}</p></div><span :class="auditWorkspace.auditChain.valid?'workspace-ok':'workspace-bad'">{{ ui(auditWorkspace.auditChain.valid?'Evidence chain valid':'Evidence chain failed') }}</span></div><div class="audit-range"><label>{{ ui("From") }}<input v-model="auditRange.from" type="date"></label><label>{{ ui("To") }}<input v-model="auditRange.to" type="date"></label><button class="secondary" @click="loadAudit">{{ ui("Apply") }}</button><a class="secondary button-link" :href="auditReportUrl('pdf')">PDF</a><a class="secondary button-link" :href="auditReportUrl('xlsx')">XLSX</a><a class="primary button-link" :href="exportAuditUrl()">Evidence ZIP</a></div><div class="coverage-grid"><article><small>{{ ui("Evidence events") }}</small><strong>{{ auditWorkspace.evidenceEvents }}</strong></article><article><small>{{ ui("Mapped assets") }}</small><strong>{{ auditWorkspace.mappedAssets }}/{{ auditWorkspace.assets }}</strong></article><article><small>{{ ui("Successful backups") }}</small><strong>{{ auditWorkspace.backupCount-auditWorkspace.failedBackups }}/{{ auditWorkspace.backupCount }}</strong></article><article><small>{{ ui("Restore tests passed") }}</small><strong>{{ auditWorkspace.passedRestores }}/{{ auditWorkspace.restoreCount }}</strong></article><article><small>{{ ui("Open findings") }}</small><strong :class="auditWorkspace.openFindings?'red':'green'">{{ auditWorkspace.openFindings }}</strong></article></div></section>
        <ServerEvidenceExport v-if="canReadLogs" :agents="agents" :projects="projects" :from="auditRange.from" :to="auditRange.to" />
        <div class="metrics audit-metrics"><article><span>{{ ui("Assets") }}</span><strong>{{ auditOverview.assets.length }}</strong></article><article><span>{{ ui("Mapped controls") }}</span><strong>{{ auditOverview.controlsMapped }}</strong></article><article><span>{{ ui("Open incidents") }}</span><strong :class="auditOverview.openIncidents?'red':'green'">{{ auditOverview.openIncidents }}</strong></article><article><span>{{ ui("Audit chain") }}</span><strong :class="auditOverview.auditChain.valid?'green':'red'">{{ auditOverview.auditChain.valid?'VALID':'FAILED' }}</strong></article></div>
        <section class="panel page-panel"><div class="section-title"><h2>{{ ui("Asset evidence profiles") }}</h2><span>ISO/IEC 27001:2022</span></div><div class="audit-assets"><article v-for="asset in auditOverview.assets" :key="asset.id" class="audit-asset-row"><span :class="['status-dot',asset.lastStatus.toLowerCase()]"></span><span><strong>{{ asset.name }}</strong><small>{{ asset.assetTag||'No asset tag' }} · {{ asset.monitorType }}</small></span><span><small>{{ ui("Owner") }}</small>{{ asset.assetOwner||'Not assigned' }}</span><span><small>{{ ui("Environment") }}</small>{{ asset.environment }}</span><span :class="['criticality',asset.criticality.toLowerCase()]">{{ asset.criticality }}</span><span><small>{{ ui("Controls") }}</small>{{ asset.controlIds.length }}</span><button class="secondary" @click="openAuditProfile(asset)">{{ ui("Configure") }}</button></article></div></section>
        <section class="audit-evidence-grid"><article class="panel evidence-panel"><div class="section-title"><h2>{{ ui("Backup evidence") }}</h2><button v-if="canWrite" class="secondary" @click="openBackupCreate"><AppIcon name="plus" /> {{ ui("Record backup") }}</button></div><div v-if="!backups.length" class="empty compact">{{ ui("No backup evidence recorded.") }}</div><div v-else><div v-for="item in backups.slice(0,8)" :key="item.id" class="evidence-row"><span :class="['status-dot',item.status==='SUCCESS'?'up':'down']"></span><span><strong>{{ item.assetName }}</strong><small>{{ item.backupType }} · {{ item.storageLocation }}</small></span><span><small>{{ ui("Status") }}</small>{{ ui(item.status) }}</span><time>{{ displayDateOnly(item.startedAt) }}</time></div></div></article><article class="panel evidence-panel"><div class="section-title"><h2>{{ ui("Restore tests") }}</h2><button v-if="canWrite" class="secondary" @click="openRestoreCreate"><AppIcon name="plus" /> {{ ui("Record test") }}</button></div><div v-if="!restoreTests.length" class="empty compact">{{ ui("No restore test evidence recorded.") }}</div><div v-else><div v-for="item in restoreTests.slice(0,8)" :key="item.id" class="evidence-row"><span :class="['status-dot',item.result==='PASS'?'up':'down']"></span><span><strong>{{ item.assetName }}</strong><small>{{ item.testScope }}</small></span><span><small>{{ ui("Result") }}</small>{{ ui(item.result) }}</span><time>{{ displayDateOnly(item.testedAt) }}</time></div></div></article></section>
        <section class="panel report-panel"><div class="section-title"><h2>{{ ui("Automated backup connectors") }}</h2><button v-if="canWrite" class="secondary" @click="openBackupConnector"><AppIcon name="plus" /> {{ ui("Add connector") }}</button></div><div v-if="!backupConnectors.length" class="empty compact">{{ ui("Connect Restic, Borg, Veeam, scripts, or any backup platform using the generic HTTPS webhook.") }}</div><div v-else class="schedule-list"><article v-for="item in backupConnectors" :key="item.id" class="schedule-row"><span :class="['status-dot',item.findingStatus?'down':item.enabled?'up':'down']"></span><span><strong>{{ item.name }}</strong><small>{{ item.assetName }} · {{ item.backupType }} {{ ui("· max age") }} {{ item.maxAgeHours }}h</small></span><span><small>{{ ui("Latest evidence") }}</small>{{ relative(item.lastReceivedAt) }}</span><span><small>{{ ui("Policy") }}</small>{{ item.findingStatus?item.findingExplanation:'HEALTHY' }}</span><button v-if="canWrite&&item.enabled" class="icon-button" @click="revokeBackupConnector(item)"><AppIcon name="trash" /></button></article></div></section>
        <section class="panel report-panel"><div class="section-title"><div><h2>{{ ui("Report delivery channels") }}</h2><span>{{ ui("Encrypted SMTP, S3, and immutable WORM destinations") }}</span></div><button v-if="canWrite" class="secondary" @click="openReportDelivery"><AppIcon name="plus" /> {{ ui("Add channel") }}</button></div><div v-if="!reportDeliveryChannels.length" class="empty compact">{{ ui("Add an Email or S3 destination, test it, then attach it to a report schedule.") }}</div><div v-else class="schedule-list"><article v-for="item in reportDeliveryChannels" :key="item.id" class="schedule-row"><span :class="['status-dot',item.enabled?'up':'down']"></span><span><strong>{{ item.name }} <b v-if="item.wormMode&&item.wormMode!=='NONE'" class="worm-badge">WORM {{ item.wormMode }}</b></strong><small>{{ item.type }} {{ ui("· credentials encrypted") }}<template v-if="item.wormMode&&item.wormMode!=='NONE'"> · {{ item.retentionDays }} {{ ui("days") }}</template><template v-if="item.legalHold"> {{ ui("· legal hold") }}</template></small></span><span><small>{{ ui("Status") }}</small>{{ item.enabled?'READY':'DISABLED' }}</span><span><small>{{ ui("Created") }}</small>{{ relative(item.createdAt) }}</span><button v-if="canWrite&&item.enabled" class="icon-button" @click="disableReportDelivery(item)"><AppIcon name="trash" /></button></article></div><div v-if="reportDeliveries.length" class="generated-list"><h3>{{ ui("Recent deliveries") }}</h3><div v-for="item in reportDeliveries.slice(0,10)" :key="item.id" class="delivery-history"><span :class="['status-dot',item.status==='DELIVERED'?'up':'down']"></span><span><strong>{{ item.channelName||item.channelType }} <b v-if="item.immutableVerified" class="worm-badge">WORM {{ item.wormMode||'LEGAL HOLD' }}</b></strong><small>{{ ui(item.status) }} · {{ item.destination||item.errorCode }} · {{ item.attempts }} {{ ui("attempt(s)") }}<template v-if="item.retainUntil"> {{ ui("· retained until") }} {{ displayDate(item.retainUntil) }}</template><template v-if="item.legalHold"> {{ ui("· legal hold ON") }}</template></small></span><time>{{ relative(item.deliveredAt||item.createdAt) }}</time></div></div></section>
        <section class="panel report-panel"><div class="section-title"><h2>{{ ui("Scheduled audit reports") }}</h2><button v-if="canWrite" class="secondary" @click="openReportSchedule"><AppIcon name="plus" /> {{ ui("Add schedule") }}</button></div><div v-if="!reportSchedules.length" class="empty compact">{{ ui("No report schedule configured.") }}</div><div v-else class="schedule-list"><article v-for="item in reportSchedules" :key="item.id" class="schedule-row"><span :class="['status-dot',item.enabled?'up':'down']"></span><span><strong>{{ item.name }}</strong><small>{{ item.formats.join(' + ') }} · {{ item.periodDays }}{{ ui("-day evidence window ·") }} {{ item.deliveryChannelIds.length }} {{ ui("destination(s)") }}</small></span><span><small>{{ ui("Frequency") }}</small>{{ item.frequency }}</span><span><small>{{ ui("Next run") }}</small>{{ relative(item.nextRunAt) }}</span><button v-if="canWrite&&item.enabled" class="icon-button" @click="disableReportSchedule(item)"><AppIcon name="trash" /></button></article></div><div v-if="generatedReports.length" class="generated-list"><h3>{{ ui("Generated files") }}</h3><a v-for="item in generatedReports.slice(0,10)" :key="item.id" :href="`/api/generated-reports/${item.id}/download`"><span><strong>{{ item.fileName||item.format }}</strong><small>{{ ui(item.status) }} · {{ Math.ceil(item.sizeBytes/1024) }} {{ ui("KB · SHA-256") }} {{ item.sha256.slice(0,12) }}…</small></span><time>{{ relative(item.createdAt) }}</time></a></div></section>
        <section class="security-note"><strong>{{ ui("Evidence integrity") }}</strong><p>{{ thai ? "Audit trail เชื่อมด้วย SHA-256; Evidence ZIP มี Manifest และ Hash รายไฟล์ ส่วน Excel รวมมีขอบเขต จำนวนข้อมูล และ SHA-256 ของไฟล์ การตรวจ Chain ผ่านไม่ได้ยืนยันว่าหลักฐานไม่เคยถูกล้างหรือครอบคลุมทุกระบบ" : "Audit events are linked by SHA-256. Evidence ZIP includes a manifest and per-file hashes; the combined Excel includes scope, row counts and a workbook checksum. A valid chain does not prove complete collection or absence of evidence cleanup." }}</p></section>
        <section class="settings-card audit-retention"><h2>{{ ui("Evidence retention policy") }}</h2><p>{{ thai ? "Log events ถูกล้างอัตโนมัติตามจำนวนวันที่ตั้ง และ WebSocket gaps เก็บประมาณ 30 วัน ผู้ดูแลสามารถล้างประวัติหรือรีเซ็ตข้อมูลจาก Settings ได้ ควรเก็บหลักฐานและไฟล์สำรองตามนโยบายก่อนล้าง" : "Log events are automatically purged after the configured retention; WebSocket gaps retain about 30 days. Admins can clean history or reset monitoring data in Settings. Archive required evidence and backups under your records policy before cleanup." }}</p><div class="retention-control"><label>{{ ui("Retention days") }}<input v-model.number="auditRetentionDays" type="number" min="90" max="3650"></label><button class="secondary" @click="saveAuditSettings">{{ ui("Save policy") }}</button></div></section>
      </template>

      <template v-else-if="activeView === 'users' && isAdmin">
        <header><div><h1>{{ t('page.users') }}</h1><p>{{ t('page.usersSub') }}</p></div><button class="primary" @click="openUserCreate"><AppIcon name="plus" /> {{ t('page.add') }}</button></header>
        <section class="panel page-panel"><div class="role-guide"><span><strong>ADMIN</strong><small>{{ ui("Full access and user management") }}</small></span><span><strong>OPERATOR</strong><small>{{ ui("Monitor and evidence operations") }}</small></span><span><strong>AUDITOR</strong><small>{{ ui("Read and export evidence") }}</small></span><span><strong>VIEWER</strong><small>{{ ui("Read-only dashboards") }}</small></span></div><div class="user-list"><button v-for="item in users" :key="item.id" class="user-row" @click="editUser(item)"><span :class="['status-dot',item.enabled?'up':'down']"></span><span><strong>{{ item.username }}</strong><small>{{ ui(item.id===session.user?.id?'Current account':'User account') }}</small></span><span :class="['role-pill',item.role.toLowerCase()]">{{ item.role }}</span><span><small>{{ ui("Last login") }}</small>{{ relative(item.lastLoginAt) }}</span><span><small>{{ ui("Status") }}</small>{{ ui(item.enabled?'Enabled':'Disabled') }}</span></button></div></section>
        <section class="security-note"><strong>{{ ui("Least privilege") }}</strong><p>{{ ui("Auditor and Viewer roles are enforced as read-only by the server API, not only hidden in the interface. User and role changes are written to the tamper-evident audit chain.") }}</p></section>
      </template>

      <template v-else>
        <header><div><h1>{{ t('settings.title') }}</h1><p>{{ t('settings.subtitle') }}</p></div></header>
        <div class="settings-grid">
          <DataManagement v-if="isAdmin" @cleaned="loadInfrastructure(); loadVulnerabilities(); loadHealth(); loadAudit(); loadIncidents(); loadDeliveries(); loadProjects()" />
          <section class="settings-card regional-card"><h2>{{ t('settings.regional') }}</h2><div class="form-grid"><label>{{ t('settings.language') }}<select :value="regionalForm.userLocale" :disabled="languageSaving" @change="changeLanguage(($event.target as HTMLSelectElement).value as Locale)"><option value="th-TH">ไทย</option><option value="en-US">English</option></select></label><label>{{ t('settings.userTimezone') }}<select v-model="regionalForm.userTimezone"><option value="SYSTEM">{{ t('settings.inherit') }}</option><option v-for="zone in regional?.supportedTimezones" :key="zone" :value="zone">{{ zone }}</option></select></label></div><dl><div><dt>{{ t('settings.browserTimezone') }}</dt><dd>{{ browserTimezone }}</dd></div><div><dt>{{ t('settings.serverTimezone') }}</dt><dd>{{ regional?.serverTimezone||'—' }}</dd></div><div><dt>{{ t('settings.serverTime') }}</dt><dd>{{ displayDate(regional?.serverNow||null) }}</dd></div></dl><button class="secondary" @click="savePreferences">{{ t('settings.savePreferences') }}</button><template v-if="isAdmin"><hr><div class="form-grid"><label>{{ t('settings.language') }}<select v-model="regionalForm.systemLocale"><option value="th-TH">ไทย</option><option value="en-US">English</option></select></label><label>{{ t('settings.systemTimezone') }}<select v-model="regionalForm.applicationTimezone"><option v-for="zone in regional?.supportedTimezones" :key="zone" :value="zone">{{ zone }}</option></select></label></div><button class="secondary" @click="saveRegionalDefaults">{{ t('settings.saveSystem') }}</button></template></section>
          <section class="settings-card"><h2>{{ ui("Application") }}</h2><dl><div><dt>{{ ui("Version") }}</dt><dd>2.3.0</dd></div><div><dt>{{ ui("Storage") }}</dt><dd>{{ ui("Encrypted SQLite volume") }}</dd></div><div><dt>{{ ui("Scheduler") }}</dt><dd>{{ ui("Active") }}</dd></div></dl></section>
          <section class="settings-card"><h2>{{ ui("Public status page") }}</h2><p>{{ ui("Publish selected monitors at") }} <a href="/status" target="_blank">/status <AppIcon name="external" /></a>.</p><label>{{ ui("Page title") }}<input v-model="statusTitle" maxlength="100"></label><button class="secondary" @click="saveStatusSettings">{{ ui("Save status page") }}</button></section>
          <section class="settings-card"><h2>{{ ui("Heartbeat setup SQL") }}</h2><p>{{ ui("Copy this script when preparing another Supabase project.") }}</p><button class="secondary" @click="copySetupSql"><AppIcon :name="copiedSetupSql?'check':'copy'" />{{ copiedSetupSql ? "Copied" : "Copy setup SQL" }}</button></section>
          <section class="settings-card"><h2>{{ ui("Multi-factor authentication") }}</h2><p>{{ ui("Protect this account with a TOTP authenticator and single-use recovery codes.") }}</p><strong :class="session.user?.mfaEnabled?'green':'muted'">{{ session.user?.mfaEnabled?'ENABLED':'NOT ENABLED' }}</strong><button v-if="!session.user?.mfaEnabled" class="secondary wide" @click="startMfaSetup">{{ ui("Set up MFA") }}</button><template v-else><button class="secondary wide" @click="regenerateRecoveryCodes">{{ ui("Generate new recovery codes") }}</button><button class="secondary wide" @click="disableMfa">{{ ui("Disable MFA") }}</button></template></section>
          <section v-if="isAdmin" class="settings-card regional-card"><h2>{{ ui("MFA enforcement policy") }}</h2><p>{{ ui("Require selected roles to enroll MFA before accessing monitoring or audit data. The policy cannot be saved while an affected active user is not enrolled.") }}</p><div class="role-policy"><label v-for="role in mfaPolicyRoles" :key="role" class="check"><input v-model="mfaRequiredRoles" type="checkbox" :value="role"> {{ role }}</label></div><button class="secondary" @click="saveMfaPolicy">{{ ui("Save MFA policy") }}</button></section>
          <section v-if="isAdmin" class="settings-card regional-card"><div class="section-title"><div><h2>{{ ui("OpenID Connect / SSO") }}</h2><p>{{ ui("Microsoft Entra ID, Google Workspace, Keycloak, or any standards-compatible provider.") }}</p></div><button class="secondary" @click="openOidcCreate"><AppIcon name="plus" /> {{ ui("Add provider") }}</button></div><div v-if="!oidcProviders.length" class="empty compact">{{ ui("No SSO provider configured. Local emergency login remains available.") }}</div><div v-for="provider in oidcProviders" :key="provider.id" class="provider-row"><span><strong>{{ provider.name }}</strong><small>{{ provider.preset }} {{ ui("· default") }} {{ provider.defaultRole }}</small></span><span :class="['status-pill',provider.enabled?'up':'disabled']">{{ provider.enabled?'ACTIVE':'DISABLED' }}</span><button v-if="provider.enabled" class="icon-button" @click="disableOidcProvider(provider)"><AppIcon name="trash" /></button></div><p class="field-note">{{ ui("Uses Authorization Code + PKCE and state/nonce validation. Client secrets are encrypted at rest.") }}</p></section>
          <section class="settings-card danger-card"><h2>{{ ui("Session") }}</h2><p>{{ ui("Sign out of the current Byakugan session.") }}</p><button class="secondary" @click="logout">{{ ui("Sign out") }}</button></section>
        </div>
      </template>
    </section>
  </div>

  <div v-if="showOidcForm" class="modal-backdrop" @click.self="showOidcForm=false"><form class="modal" @submit.prevent="saveOidcProvider"><div class="modal-head"><div><h2>{{ ui("Add OpenID Connect provider") }}</h2><p>{{ ui("Register the callback URL shown after saving in the identity provider.") }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showOidcForm=false"><AppIcon name="x" /></button></div><div class="form-grid"><label>{{ ui("Name") }}<input v-model="oidcForm.name" required maxlength="100" :placeholder="ui('Company SSO')"></label><label>{{ ui("Preset") }}<select v-model="oidcForm.preset"><option>GENERIC</option><option>ENTRA</option><option>GOOGLE</option><option>KEYCLOAK</option></select></label></div><label>{{ ui("Issuer URL") }}<input v-model="oidcForm.issuerUrl" required type="url" placeholder="https://login.microsoftonline.com/tenant-id/v2.0"></label><label>{{ ui("Client ID") }}<input v-model="oidcForm.clientId" required autocomplete="off"></label><label>{{ ui("Client secret") }}<input v-model="oidcForm.clientSecret" required type="password" autocomplete="new-password"></label><div class="form-grid"><label>{{ ui("Scopes") }}<input v-model="oidcForm.scopes" required></label><label>{{ ui("Default role") }}<select v-model="oidcForm.defaultRole"><option>VIEWER</option><option>AUDITOR</option><option>OPERATOR</option><option>ADMIN</option></select></label></div><label>{{ ui("Allowed email domains") }} <small>{{ ui("(comma-separated, blank allows all)") }}</small><input v-model="oidcForm.allowedDomains" placeholder="example.com, subsidiary.co.th"></label><div class="form-grid"><label>{{ ui("Username claim") }}<input v-model="oidcForm.usernameClaim" required></label><label>{{ ui("Groups claim") }}<input v-model="oidcForm.groupsClaim" required></label></div><label>{{ ui("Role mapping JSON") }}<textarea v-model="oidcForm.roleMapping" rows="4" placeholder='{"ADMIN":["security-admins"],"OPERATOR":["it-ops"]}'></textarea></label><label class="check"><input v-model="oidcForm.jitProvisioning" type="checkbox"> {{ ui("Automatically create approved users on first sign-in (JIT)") }}</label><p v-if="error" class="error-banner">{{ error }}</p><div class="modal-actions"><button type="button" class="secondary" @click="showOidcForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy">{{ busy?'Testing discovery…':'Test and save' }}</button></div></form></div>

  <div v-if="showShareForm" class="modal-backdrop" @click.self="showShareForm = false">
    <form class="modal share-modal" @submit.prevent="saveShareDashboard">
      <div class="modal-head"><div><h2>{{ t('form.createShare') }}</h2><p>{{ t('form.createShareSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showShareForm = false"><AppIcon name="x" /></button></div>
      <label>{{ t('form.dashboardName') }}<input v-model="shareForm.name" required maxlength="100" placeholder="Customer services status"></label>
      <fieldset class="share-project-picker"><legend>{{ t('form.monitorsGroups') }}</legend><article v-for="project in projects" :key="project.id"><label class="check"><input v-model="shareForm.selections[project.id].selected" type="checkbox"><span><strong>{{ project.name }}</strong><small>{{ project.monitorType }}</small></span></label><label v-if="shareForm.selections[project.id].selected">{{ t('form.group') }}<input v-model="shareForm.selections[project.id].groupName" required maxlength="80" :placeholder="ui('Services')"></label></article></fieldset>
      <p class="field-note">{{ ui("The generated link contains a random 192-bit token. Anyone holding it can view this dashboard, but cannot access targets, keys, or administrator functions.") }}</p>
      <p v-if="error" class="error-banner">{{ error }}</p>
      <div class="modal-actions"><button type="button" class="secondary" @click="showShareForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy">{{ busy?'Creating…':'Create secure link' }}</button></div>
    </form>
  </div>

  <div v-if="showAuditForm" class="modal-backdrop" @click.self="showAuditForm=false">
    <form class="modal audit-modal" @submit.prevent="saveAuditProfile"><div class="modal-head"><div><h2>{{ t('form.auditProfile') }} · {{ auditForm.name }}</h2><p>{{ t('form.auditProfileSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showAuditForm=false"><AppIcon name="x" /></button></div>
      <div class="form-grid"><label>{{ t('form.assetTag') }}<input v-model="auditForm.assetTag" maxlength="100" placeholder="SRV-PROD-001"></label><label>{{ t('form.owner') }}<input v-model="auditForm.assetOwner" maxlength="150" placeholder="Infrastructure team"></label></div>
      <div class="form-grid"><label>{{ t('form.environment') }}<select v-model="auditForm.environment"><option value="Production">{{ ui("Production") }}</option><option value="Staging">{{ ui("Staging") }}</option><option value="Development">{{ ui("Development") }}</option><option>DR</option><option value="Other">{{ ui("Other") }}</option></select></label><label>{{ t('form.criticality') }}<select v-model="auditForm.criticality"><option value="Low">{{ ui("Low") }}</option><option value="Medium">{{ ui("Medium") }}</option><option value="High">{{ ui("High") }}</option><option value="Critical">{{ ui("Critical") }}</option></select></label></div>
      <fieldset><legend>{{ t('form.metricPolicy') }}</legend><div class="form-grid"><label>{{ t('form.warning') }}<input v-model.number="auditForm.warningThreshold" type="number" step="any" placeholder="70"></label><label>{{ t('form.critical') }}<input v-model.number="auditForm.criticalThreshold" type="number" step="any" placeholder="85"></label></div><div class="form-grid"><label>{{ ui("Operator") }}<select v-model="auditForm.thresholdOperator"><option>&gt;=</option><option>&gt;</option><option>&lt;=</option><option>&lt;</option></select></label><label>{{ t('form.duration') }}<input v-model.number="auditForm.thresholdDurationSeconds" type="number" min="0" max="86400"></label></div></fieldset>
      <fieldset class="control-picker"><legend>{{ t('form.controls') }}</legend><label v-for="control in isoControls" :key="control.id" class="check"><input v-model="auditForm.controlIds" type="checkbox" :value="control.id"><span><strong>{{ control.code }}</strong><small>{{ control.title }}</small></span></label></fieldset>
      <p v-if="error" class="error-banner">{{ error }}</p><div class="modal-actions"><button type="button" class="secondary" @click="showAuditForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy">{{ ui("Save audit profile") }}</button></div>
    </form>
  </div>

  <div v-if="showAgentForm" class="modal-backdrop" @click.self="showAgentForm=false">
    <form class="modal" @submit.prevent="createAgent"><div class="modal-head"><div><h2>{{ t('form.enrollServer') }}</h2><p>{{ t('form.enrollServerSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showAgentForm=false"><AppIcon name="x" /></button></div>
      <template v-if="!enrollmentToken"><label>{{ t('form.agentName') }}<input v-model="agentForm.name" required maxlength="100" placeholder="PROD-API-01"></label><div class="modal-actions"><button type="button" class="secondary" @click="showAgentForm=false">{{ t('form.cancel') }}</button><button class="primary" :disabled="busy">{{ t('form.createToken') }}</button></div></template>
      <template v-else><section class="token-result"><strong>{{ ui("ติดตั้ง Agent") }}</strong><p>{{ ui("เลือก OS แล้วคัดลอกคำสั่งเดียวไปรันบนเครื่องปลายทาง Token จะแสดงเฉพาะครั้งนี้") }}</p><div class="platform-picker"><button type="button" :class="agentPlatform==='linux'?'active':''" @click="agentPlatform='linux'">Linux</button><button type="button" :class="agentPlatform==='windows'?'active':''" @click="agentPlatform='windows'">Windows</button></div><pre class="agent-command">{{ agentInstallCommand }}</pre><button type="button" class="primary" @click="copyAgentInstallCommand">{{ ui("Copy install command") }}</button><details><summary>{{ ui("ดู Token แยก") }}</summary><textarea readonly :value="enrollmentToken"></textarea><button type="button" class="secondary" @click="copyAgentToken">{{ ui("Copy token") }}</button></details></section><p class="field-note">{{ agentPlatform==='windows'?'เปิด PowerShell แบบ Run as administrator แล้ววางคำสั่ง':'เปิด Terminal บน Linux แล้ววางคำสั่ง ระบบจะขอรหัส sudo' }}</p><div class="modal-actions"><button type="button" class="primary" @click="showAgentForm=false">{{ ui("Done") }}</button></div></template>
    </form>
  </div>

  <div v-if="showFindingForm" class="modal-backdrop" @click.self="showFindingForm=false"><form class="modal" @submit.prevent="saveFinding"><p v-if="error" class="error-banner" role="alert">{{ error }}</p><div class="modal-head"><div><h2>{{ findingForm.title }}</h2><p>{{ t('modal.findingSub') }}</p><p class="finding-modal-asset"><AppIcon name="server" /> {{ t('actions.asset') }}: {{ findingForm.hostname||findingForm.agentName||t('actions.unknownAsset') }}<template v-if="findingForm.hostname&&findingForm.agentName&&findingForm.hostname!==findingForm.agentName"> · {{ t('actions.agent') }}: {{ findingForm.agentName }}</template></p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showFindingForm=false"><AppIcon name="x" /></button></div><FindingDetails v-if="selectedFinding" :finding="selectedFinding" :first-detected="displayDate(selectedFinding.firstDetectedAt)" :last-detected="displayDate(selectedFinding.lastDetectedAt??null)" /><fieldset :disabled="!canWrite" class="finding-workflow-fields"><div class="form-grid"><label>{{ t('modal.status') }}<select v-model="findingForm.status"><option value="OPEN">{{ t('actions.statuses.OPEN') }}</option><option value="ACKNOWLEDGED">{{ t('actions.statuses.ACKNOWLEDGED') }}</option><option value="RESOLVED">{{ t('actions.statuses.RESOLVED') }}</option></select></label><label>{{ t('modal.owner') }}<input v-model="findingForm.owner" maxlength="150" placeholder="Infrastructure team"></label></div><label>{{ t('modal.dueDate') }}<input v-model="findingForm.dueAt" type="datetime-local"></label><label>{{ t('modal.resolution') }}<textarea v-model="findingForm.resolutionNote" maxlength="2000" :placeholder="thai ? 'ระบุสิ่งที่แก้ วันเวลา และผลตรวจยืนยันหลังแก้' : 'Record changes, time and verification results'"></textarea></label></fieldset><div class="modal-actions"><button type="button" class="secondary" @click="showFindingForm=false">{{ t('modal.cancel') }}</button><button v-if="canWrite" class="primary" :disabled="busy">{{ t('modal.saveWorkflow') }}</button></div></form></div>

  <div v-if="selectedScanJob" class="modal-backdrop" @click.self="selectedScanJob=null"><section class="modal scan-result-modal"><div class="modal-head"><div><h2>{{ ui("ผลสแกน #") }}{{ selectedScanJob.id }}</h2><p>{{ selectedScanJob.agentName }} · {{ selectedScanJob.targetType }} · {{ selectedScanJob.target }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="selectedScanJob=null"><AppIcon name="x" /></button></div><div class="scan-result-summary"><article v-for="level in ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']" :key="level" :class="level.toLowerCase()"><small>{{ level }}</small><strong>{{ Number(selectedScanJob.resultSummary?.[level]||0) }}</strong></article></div><section v-if="!selectedScanJob.findings.length" class="scan-clean-result"><span><AppIcon name="check" /></span><div><strong>{{ ui("ตรวจสอบเสร็จแล้ว ไม่พบรายการตามเงื่อนไข") }}</strong><p>{{ ui("Trivy สแกนสำเร็จ") }} {{ Number(selectedScanJob.resultSummary?.durationMs||0).toLocaleString(locale) }} {{ ui("ms และไม่พบช่องโหว่ การตั้งค่าผิด หรือ secret ในระดับที่โปรไฟล์กำหนด") }}</p></div></section><div v-else class="scan-finding-list"><article v-for="finding in selectedScanJob.findings" :key="`${finding.id}-${finding.packageName}`"><b :class="['criticality',finding.severity.toLowerCase()]">{{ ui(finding.severity) }}</b><span><strong>{{ finding.id }}</strong><small>{{ finding.title||finding.type }}</small></span><span><small>{{ ui("Package / resource") }}</small>{{ finding.packageName }} {{ finding.installedVersion }}<small v-if="finding.resourcePath">{{ finding.resourcePath }}</small></span><span><small>{{ ui("Fixed version") }}</small>{{ ui(finding.fixedVersion||'Not published') }}</span></article></div><div class="scan-result-meta"><span>{{ ui("Scanner duration:") }} {{ Number(selectedScanJob.resultSummary?.durationMs||0).toLocaleString(locale) }} ms</span><span>{{ ui("Completed:") }} {{ selectedScanJob.completedAt?displayDate(selectedScanJob.completedAt):'—' }}</span><span v-if="selectedScanJob.resultSummary?.truncated">{{ ui("ผลลัพธ์ถูกตัดตามขีดจำกัด") }}</span></div></section></div>

  <div v-if="showScanScheduleForm" class="modal-backdrop" @click.self="showScanScheduleForm=false"><form class="modal" @submit.prevent="createScanSchedule"><div class="modal-head"><div><h2>{{ ui("Schedule security scan") }}</h2><p>{{ ui("Run a reusable, centrally managed Trivy scan profile automatically.") }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showScanScheduleForm=false"><AppIcon name="x" /></button></div><label>{{ ui("Schedule name") }}<input v-model="scanScheduleForm.name" required maxlength="120" placeholder="Weekly production security scan"></label><div class="form-grid"><label>Agent<select v-model.number="scanScheduleForm.agentId" required><option :value="0" disabled>{{ ui("Select agent") }}</option><option v-for="agent in agents.filter(x=>x.enabled)" :key="agent.id" :value="agent.id">{{ agent.hostname||agent.name }}</option></select></label><label>{{ ui("Scan profile") }}<select v-model.number="scanScheduleForm.profileId" required @change="applyScheduleProfile(scanScheduleForm.profileId)"><option v-for="profile in scanProfiles" :key="profile.id" :value="profile.id">{{ profile.name }}</option></select></label></div><label>{{ ui("Target") }}<input v-model="scanScheduleForm.target" required maxlength="500" placeholder="/ or registry/image:tag"></label><div class="form-grid"><label>{{ ui("Frequency") }}<select v-model="scanScheduleForm.frequency"><option value="DAILY">{{ ui("Daily") }}</option><option value="WEEKLY">{{ ui("Weekly") }}</option></select></label><label>{{ ui("First run") }}<input v-model="scanScheduleForm.firstRunAt" required type="datetime-local"></label></div><p class="field-note">{{ ui("The following runs use the same local time and are queued only when no matching scan is active.") }}</p><p v-if="error" class="error-banner">{{ error }}</p><div class="modal-actions"><button type="button" class="secondary" @click="showScanScheduleForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy||!scanScheduleForm.agentId||!scanScheduleForm.profileId">{{ busy?'Saving…':'Create schedule' }}</button></div></form></div>

  <div v-if="showScanJobForm" class="modal-backdrop" @click.self="showScanJobForm=false"><form class="modal" @submit.prevent="createScanJob"><div class="modal-head"><div><h2>{{ ui("Start security scan") }}</h2><p>{{ ui("Queue an allowlisted Trivy scan on an enrolled agent.") }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showScanJobForm=false"><AppIcon name="x" /></button></div><label>Agent<select v-model.number="scanJobForm.agentId" required @change="ensureCompatibleScanProfile"><option :value="0" disabled>{{ ui("Select agent") }}</option><option v-for="agent in agents.filter(x=>x.enabled)" :key="agent.id" :value="agent.id">{{ agent.hostname||agent.name }}</option></select></label><label>{{ ui("Scan profile") }}<select v-model.number="scanJobForm.profileId" required @change="applyScanProfile(scanJobForm.profileId)"><option v-for="profile in compatibleScanProfiles(scanJobForm.agentId)" :key="profile.id" :value="profile.id">{{ profile.name }}</option></select><small v-if="/windows/i.test(agents.find(x=>x.id===scanJobForm.agentId)?.osName||'')" class="field-note">{{ ui("Windows รองรับ Quick vulnerabilities และ Container image security; ROOTFS ใช้สำหรับ Linux เท่านั้น") }}</small></label><div class="form-grid"><label>{{ ui("Target type") }}<select v-model="scanJobForm.targetType" disabled><option value="FILESYSTEM">{{ ui("Filesystem") }}</option><option value="ROOTFS">{{ ui("Root filesystem") }}</option><option value="IMAGE">{{ ui("Container image") }}</option></select></label><label>{{ ui("Target") }}<input v-model="scanJobForm.target" required maxlength="500" :placeholder="scanJobForm.targetType==='IMAGE'?'registry/image:tag':'/'"></label></div><fieldset class="notification-picker"><legend>{{ ui("Profile scanners") }}</legend><label class="check"><input v-model="scanJobForm.scanners" disabled type="checkbox" value="vuln"> {{ ui("Vulnerabilities") }}</label><label class="check"><input v-model="scanJobForm.scanners" disabled type="checkbox" value="misconfig"> {{ ui("Misconfiguration") }}</label><label class="check"><input v-model="scanJobForm.scanners" disabled type="checkbox" value="secret"> {{ ui("Exposed secrets") }}</label></fieldset><p class="field-note">{{ ui("The agent runs Trivy directly without a shell. Profile rules are enforced again by the server before the job is queued.") }}</p><p v-if="error" class="error-banner">{{ error }}</p><div class="modal-actions"><button type="button" class="secondary" @click="showScanJobForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy||!scanJobForm.agentId||!scanJobForm.profileId">{{ busy?'Queuing…':'Queue scan' }}</button></div></form></div>

  <div v-if="showVulnerabilityForm" class="modal-backdrop" @click.self="showVulnerabilityForm=false"><form class="modal" @submit.prevent="saveVulnerability"><div class="modal-head"><div><h2>{{ vulnerabilityForm.title }}</h2><p>{{ t('modal.vulnerabilitySub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showVulnerabilityForm=false"><AppIcon name="x" /></button></div><div class="form-grid"><label>{{ t('modal.status') }}<select v-model="vulnerabilityForm.status"><option value="OPEN">{{ ui("OPEN") }}</option><option value="IN_PROGRESS">{{ ui("IN_PROGRESS") }}</option><option value="RISK_ACCEPTED">{{ ui("RISK_ACCEPTED") }}</option><option value="RESOLVED">{{ ui("RESOLVED") }}</option></select></label><label>{{ t('modal.owner') }}<input v-model="vulnerabilityForm.owner" maxlength="150" placeholder="Security team"></label></div><label>{{ t('modal.remediationDue') }}<input v-model="vulnerabilityForm.dueAt" type="datetime-local"></label><template v-if="vulnerabilityForm.status==='RISK_ACCEPTED'"><label>{{ t('modal.riskReason') }}<textarea v-model="vulnerabilityForm.riskReason" required maxlength="2000"></textarea></label><label>{{ t('modal.riskExpires') }}<input v-model="vulnerabilityForm.riskExpiresAt" required type="datetime-local"></label></template><div class="modal-actions"><button type="button" class="secondary" @click="showVulnerabilityForm=false">{{ t('modal.cancel') }}</button><button v-if="canWrite" class="primary" :disabled="busy">{{ t('modal.saveWorkflow') }}</button></div></form></div>

  <div v-if="showUserForm" class="modal-backdrop" @click.self="showUserForm=false"><form class="modal" @submit.prevent="saveUser"><div class="modal-head"><div><h2>{{ userForm.id?t('modal.editUser'):t('modal.addUser') }}</h2><p>{{ t('modal.userSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showUserForm=false"><AppIcon name="x" /></button></div><label>{{ t('modal.username') }}<input v-model="userForm.username" required minlength="3" maxlength="64" :disabled="Boolean(userForm.id)"></label><div class="form-grid"><label>{{ t('modal.role') }}<select v-model="userForm.role"><option>ADMIN</option><option>OPERATOR</option><option>AUDITOR</option><option>VIEWER</option></select></label><label v-if="userForm.id" class="check user-enabled"><input v-model="userForm.enabled" type="checkbox"> {{ t('modal.accountEnabled') }}</label></div><label>{{ userForm.id?t('modal.newPassword'):t('modal.initialPassword') }}<input v-model="userForm.password" :required="!userForm.id" type="password" minlength="10" maxlength="256" autocomplete="new-password"></label><section v-if="userForm.id&&userForm.mfaEnabled" class="security-note"><strong>{{ ui("MFA enabled") }}</strong><p>{{ ui("An administrator may reset another user's authenticator and recovery codes. The action is written to the audit chain.") }}</p><button v-if="userForm.id!==session?.user?.id" type="button" class="secondary" @click="resetUserMfa">{{ ui("Reset user MFA") }}</button></section><p v-if="error" class="error-banner">{{ error }}</p><div class="modal-actions"><button type="button" class="secondary" @click="showUserForm=false">{{ t('modal.cancel') }}</button><button class="primary" :disabled="busy">{{ t('modal.saveUser') }}</button></div></form></div>

  <div v-if="showMfaForm&&mfaSetup" class="modal-backdrop" @click.self="showMfaForm=false"><form class="modal mfa-modal" @submit.prevent="enableMfa"><div class="modal-head"><div><h2>{{ t('setup.mfaTitle') }}</h2><p v-if="!mfaRecoveryCodes.length">{{ t('setup.mfaScan') }}</p><p v-else>{{ t('setup.mfaEnabled') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showMfaForm=false"><AppIcon name="x" /></button></div><template v-if="!mfaRecoveryCodes.length"><img class="mfa-qr" :src="mfaSetup.qrDataUrl" alt="TOTP setup QR code"><section class="token-result"><strong>{{ t('setup.manualSecret') }}</strong><p>{{ t('setup.manualSecretSub') }}</p><textarea readonly :value="mfaSetup.secret"></textarea></section><label>{{ t('setup.verificationCode') }}<input v-model="mfaCode" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></label><div class="modal-actions"><button type="button" class="secondary" @click="showMfaForm=false">{{ t('setup.cancel') }}</button><button class="primary">{{ t('setup.enableMfa') }}</button></div></template><template v-else><section class="recovery-warning"><strong>{{ t('setup.storeRecovery') }}</strong><p>{{ t('setup.recoverySub') }}</p></section><div class="recovery-grid"><code v-for="code in mfaRecoveryCodes" :key="code">{{ code }}</code></div><div class="modal-actions"><button type="button" class="secondary" @click="copyRecoveryCodes">{{ t('setup.copyCodes') }}</button><button type="button" class="primary" @click="showMfaForm=false;mfaSetup=null;mfaRecoveryCodes=[]">{{ t('setup.savedCodes') }}</button></div></template></form></div>

  <div v-if="showBackupForm" class="modal-backdrop" @click.self="showBackupForm=false"><form class="modal" @submit.prevent="saveBackup"><div class="modal-head"><div><h2>{{ t('modal.backupTitle') }}</h2><p>{{ t('modal.backupSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showBackupForm=false"><AppIcon name="x" /></button></div><div class="form-grid"><label>{{ t('modal.assetName') }}<input v-model="backupForm.assetName" required maxlength="150" placeholder="PROD-DB-01"></label><label>{{ t('modal.backupType') }}<select v-model="backupForm.backupType"><option>FULL</option><option>INCREMENTAL</option><option>SNAPSHOT</option><option>DATABASE</option><option>CONFIGURATION</option></select></label></div><label>{{ t('modal.storageLocation') }}<input v-model="backupForm.storageLocation" required maxlength="500" placeholder="S3 immutable vault / NAS / cloud snapshot"></label><div class="form-grid"><label>{{ t('modal.status') }}<select v-model="backupForm.status"><option value="SUCCESS">{{ ui("SUCCESS") }}</option><option value="WARNING">{{ ui("WARNING") }}</option><option value="FAILED">{{ ui("FAILED") }}</option></select></label><label>{{ t('modal.sizeBytes') }}<input v-model.number="backupForm.sizeBytes" type="number" min="0"></label></div><div class="form-grid"><label>{{ t('modal.startedAt') }}<input v-model="backupForm.startedAt" required type="datetime-local"></label><label>{{ t('modal.completedAt') }}<input v-model="backupForm.completedAt" type="datetime-local"></label></div><label>{{ t('modal.checksum') }}<input v-model="backupForm.checksum" maxlength="256"></label><label>{{ t('modal.evidenceNote') }}<textarea v-model="backupForm.notes" maxlength="2000"></textarea></label><div class="modal-actions"><button type="button" class="secondary" @click="showBackupForm=false">{{ t('modal.cancel') }}</button><button class="primary" :disabled="busy">{{ t('modal.recordEvidence') }}</button></div></form></div>

  <div v-if="showBackupConnectorForm" class="modal-backdrop" @click.self="showBackupConnectorForm=false"><form class="modal" @submit.prevent="saveBackupConnector"><div class="modal-head"><div><h2>{{ t('setup.connectorTitle') }}</h2><p>{{ t('setup.connectorSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showBackupConnectorForm=false"><AppIcon name="x" /></button></div><template v-if="!backupConnectorToken"><label>{{ t('setup.connectorName') }}<input v-model="backupConnectorForm.name" required maxlength="120" placeholder="Nightly PostgreSQL backup"></label><div class="form-grid"><label>{{ t('modal.assetName') }}<input v-model="backupConnectorForm.assetName" required maxlength="150" placeholder="PROD-DB-01"></label><label>{{ t('modal.backupType') }}<select v-model="backupConnectorForm.backupType"><option>FULL</option><option>INCREMENTAL</option><option>SNAPSHOT</option><option>DATABASE</option><option>CONFIGURATION</option></select></label></div><label>{{ t('setup.maxAge') }}<input v-model.number="backupConnectorForm.maxAgeHours" required type="number" min="1" max="8760"></label><div class="modal-actions"><button type="button" class="secondary" @click="showBackupConnectorForm=false">{{ t('setup.cancel') }}</button><button class="primary" :disabled="busy">{{ t('setup.createConnector') }}</button></div></template><template v-else><section class="token-result"><strong>{{ t('setup.copyToken') }}</strong><p>{{ t('setup.tokenSub') }}</p><textarea readonly :value="backupConnectorToken"></textarea></section><pre class="agent-command">POST {{ appOrigin }}/api/backup/ingest<br>Authorization: Bearer &lt;token&gt;<br>Content-Type: application/json<br><br>{ "status":"SUCCESS", "startedAt":"ISO-8601", "completedAt":"ISO-8601", "storageLocation":"s3://backup/object", "checksum":"sha256..." }</pre><div class="modal-actions"><button type="button" class="primary" @click="showBackupConnectorForm=false">{{ t('setup.done') }}</button></div></template></form></div>

  <div v-if="showIncidentForm" class="modal-backdrop" @click.self="showIncidentForm=false"><form class="modal audit-modal" @submit.prevent="saveIncident()"><p v-if="error" class="error-banner" role="alert">{{ error }}</p><div class="modal-head"><div><h2>{{ incidentForm.title }}</h2><p>{{ t('modal.incidentSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showIncidentForm=false"><AppIcon name="x" /></button></div><IncidentDetails v-if="selectedIncident" :incident="selectedIncident" :started="displayDate(selectedIncident.startedAt)" :recovered="displayDate(selectedIncident.resolvedAt)" :reviewed="displayDate(selectedIncident.reviewedAt)" /><fieldset :disabled="!canWrite" class="finding-workflow-fields"><div class="form-grid"><label>{{ t('modal.severity') }}<select v-model="incidentForm.severity"><option value="LOW">{{ ui("LOW") }}</option><option value="MEDIUM">{{ ui("MEDIUM") }}</option><option value="HIGH">{{ ui("HIGH") }}</option><option value="CRITICAL">{{ ui("CRITICAL") }}</option></select></label><label>{{ t('modal.owner') }}<input v-model="incidentForm.owner" maxlength="150" placeholder="Operations lead"></label></div><p class="workflow-note">{{ thai ? 'APPROVED คืออนุมัติผลทบทวน ปุ่มบันทึกและปิดเคสใช้จบงานเอกสาร ส่วนสถานะบริการยังแสดงตามการตรวจจริง' : 'APPROVED approves the review. Save and close case completes the case workflow; service status still reflects actual monitoring.' }}</p><p v-if="incidentForm.closedAt" class="workflow-result">{{ thai ? 'ปิดเคสแล้ว' : 'Case closed' }} · {{ displayDate(incidentForm.closedAt) }}</p><label>{{ t('modal.reviewStatus') }}<select v-model="incidentForm.reviewStatus"><option value="PENDING">{{ ui("PENDING") }}</option><option value="IN_REVIEW">{{ ui("IN_REVIEW") }}</option><option value="APPROVED">{{ ui("APPROVED") }}</option></select></label><label>{{ t('modal.rootCause') }}<textarea :placeholder="thai ? 'ระบุสาเหตุที่ยืนยันจากหลักฐาน ไม่ใช่เพียงอาการหรือข้อสันนิษฐาน' : 'Record the evidence-backed cause, not only the symptom'" v-model="incidentForm.rootCause" :required="incidentForm.reviewStatus==='APPROVED'" maxlength="4000"></textarea></label><label>{{ t('modal.correctiveAction') }}<textarea :placeholder="thai ? 'ระบุสิ่งที่แก้ วันเวลา ผู้ดำเนินการ และผลทดสอบหลังแก้' : 'Record the change, time, owner and verification results'" v-model="incidentForm.correctiveAction" :required="incidentForm.reviewStatus==='APPROVED'" maxlength="4000"></textarea></label><label>{{ t('modal.lessons') }}<textarea v-model="incidentForm.lessonsLearned" maxlength="4000"></textarea></label></fieldset><div class="modal-actions"><button type="button" class="secondary" @click="showIncidentForm=false">{{ t('modal.cancel') }}</button><button v-if="canWrite" class="secondary" :disabled="busy">{{ t('modal.saveReview') }}</button><button v-if="canWrite&&!incidentForm.closedAt" type="button" class="primary" :disabled="busy||!incidentForm.rootCause.trim()||!incidentForm.correctiveAction.trim()" @click="saveIncident(true)"><AppIcon name="closecase" />{{ thai ? 'บันทึกและปิดเคส' : 'Save and close case' }}</button></div></form></div>

  <div v-if="showRestoreForm" class="modal-backdrop" @click.self="showRestoreForm=false"><form class="modal" @submit.prevent="saveRestore"><div class="modal-head"><div><h2>{{ t('modal.restoreTitle') }}</h2><p>{{ t('modal.restoreSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showRestoreForm=false"><AppIcon name="x" /></button></div><label>{{ t('modal.relatedBackup') }}<select v-model="restoreForm.backupEvidenceId"><option :value="null">{{ t('modal.notLinked') }}</option><option v-for="item in backups" :key="item.id" :value="item.id">#{{ item.id }} · {{ item.assetName }} · {{ displayDate(item.startedAt) }}</option></select></label><label>{{ t('modal.assetName') }}<input v-model="restoreForm.assetName" required maxlength="150" placeholder="PROD-DB-01"></label><label>{{ t('modal.testScope') }}<input v-model="restoreForm.testScope" required maxlength="500"></label><div class="form-grid"><label>{{ t('modal.result') }}<select v-model="restoreForm.result"><option value="PASS">{{ ui("PASS") }}</option><option value="PARTIAL">{{ ui("PARTIAL") }}</option><option value="FAIL">{{ ui("FAIL") }}</option></select></label><label>{{ t('modal.testedAt') }}<input v-model="restoreForm.testedAt" required type="datetime-local"></label></div><div class="form-grid"><label>{{ t('modal.targetRto') }}<input v-model.number="restoreForm.rtoMinutes" type="number" min="0"></label><label>{{ t('modal.actualRecovery') }}<input v-model.number="restoreForm.actualMinutes" type="number" min="0"></label></div><label>{{ t('modal.evidenceNote') }}<textarea v-model="restoreForm.evidenceNote" maxlength="2000"></textarea></label><div class="modal-actions"><button type="button" class="secondary" @click="showRestoreForm=false">{{ t('modal.cancel') }}</button><button class="primary" :disabled="busy">{{ t('modal.recordTest') }}</button></div></form></div>

  <div v-if="showReportScheduleForm" class="modal-backdrop" @click.self="showReportScheduleForm=false"><form class="modal" @submit.prevent="saveReportSchedule"><div class="modal-head"><div><h2>{{ t('modal.scheduleTitle') }}</h2><p>{{ t('modal.scheduleSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showReportScheduleForm=false"><AppIcon name="x" /></button></div><label>{{ t('modal.scheduleName') }}<input v-model="reportScheduleForm.name" required maxlength="120"></label><div class="form-grid"><label>{{ t('modal.frequency') }}<select v-model="reportScheduleForm.frequency"><option value="WEEKLY">{{ ui("WEEKLY") }}</option><option value="MONTHLY">{{ ui("MONTHLY") }}</option></select></label><label>{{ t('modal.evidenceWindow') }}<input v-model.number="reportScheduleForm.periodDays" required type="number" min="7" max="365"></label></div><fieldset class="notification-picker"><legend>{{ t('modal.formats') }}</legend><label class="check"><input v-model="reportScheduleForm.formats" type="checkbox" value="PDF"> PDF</label><label class="check"><input v-model="reportScheduleForm.formats" type="checkbox" value="XLSX"> XLSX</label></fieldset><fieldset v-if="reportDeliveryChannels.filter(x=>x.enabled).length" class="notification-picker"><legend>{{ ui("Automatic delivery destinations") }}</legend><label v-for="channel in reportDeliveryChannels.filter(x=>x.enabled)" :key="channel.id" class="check"><input v-model="reportScheduleForm.deliveryChannelIds" type="checkbox" :value="channel.id"> {{ channel.name }} <small>{{ channel.type }}</small></label></fieldset><p v-else class="field-note">{{ ui("No delivery channel selected. Reports will still be generated and available for download.") }}</p><label class="check"><input v-model="reportScheduleForm.enabled" type="checkbox"> {{ t('modal.enableSchedule') }}</label><div class="modal-actions"><button type="button" class="secondary" @click="showReportScheduleForm=false">{{ t('modal.cancel') }}</button><button class="primary" :disabled="busy||!reportScheduleForm.formats.length">{{ t('modal.createSchedule') }}</button></div></form></div>

  <div v-if="showReportDeliveryForm" class="modal-backdrop" @click.self="showReportDeliveryForm=false"><form class="modal" @submit.prevent="saveReportDelivery"><div class="modal-head"><div><h2>{{ ui("Add report delivery channel") }}</h2><p>{{ ui("The connection is tested before encrypted credentials are saved.") }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showReportDeliveryForm=false"><AppIcon name="x" /></button></div><div class="form-grid"><label>{{ ui("Channel name") }}<input v-model="reportDeliveryForm.name" required maxlength="120" placeholder="Audit mailbox"></label><label>{{ ui("Type") }}<select v-model="reportDeliveryForm.type"><option value="SMTP">Email / SMTP</option><option value="S3">{{ ui("S3-compatible storage") }}</option></select></label></div><template v-if="reportDeliveryForm.type==='SMTP'"><div class="form-grid"><label>{{ ui("SMTP host") }}<input v-model="reportDeliveryForm.host" required placeholder="smtp.example.com"></label><label>{{ ui("Port") }}<input v-model.number="reportDeliveryForm.port" required type="number" min="1" max="65535"></label></div><label class="check"><input v-model="reportDeliveryForm.secure" type="checkbox"> {{ ui("Implicit TLS (usually port 465)") }}</label><div class="form-grid"><label>{{ ui("Username") }}<input v-model="reportDeliveryForm.username" autocomplete="off"></label><label>{{ ui("Password") }}<input v-model="reportDeliveryForm.password" type="password" autocomplete="new-password"></label></div><label>{{ ui("From address") }}<input v-model="reportDeliveryForm.from" required type="email" placeholder="audit@example.com"></label><label>{{ ui("Recipients") }} <small>{{ ui("(comma-separated)") }}</small><input v-model="reportDeliveryForm.recipients" required placeholder="auditor@example.com, it@example.com"></label></template><template v-else><label>{{ ui("Endpoint") }} <small>{{ ui("(blank for AWS S3)") }}</small><input v-model="reportDeliveryForm.endpoint" type="url" placeholder="https://s3.example.com"></label><div class="form-grid"><label>{{ ui("Region") }}<input v-model="reportDeliveryForm.region" required></label><label>{{ ui("Bucket") }}<input v-model="reportDeliveryForm.bucket" required></label></div><label>{{ ui("Object prefix") }}<input v-model="reportDeliveryForm.prefix" placeholder="byakugan-audit"></label><div class="form-grid"><label>{{ ui("Access key ID") }}<input v-model="reportDeliveryForm.accessKeyId" required autocomplete="off"></label><label>{{ ui("Secret access key") }}<input v-model="reportDeliveryForm.secretAccessKey" required type="password" autocomplete="new-password"></label></div><label class="check"><input v-model="reportDeliveryForm.forcePathStyle" type="checkbox"> {{ ui("Force path-style addressing (MinIO and some compatible services)") }}</label><section class="security-note worm-config"><strong>{{ ui("Immutable/WORM protection") }}</strong><div class="form-grid"><label>{{ ui("Object Lock mode") }}<select v-model="reportDeliveryForm.wormMode"><option value="NONE">{{ ui("Disabled") }}</option><option value="GOVERNANCE">{{ ui("Governance") }}</option><option value="COMPLIANCE">{{ ui("Compliance") }}</option></select></label><label>{{ ui("Retention days") }}<input v-model.number="reportDeliveryForm.retentionDays" type="number" min="1" max="3650" :disabled="reportDeliveryForm.wormMode==='NONE'"></label></div><label class="check"><input v-model="reportDeliveryForm.legalHold" type="checkbox"> {{ ui("Apply indefinite Legal Hold to every report") }}</label><p v-if="reportDeliveryForm.wormMode==='COMPLIANCE'">{{ ui("Compliance mode cannot be shortened or bypassed before expiry, including by the root account. Confirm the retention period carefully.") }}</p><p v-else>{{ ui("Bucket versioning and Object Lock must already be enabled. Byakugan verifies this before saving.") }}</p></section></template><p v-if="error" class="error-banner">{{ error }}</p><div class="modal-actions"><button type="button" class="secondary" :disabled="busy" @click="testReportDelivery">{{ ui("Test connection") }}</button><button type="button" class="secondary" @click="showReportDeliveryForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy">{{ ui("Test and save") }}</button></div></form></div>

  <div v-if="showProjectForm" class="modal-backdrop" @click.self="showProjectForm = false">
    <form class="modal" @submit.prevent="saveProject">
      <div class="modal-head"><div><h2>{{ editingId?t('setup.projectEdit'):t('setup.projectAdd') }}</h2><p>{{ t('setup.projectSub') }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showProjectForm = false"><AppIcon name="x" /></button></div>
      <label>{{ t('setup.projectName') }}<input v-model="form.name" required maxlength="100" placeholder="Customer portal"></label>
      <label>{{ t('setup.monitorType') }}<select v-model="form.monitorType"><option value="SUPABASE">{{ ui("Supabase database heartbeat") }}</option><option value="DATABASE">{{ ui("Database health (PostgreSQL / MySQL / SQL Server / MongoDB)") }}</option><option value="HTTP">{{ ui("HTTP / HTTPS") }}</option><option value="TCP">{{ ui("TCP port") }}</option><option value="PING">{{ ui("Ping / ICMP") }}</option><option value="DNS">{{ ui("DNS record") }}</option><option value="SSL">{{ ui("SSL certificate") }}</option><option value="DOCKER">{{ ui("Docker container") }}</option><option value="WEBSOCKET">{{ ui("WebSocket stream (persistent)") }}</option></select></label>
      <template v-if="form.monitorType === 'SUPABASE'">
      <label>Supabase URL<input v-model="form.supabaseUrl" required type="url" placeholder="https://abc.supabase.co"></label>
      <label>Publishable / anon key<input v-model="form.publishableKey" :required="!editingId" type="password" :placeholder="editingId ? 'Leave blank to keep current key' : 'eyJ…'"><small v-if="editingId" class="field-note"><AppIcon name="check" /> {{ ui("A key is stored encrypted. Enter a value only to replace it.") }}</small></label>
      <section class="setup-inline">
        <div><strong>{{ ui("One-time database setup") }}</strong><p>{{ ui("Run the setup SQL once in this Supabase project before saving.") }}</p></div>
        <div class="setup-actions">
          <button type="button" class="secondary" @click="copySetupSql"><AppIcon :name="copiedSetupSql?'check':'copy'" />{{ copiedSetupSql ? "Copied" : "Copy setup SQL" }}</button>
          <a v-if="form.supabaseUrl" class="secondary button-link" :href="sqlEditorUrl(form)" target="_blank" rel="noopener noreferrer">{{ ui("Open SQL Editor") }} <AppIcon name="external" /></a>
        </div>
      </section>
      </template>
      <template v-else-if="form.monitorType === 'DATABASE'"><label>{{ ui("Database engine") }}<select v-model="form.databaseEngine"><option value="POSTGRESQL">PostgreSQL</option><option value="MYSQL">MySQL / MariaDB</option><option value="SQLSERVER">Microsoft SQL Server</option><option value="MONGODB">MongoDB</option></select></label><label>{{ ui("Connection string") }}<input v-model="form.connectionString" :required="!editingId" type="password" autocomplete="new-password" :placeholder="editingId?'Leave blank to keep encrypted credentials':form.databaseEngine==='POSTGRESQL'?'postgresql://monitor:password@db:5432/app?sslmode=require':form.databaseEngine==='MYSQL'?'mysql://monitor:password@db:3306/app':form.databaseEngine==='MONGODB'?'mongodb://monitor:password@db:27017/app':'Server=db,1433;Database=app;User Id=monitor;Password=…;Encrypt=true'"><small class="field-note"><AppIcon name="lock" />{{ editingId?'Credentials are stored encrypted. Enter a value only to replace them.':'Use a dedicated read-only monitoring account. The connection string is encrypted and never returned by the API.' }}</small></label><section class="security-note"><strong>{{ ui("Least-privilege account recommended") }}</strong><p>{{ ui("Grant only connection and monitoring-view permissions. Byakugan does not modify application data or execute user-provided SQL.") }}</p></section></template>
      <template v-else-if="form.monitorType === 'HTTP'">
        <label>{{ t('setup.targetUrl') }}<input v-model="form.target" required type="url" placeholder="https://example.com/health"></label>
        <div class="form-grid"><label>{{ t('setup.method') }}<select v-model="form.httpMethod"><option>GET</option><option>HEAD</option></select></label><label>{{ t('setup.expectedStatus') }}<input v-model.number="form.expectedStatus" type="number" min="100" max="599" :placeholder="ui('Any 2xx')"></label></div>
        <label>{{ t('setup.keyword') }}<input v-model="form.keyword" placeholder="healthy"></label>
        <label class="check"><input v-model="form.ignoreTlsErrors" type="checkbox">{{ t('setup.ignoreTlsErrors') }}</label>
        <small v-if="form.ignoreTlsErrors" class="field-note">{{ t('setup.ignoreTlsWarning') }}</small>
      </template>
      <template v-else-if="form.monitorType === 'TCP'">
        <div class="form-grid"><label>{{ t('setup.host') }}<input v-model="form.tcpHost" required placeholder="db.example.com"></label><label>{{ t('setup.port') }}<input v-model.number="form.tcpPort" required type="number" min="1" max="65535" placeholder="5432"></label></div>
      </template>
      <template v-else-if="form.monitorType === 'PING'">
        <label>{{ t('setup.hostnameIp') }}<input v-model="form.target" required placeholder="server.example.com"></label>
      </template>
      <template v-else-if="form.monitorType === 'WEBSOCKET'">
        <label>WebSocket URL<input v-model="form.target" required placeholder="wss://stream.example.com/vitals"></label><p class="field-note">{{ thai ? 'Byakugan เปิดการเชื่อมต่อค้างไว้และบันทึกทุกครั้งที่หลุด ใช้ตัดสิน Health Check ข้อ 4' : 'Byakugan keeps this connection open and records every drop; it feeds Health Check item 4.' }}</p>
      </template>
      <template v-else-if="form.monitorType === 'DNS'">
        <div class="form-grid"><label>{{ ui("Hostname") }}<input v-model="form.target" required placeholder="example.com"></label><label>{{ ui("Record type") }}<select v-model="form.dnsRecordType"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option><option>SRV</option></select></label></div>
      </template>
      <template v-else-if="form.monitorType === 'SSL'">
        <label>{{ ui("Hostname") }}<input v-model="form.target" required placeholder="example.com"></label><div class="form-grid"><label>{{ ui("Port") }}<input v-model.number="form.sslPort" required type="number" min="1" max="65535"></label><label>{{ ui("Alert before expiry (days)") }}<input v-model.number="form.sslExpiryDays" required type="number" min="1" max="365"></label></div>
      </template>
      <template v-else-if="form.monitorType === 'DOCKER'">
        <label>{{ t('setup.container') }}<input v-model="form.dockerContainer" required placeholder="my-api"></label><p class="field-note">{{ ui("Requires the Docker socket mounted read-only in compose.yaml.") }}</p>
      </template>
      <div class="form-grid">
        <label>{{ ui("Interval") }}<select v-model.number="form.intervalSeconds"><option v-if="form.monitorType !== 'SUPABASE'" :value="30">{{ ui("30 seconds") }}</option><option v-if="form.monitorType !== 'SUPABASE'" :value="60">{{ ui("1 minute") }}</option><option v-if="form.monitorType !== 'SUPABASE'" :value="300">{{ ui("5 minutes") }}</option><option :value="3600">{{ ui("1 hour") }}</option><option :value="10800">{{ ui("3 hours") }}</option><option :value="21600">{{ ui("6 hours") }}</option><option :value="28800">{{ ui("8 hours") }}</option><option :value="43200">{{ ui("12 hours") }}</option><option :value="86400">{{ ui("24 hours") }}</option></select></label>
        <label>{{ ui("Retries") }}<input v-model.number="form.retryCount" type="number" min="0" max="5"></label>
      </div>
      <label class="check"><input v-model="form.enabled" type="checkbox"> {{ t('setup.enabled') }}</label>
      <label class="check"><input v-model="form.maintenance" type="checkbox"> {{ t('setup.maintenance') }}</label>
      <label class="check"><input v-model="form.published" type="checkbox"> {{ t('setup.published') }}</label>
      <fieldset v-if="notifications.length" class="notification-picker"><legend>{{ ui("Alert channels") }}</legend><label v-for="item in notifications" :key="item.id" class="check"><input v-model="form.notificationIds" type="checkbox" :value="item.id"> {{ item.name }} <small>{{ item.type }}</small></label></fieldset>
      <p v-if="error" class="error-banner">{{ error }}</p>
      <div class="modal-actions"><button type="button" class="secondary" @click="showProjectForm = false">{{ t('setup.cancel') }}</button><button class="primary" :disabled="busy">{{ busy ? "…" : t('setup.saveProject') }}</button></div>
    </form>
  </div>

  <div v-if="showNotificationForm" class="modal-backdrop" @click.self="showNotificationForm = false">
    <form class="modal" @submit.prevent="saveNotification">
      <div class="modal-head"><div><h2>{{ ui("Add notification channel") }}</h2><p>{{ ui("Credentials are encrypted before storage.") }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showNotificationForm = false"><AppIcon name="x" /></button></div>
      <label>{{ ui("Name") }}<input v-model="notificationForm.name" required placeholder="Operations alerts"></label>
      <label>{{ ui("Type") }}<select v-model="notificationForm.type"><option value="DISCORD">{{ ui("Discord webhook") }}</option><option value="TELEGRAM">{{ ui("Telegram bot") }}</option><option value="WEBHOOK">{{ ui("Generic webhook") }}</option></select></label>
      <template v-if="notificationForm.type === 'TELEGRAM'"><label>{{ ui("Bot token") }}<input v-model="notificationForm.botToken" required type="password" placeholder="123456:ABC..."></label><label>{{ ui("Chat ID") }}<input v-model="notificationForm.chatId" required placeholder="-100123456789"></label></template>
      <label v-else>{{ ui("Webhook URL") }}<input v-model="notificationForm.url" required type="url" placeholder="https://..."></label>
      <label class="check"><input v-model="notificationForm.enabled" type="checkbox"> {{ ui("Enable this channel") }}</label>
      <p v-if="error" class="error-banner">{{ error }}</p>
      <div class="modal-actions"><button type="button" class="secondary" :disabled="busy" @click="testNotificationChannel">{{ ui("Send test") }}</button><button type="button" class="secondary" @click="showNotificationForm = false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy">{{ ui("Save channel") }}</button></div>
    </form>
  </div>

  <div v-if="showScanProfileForm" class="modal-backdrop" @click.self="showScanProfileForm=false">
    <form class="modal" @submit.prevent="createScanProfile">
      <div class="modal-head"><div><h2>{{ ui("Create scan profile") }}</h2><p>{{ ui("Define a reusable Trivy policy enforced by the Byakugan server.") }}</p></div><button type="button" class="close" :aria-label="ui('Close')" @click="showScanProfileForm=false"><AppIcon name="x" /></button></div>
      <label>{{ ui("Profile name") }}<input v-model="scanProfileForm.name" required maxlength="120" placeholder="Production critical CVEs"></label>
      <label>{{ ui("Description") }}<textarea v-model="scanProfileForm.description" maxlength="500" :placeholder="ui('Purpose and scope of this security scan')"></textarea></label>
      <div class="form-grid"><label>{{ ui("Target type") }}<select v-model="scanProfileForm.targetType"><option value="FILESYSTEM">{{ ui("Filesystem") }}</option><option value="ROOTFS">{{ ui("Root filesystem") }}</option><option value="IMAGE">{{ ui("Container image") }}</option></select></label><label>{{ ui("Timeout (seconds)") }}<input v-model.number="scanProfileForm.timeoutSeconds" required type="number" min="60" max="3600" step="30"></label></div>
      <fieldset class="notification-picker"><legend>{{ ui("Scanners") }}</legend><label class="check"><input v-model="scanProfileForm.scanners" type="checkbox" value="vuln"> {{ ui("Vulnerabilities") }}</label><label class="check"><input v-model="scanProfileForm.scanners" type="checkbox" value="misconfig"> {{ ui("Misconfiguration") }}</label><label class="check"><input v-model="scanProfileForm.scanners" type="checkbox" value="secret"> {{ ui("Exposed secrets") }}</label></fieldset>
      <fieldset class="notification-picker"><legend>{{ ui("Severity included") }}</legend><label v-for="level in ['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL']" :key="level" class="check"><input v-model="scanProfileForm.severity" type="checkbox" :value="level"> {{ level }}</label></fieldset>
      <section class="security-note"><strong>{{ ui("Safe execution") }}</strong><p>{{ ui("Profiles select allowlisted Trivy arguments only. They cannot execute shell commands or upload secret values and file contents.") }}</p></section>
      <p v-if="error" class="error-banner">{{ error }}</p>
      <div class="modal-actions"><button type="button" class="secondary" @click="showScanProfileForm=false">{{ ui("Cancel") }}</button><button class="primary" :disabled="busy||!scanProfileForm.scanners.length||!scanProfileForm.severity.length">{{ busy?'Saving…':'Create profile' }}</button></div>
    </form>
  </div>

</template>
