<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { api } from "./api";
import ThreatMap from "./ThreatMap.vue";
import ThreatCases from "./ThreatCases.vue";
import ThreatOverview, { type ThreatOverviewData } from "./ThreatOverview.vue";
import AppIcon from "./AppIcon.vue";
import { threatGuidance } from "./threat-guidance";
import { locale } from "./i18n";

type LogEvent = { id:number; agentId:number; agent:string; source:string; event:string; host:string|null; actor:string|null; srcIp:string|null; result:string|null; severity:string; detailsJson:string; occurredAt:string; receivedAt:string };
const props = defineProps<{ initialAgentId?:number; timezone:string; threats?:boolean; canManage?:boolean; isAdmin?:boolean }>();
const agents = ref<Array<{id:number;name:string;hostname:string|null;osName:string|null}>>([]);
const rows = ref<LogEvent[]>([]);
const loading = ref(false), error = ref(""), searched = ref(false), more = ref(false);
const lastUpdated = ref<string|null>(null);
const expanded = ref<number|null>(null);
const filters = reactive({ agentId:props.initialAgentId??0, source:"", severity:"", event:"", search:"", actor:"", srcIp:"", result:"", period:"24", from:"", to:"" });
const overview = ref<ThreatOverviewData|null>(null);
const appliedQuery = ref("");
let applied = new URLSearchParams();
const text = computed(() => locale.value === "th-TH" ? {
  title:"บันทึกเหตุการณ์", subtitle:"ค้นหา Windows, Linux และ log ที่ส่งเข้ามาจากระบบต่าง ๆ", refresh:"รีเฟรช", search:"ค้นหา", searchHint:"เหตุการณ์, เครื่อง, ผู้ใช้, IP หรือรายละเอียด", machine:"เครื่อง / Agent", all:"ทั้งหมด", source:"แหล่งข้อมูล", severity:"ความรุนแรง", event:"เหตุการณ์", period:"ช่วงเวลา", day:"24 ชั่วโมงล่าสุด", week:"7 วันล่าสุด", custom:"กำหนดเอง", from:"ตั้งแต่", to:"ถึง", advanced:"ตัวกรองเพิ่มเติม", actor:"ผู้ใช้", ip:"IP ต้นทาง", result:"ผลลัพธ์", reset:"ล้างตัวกรอง", loading:"กำลังโหลด…", shown:"รายการที่โหลดแล้ว", latest:"อัปเดตล่าสุด", time:"เวลาเกิดเหตุ", detail:"รายละเอียด", received:"เวลารับข้อมูล", more:"โหลดรายการเก่ากว่า", end:"โหลดครบตามเงื่อนไขแล้ว", empty:"ไม่พบเหตุการณ์ตามเงื่อนไข", emptyHint:"ลองขยายช่วงเวลา หรือล้างตัวกรอง หากเพิ่งติดตั้ง Agent ให้รอประมาณ 60 วินาทีแล้วรีเฟรช", help:"ยังไม่มี log จาก Windows?", helpBody:"Agent ต้องทำงานและเปิดส่ง logs โดยมีเหตุการณ์ที่รองรับ เช่น login หรือ service เปลี่ยนสถานะ คำสั่งด้านล่างใช้ดูเหตุการณ์บนเครื่อง Windows โดยไม่ส่งข้อมูล", validation:"กรุณาระบุช่วงเวลาให้ครบและให้เวลาเริ่มก่อนเวลาสิ้นสุด", hostHint:"host รวม Windows/Linux; เลือกเครื่องเพื่อดูเฉพาะเครื่องนั้น", exact:"ตัวกรองเหตุการณ์ ผู้ใช้ และ IP ต้องตรงกับค่าที่บันทึก", failure:"โหลด log ไม่สำเร็จ", retry:"ลองใหม่", detailsEmpty:"ไม่มีรายละเอียดเพิ่มเติม", moreHint:"เรียงตามเวลาเกิดเหตุล่าสุด ครั้งละ 100 รายการ", noResults:"ค้นหาแล้วไม่พบข้อมูล", noAgents:"โหลดรายชื่อเครื่องไม่สำเร็จ ยังค้นหา log ด้วยตัวกรองอื่นได้", filtered:"แก้ตัวกรองแล้วกดค้นหาเพื่อแสดงผลใหม่", timezone:"เขตเวลา"
} : {
  title:"Event logs", subtitle:"Search Windows, Linux and logs shipped by connected systems", refresh:"Refresh", search:"Search", searchHint:"Event, host, user, IP or details", machine:"Machine / Agent", all:"All", source:"Source", severity:"Severity", event:"Event", period:"Time range", day:"Last 24 hours", week:"Last 7 days", custom:"Custom", from:"From", to:"To", advanced:"More filters", actor:"User", ip:"Source IP", result:"Result", reset:"Reset filters", loading:"Loading…", shown:"Loaded events", latest:"Last refreshed", time:"Occurred at", detail:"Details", received:"Received at", more:"Load older events", end:"All matching events loaded", empty:"No matching events", emptyHint:"Try a wider time range or reset filters. For a new agent, wait about 60 seconds and refresh.", help:"No Windows logs yet?", helpBody:"The agent must be running with logs enabled and supported events available, such as logins or service state changes. Run this on Windows to inspect local events without uploading them.", validation:"Enter a valid start and end time, with the start before the end", hostHint:"host includes Windows/Linux; choose a machine to narrow the results", exact:"Event, user and IP filters match exact recorded values", failure:"Unable to load logs", retry:"Try again", detailsEmpty:"No additional details", moreHint:"Newest event time first, 100 events per request", noResults:"No search results", noAgents:"Unable to load machine names. Other log filters are still available.", filtered:"After changing filters, select Search to apply them", timezone:"Timezone"
});
const thai = computed(() => locale.value === "th-TH");
const title = computed(() => props.threats ? (thai.value ? "ภัยคุกคาม" : "Threats") : text.value.title);
const subtitle = computed(() => props.threats ? (thai.value ? "ตรวจสอบความล้มเหลวในการยืนยันตัวตนและการเชื่อมต่อที่ Firewall ปฏิเสธจาก Log จริง" : "Investigate authentication failures and firewall denials from collected logs") : text.value.subtitle);
const guidance = (event:string) => threatGuidance(event, thai.value);
const candidateEvents = ["LOGIN_FAILED","SSH_LOGIN_FAILED","SUDO_AUTH_FAILED","ROOT_LOGIN_DENIED","VPN_AUTH_FAILED","DB_AUTH_FAILED","FIREWALL_DENY","IP_BANNED","HTTP_PROBE"];
const agentError = ref(false);
const events = ["LOGIN_SUCCESS","LOGIN_FAILED","SSH_LOGIN_SUCCESS","SSH_LOGIN_FAILED","ROOT_LOGIN_DENIED","SUDO_COMMAND","SUDO_AUTH_FAILED","PRIVILEGE_ASSIGNED","USER_CREATED","GROUP_MEMBER_ADDED","SERVICE_START","SERVICE_STOP","SERVICE_RESTART","SERVICE_INSTALLED","BACKUP_COMPLETE","BACKUP_FAILED","DB_BACKUP_COMPLETE","DB_BACKUP_FAILED","HTTP_REQUEST","FIREWALL_DENY","VPN_AUTH_FAILED"];
const sources = ["host","nginx","app-audit","db","firewall","vpn","fail2ban"];
function date(value:string|null) {
  return value ? new Intl.DateTimeFormat(locale.value,{dateStyle:"medium",timeStyle:"medium",timeZone:props.timezone,calendar:"gregory"}).format(new Date(value)) : "—";
}
function details(row:LogEvent) { try { return JSON.stringify(JSON.parse(row.detailsJson),null,2); } catch { return row.detailsJson; } }
function query() {
  const q = new URLSearchParams({limit:"100"});
  if (props.threats) q.set("threatOnly","true");
  for (const key of ["source","severity","event","search","actor","srcIp","result"] as const) {
    if (filters[key].trim()) q.set(key,filters[key].trim());
  }
  if (filters.agentId) q.set("agentId",String(filters.agentId));
  if (filters.period === "custom") {
    const from = new Date(filters.from), to = new Date(filters.to);
    if (!filters.from || !filters.to || !Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from > to) throw new Error(text.value.validation);
    q.set("from",from.toISOString()); q.set("to",to.toISOString());
  } else if (filters.period !== "all") {
    const now = Date.now();
    q.set("from",new Date(now-Number(filters.period)*3600000).toISOString()); q.set("to",new Date(now).toISOString());
  }
  return q;
}
async function load(older = false) {
  if (loading.value) return;
  loading.value = true; error.value = "";
  try {
    const q = older ? new URLSearchParams(applied) : query();
    const last = rows.value.at(-1);
    if (older && last) { q.set("beforeTime",last.occurredAt); q.set("beforeId",String(last.id)); }
    const [result, summary] = await Promise.all([api<{events:LogEvent[]}>(`/api/logs?${q}`),props.threats && !older ? api<ThreatOverviewData>(`/api/threats/overview?${q}`) : Promise.resolve(null)]);
    if (summary) overview.value = summary;
    if (!older) { applied = q; appliedQuery.value = q.toString(); expanded.value = null; }
    rows.value = older ? [...rows.value,...result.events] : result.events;
    more.value = result.events.length === 100;
    searched.value = true; lastUpdated.value = new Date().toISOString();
  } catch (value) { if (!older) overview.value = null; error.value = value instanceof Error ? value.message : text.value.failure; }
  finally { loading.value = false; }
}
function reset() { Object.assign(filters,{agentId:0,source:"",severity:"",event:"",search:"",actor:"",srcIp:"",result:"",period:"24",from:"",to:""}); void load(); }
onMounted(() => {
  void api<typeof agents.value>("/api/agents").then(value=>{agents.value=value}).catch(()=>{agentError.value=true});
  void load();
});
</script>

<template>
  <section class="logs-view">
    <header><div><h1>{{ title }}</h1><p>{{ subtitle }}</p></div><button class="secondary" :disabled="loading" @click="load()"><AppIcon name="refresh" /> {{ text.refresh }}</button></header>
    <aside v-if="threats" class="panel threat-notice">
      <strong>{{ thai ? 'เหตุการณ์ที่ควรตรวจสอบ ไม่ใช่จำนวนการเจาะระบบสำเร็จ' : 'Investigation candidates, not confirmed compromises' }}</strong>
      <p>{{ thai ? 'แสดงเฉพาะ Log ที่ระบบรับแล้ว การไม่พบรายการไม่ได้ยืนยันว่าปลอดภัยหรือเก็บข้อมูลครบ แหล่งข้อมูลที่ยังไม่เชื่อมต่อจะไม่ปรากฏในหน้านี้' : 'Only received logs are shown. No matching events does not establish safety or complete coverage. Disconnected log sources are not represented here.' }}</p>
      <small>{{ thai ? 'จำนวนด้านล่างนับเฉพาะรายการที่โหลดแล้ว · กดรีเฟรชเพื่อรับข้อมูลใหม่ · รายละเอียดแสดงความเสี่ยงและสิ่งที่ควรตรวจสอบ' : 'The count below covers loaded rows only · Refresh to fetch new data · Expand an event for risk context and investigation steps' }}</small>
    </aside>
    <form class="panel log-filters" @submit.prevent="load()">
      <div class="log-search"><label>{{ text.search }}<input v-model="filters.search" maxlength="200" :placeholder="text.searchHint"></label><button class="primary" :disabled="loading">{{ loading ? text.loading : text.search }}</button></div>
      <div class="log-filter-grid">
        <label>{{ text.machine }}<select v-model.number="filters.agentId"><option :value="0">{{ text.all }}</option><option v-for="agent in agents" :key="agent.id" :value="agent.id">{{ agent.hostname||agent.name }} · {{ agent.osName||agent.name }}</option></select></label>
        <label>{{ text.source }}<input v-model="filters.source" list="log-sources-list" maxlength="40" :placeholder="text.all"><datalist id="log-sources-list"><option v-for="source in sources" :key="source" :value="source" /></datalist></label>
        <label>{{ text.severity }}<select v-model="filters.severity"><option value="">{{ text.all }}</option><option v-for="level in ['critical','error','warning','notice','info','debug']" :key="level">{{ level }}</option></select></label>
        <label>{{ text.period }}<select v-model="filters.period"><option value="24">{{ text.day }}</option><option value="168">{{ text.week }}</option><option value="all">{{ text.all }}</option><option value="custom">{{ text.custom }}</option></select></label>
      </div>
      <div v-if="filters.period==='custom'" class="log-filter-grid custom-period"><label>{{ text.from }}<input v-model="filters.from" type="datetime-local" required></label><label>{{ text.to }}<input v-model="filters.to" type="datetime-local" required></label><small>{{ locale==='th-TH'?'ช่วงเวลาที่กรอกใช้เขตเวลาของเบราว์เซอร์':'Date inputs use your browser timezone' }}: {{ Intl.DateTimeFormat().resolvedOptions().timeZone }}</small></div>
      <details class="log-advanced"><summary>{{ text.advanced }}</summary><div class="log-filter-grid">
        <label>{{ text.event }}<input v-model="filters.event" list="log-event-list" maxlength="80" :placeholder="text.all"><datalist id="log-event-list"><option v-for="event in (threats ? candidateEvents : events)" :key="event" :value="event" /></datalist></label>
        <label>{{ text.actor }}<input v-model="filters.actor" maxlength="150" :placeholder="text.all"></label>
        <label>{{ text.ip }}<input v-model="filters.srcIp" maxlength="64" placeholder="192.0.2.10"></label>
        <label>{{ text.result }}<input v-model="filters.result" maxlength="40" placeholder="success / failed"></label>
      </div><p class="log-note">{{ text.exact }}</p></details>
      <div class="log-filter-footer"><small>{{ text.hostHint }} · {{ text.filtered }}</small><button class="link" type="button" :disabled="loading" @click="reset">{{ text.reset }}</button></div>
    </form>
    <p v-if="agentError" class="log-note" role="status">{{ text.noAgents }}</p>
    <p v-if="error" class="error-banner" role="alert">{{ error }} <button class="secondary" :disabled="loading" @click="load()">{{ text.retry }}</button></p>
    <ThreatOverview v-if="threats && overview" :data="overview" :timezone="timezone" @source="ip=>{filters.srcIp=ip;load()}" />
    <ThreatMap v-if="threats && overview" :query="appliedQuery" :is-admin="!!isAdmin" :agents="agents" :timeline="overview.timeline" />
    <ThreatCases v-if="threats && overview" :query="appliedQuery" :can-manage="!!canManage" />
    <section class="panel log-results" :aria-busy="loading">
      <div class="log-results-head" aria-live="polite"><div><strong>{{ text.shown }}: {{ rows.length.toLocaleString(locale) }}</strong><small>{{ text.moreHint }} · {{ text.timezone }}: {{ timezone }}</small></div><small v-if="lastUpdated">{{ text.latest }}: {{ date(lastUpdated) }}</small></div>
      <div v-if="loading && !rows.length" class="empty" role="status">{{ text.loading }}</div>
      <div v-else-if="searched && !rows.length && !error" class="empty"><h2>{{ text.empty }}</h2><p>{{ text.emptyHint }}</p></div>
      <div v-if="rows.length" class="log-table-scroll"><table class="log-table"><caption class="log-sr-only">{{ title }} — {{ text.moreHint }}</caption><thead><tr><th>{{ text.time }}</th><th>{{ text.severity }}</th><th>{{ text.event }}</th><th>{{ text.machine }}</th><th>{{ text.actor }} / {{ text.ip }}</th><th>{{ text.result }}</th><th>{{ text.detail }}</th></tr></thead><tbody>
        <template v-for="row in rows" :key="row.id"><tr><td><time :datetime="row.occurredAt">{{ date(row.occurredAt) }}</time></td><td><span :class="['log-severity',row.severity]">{{ row.severity }}</span></td><td><strong>{{ row.event }}</strong><small>{{ row.source }}</small><small v-if="threats">{{ guidance(row.event)?.title }}</small></td><td>{{ row.host||row.agent }}<small>{{ row.agent }}</small></td><td>{{ row.actor||'—' }}<small>{{ row.srcIp||'—' }}</small></td><td>{{ row.result||'—' }}</td><td><button class="secondary log-detail-button" :aria-expanded="expanded===row.id" :aria-controls="`log-detail-${row.id}`" @click="expanded=expanded===row.id?null:row.id"><AppIcon :name="expanded===row.id?'x':'plus'" /><span class="log-sr-only"> {{ text.detail }} #{{ row.id }}</span></button></td></tr>
        <tr v-if="expanded===row.id" :id="`log-detail-${row.id}`" class="log-detail-row"><td colspan="7"><div class="log-event-details"><dl><div><dt>ID</dt><dd>#{{ row.id }}</dd></div><div><dt>{{ text.received }}</dt><dd>{{ date(row.receivedAt.endsWith('Z')||row.receivedAt.includes('T')?row.receivedAt:row.receivedAt.replace(' ','T')+'Z') }}</dd></div><div><dt>{{ text.machine }}</dt><dd>{{ row.agent }} (#{{ row.agentId }})</dd></div></dl><section v-if="threats && guidance(row.event)" class="threat-explanation">
          <h3>{{ guidance(row.event)?.title }}</h3><p>{{ guidance(row.event)?.meaning }}</p>
          <strong>{{ thai ? 'ผลที่หลักฐานระบุ' : 'Recorded outcome' }}</strong><p>{{ guidance(row.event)?.outcome }}</p>
          <strong>{{ thai ? 'ควรตรวจสอบอะไร' : 'What to investigate' }}</strong><p>{{ guidance(row.event)?.action }}</p>
          <strong>{{ thai ? 'หลักฐานต้นฉบับจากแหล่งข้อมูล' : 'Original source evidence' }}</strong>
        </section><pre>{{ row.detailsJson==='{}'?text.detailsEmpty:details(row) }}</pre></div></td></tr></template>
      </tbody></table></div>
      <div v-if="rows.length" class="log-pagination"><button v-if="more" class="secondary" :disabled="loading" @click="load(true)">{{ loading?text.loading:text.more }}</button><small v-else>{{ text.end }}</small></div>
    </section>
    <details class="panel log-help"><summary>{{ text.help }}</summary><p>{{ text.helpBody }}</p><pre>&amp; "$env:ProgramData\Byakugan\byakugan-agent.ps1" -LogDryRun</pre></details>
  </section>
</template>

<style scoped>
.threat-notice{padding:20px;margin-bottom:20px;border-left:3px solid #e5b85c}.threat-notice p,.threat-explanation p{line-height:1.7;color:#b8cbe3}.threat-notice small{color:#91a3bc}.threat-explanation{margin-bottom:16px}.threat-explanation h3{margin-top:0}.threat-explanation strong{color:#d7e5f5}
.logs-view{min-width:0}.logs-view header{gap:16px}.log-filters{padding:22px;margin-bottom:20px}.log-search{display:flex;align-items:flex-end;gap:12px;margin-bottom:18px}.log-search label{flex:1}.log-search .primary{min-height:42px}.log-filter-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.log-filter-grid label{min-width:0}.log-filter-grid input,.log-filter-grid select{width:100%}.log-advanced{margin-top:16px;border-top:1px solid #26344a;padding-top:14px}.log-advanced summary,.log-help summary{cursor:pointer;color:#b8cbe3;font-weight:600}.log-advanced .log-filter-grid{margin-top:14px}.log-note,.log-filter-footer small{color:#91a3bc;font-size:12px;line-height:1.6}.log-filter-footer{display:flex;gap:16px;justify-content:space-between;align-items:center;margin-top:14px}.log-filter-footer .link{white-space:nowrap}.log-results{overflow:hidden}.log-results-head{padding:20px;display:flex;justify-content:space-between;gap:14px;align-items:center}.log-results-head small{display:block;color:#91a3bc;font-size:12px;margin-top:5px}.log-table-scroll{position:relative;overflow-x:auto}.log-table{min-width:760px;width:100%;border-collapse:collapse;text-align:left;font-size:13px}.log-table th{background:#101d2d;color:#a8bad1;font-size:12px;font-weight:600}.log-table th,.log-table td{padding:14px 10px;border-bottom:1px solid #213047;vertical-align:top}.log-table td:nth-child(6){white-space:nowrap}.log-table td:first-child{min-width:130px}.log-table td strong{font-size:12px;overflow-wrap:anywhere}.log-table small{display:block;margin-top:5px;color:#8a9db6;overflow-wrap:anywhere}.log-table td{max-width:270px;overflow-wrap:anywhere}.log-severity{display:inline-block;border:1px solid #34465e;background:#172438;color:#b9cce3;padding:4px 8px;border-radius:6px;font-size:11px}.log-severity.warning{background:#3a2c11;border-color:#70531b;color:#ffd484}.log-severity.error,.log-severity.critical{background:#3b1924;border-color:#753044;color:#ffa7b7}.log-severity.notice{color:#86dcc2}.log-detail-button{position:relative;padding:5px 10px;min-width:34px}.log-detail-row td{background:#0b1421;max-width:none}.log-event-details{position:sticky;left:16px;width:min(680px,calc(100vw - 90px))}.log-detail-row dl{display:flex;flex-wrap:wrap;gap:18px;margin:0 0 14px}.log-detail-row dt{color:#8a9db6;font-size:11px}.log-detail-row dd{margin:5px 0 0}.log-detail-row pre,.log-help pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;color:#b5d9ce;max-height:320px;overflow:auto;font-size:12px}.log-pagination{text-align:center;padding:18px;color:#91a3bc;font-size:12px}.log-help{min-height:0;margin-top:20px;padding:18px 22px}.log-help p{color:#91a3bc;line-height:1.7;font-size:13px}.custom-period{margin-top:14px;grid-template-columns:1fr 1fr;align-items:end}.custom-period small{grid-column:1/-1;color:#91a3bc}.log-sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}@media(max-width:1100px){.log-filter-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.log-results-head{align-items:flex-start;flex-direction:column}}@media(max-width:600px){.log-filters{padding:16px}.log-search{align-items:stretch;flex-direction:column}.log-filter-grid{grid-template-columns:1fr}.log-filter-footer{align-items:flex-start;flex-direction:column}.logs-view header{align-items:flex-start}.log-table th,.log-table td{padding:12px}.custom-period small{grid-column:auto}}
</style>
