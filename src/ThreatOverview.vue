<script setup lang="ts">
import { computed } from "vue";
import { locale } from "./i18n";
export type ThreatOverviewData = {
  summary:{events:number;ips:number;agents:number;blocked:number};
  sources:Array<{ip:string|null;events:number;agents:number;lastSeen:string}>;
  types:Array<{event:string;events:number}>;timeline:Array<{time:string;events:number}>;
  coverage:Array<{agentId:number;name:string;hostname:string|null;enabled:number;lastSeen:string|null;lastLog:string|null;sources:string|null}>;
  coverageTruncated:boolean;generatedAt:string;
};
const props=defineProps<{data:ThreatOverviewData;timezone:string}>();
const emit=defineEmits<{source:[ip:string]}>();
const th=computed(()=>locale.value==='th-TH');
function date(s:string|null){if(!s)return '—';return new Intl.DateTimeFormat(locale.value,{dateStyle:'short',timeStyle:'short',calendar:'gregory',timeZone:props.timezone}).format(new Date(s.includes('T')?s:s.replace(' ','T')+'Z'));}
function receipt(s:string|null){if(!s)return th.value?'ยังไม่เคยรับ Log':'No logs received';const age=Date.now()-new Date(s.includes('T')?s:s.replace(' ','T')+'Z').getTime();return age>900000?(th.value?'ไม่มี Log ใหม่เกิน 15 นาที — ตรวจแหล่งข้อมูล':'No new logs for over 15 min — check source'):(th.value?'มี Log ล่าสุด — ยังไม่ยืนยันความครบ':'Recent logs — completeness unverified');}
</script>
<template>
  <section class="threat-overview">
    <div class="threat-cards"><div class="panel" v-for="card in [[th?'เหตุการณ์ตามตัวกรอง':'Matching events',data.summary.events],[th?'IP ไม่ซ้ำ':'Distinct IPs',data.summary.ips],[th?'เครื่องที่พบเหตุการณ์':'Machines with events',data.summary.agents],[th?'การเชื่อมต่อถูกปฏิเสธ':'Denied connections',data.summary.blocked]]" :key="String(card[0])"><small>{{card[0]}}</small><strong>{{Number(card[1]).toLocaleString(locale)}}</strong></div></div>
    <details class="panel"><summary>{{th?'IP ต้นทาง 50 อันดับแรก':'Top 50 source IPs'}}</summary><div class="scroll"><table><thead><tr><th>IP</th><th>{{th?'เหตุการณ์':'Events'}}</th><th>{{th?'เครื่อง':'Machines'}}</th><th>{{th?'ล่าสุด':'Last seen'}}</th></tr></thead><tbody><tr v-for="row in data.sources" :key="row.ip??'unknown'"><td><button v-if="row.ip" class="link" @click="emit('source',row.ip)">{{row.ip}}</button><span v-else>{{th?'ไม่ทราบ':'Unknown'}}</span></td><td>{{row.events}}</td><td>{{row.agents}}</td><td>{{date(row.lastSeen)}}</td></tr></tbody></table></div></details>
    <details class="panel"><summary>{{th?'สถานะการรับ Log รายเครื่อง (ปัจจุบัน)':'Log receipt by machine (current)'}}</summary><p>{{th?'แสดงแหล่งที่เคยรับ ไม่ได้ยืนยันว่าครบทุกแหล่ง การไม่มี Log ใหม่อาจเกิดจากไม่มีเหตุการณ์หรือการส่งขัดข้อง':'Observed sources do not prove full coverage. A quiet source may have no events or a delivery problem.'}}</p><div class="scroll"><table><thead><tr><th>{{th?'เครื่อง':'Machine'}}</th><th>{{th?'แหล่งที่เคยรับ':'Observed sources'}}</th><th>{{th?'รับ Log ล่าสุด':'Last received'}}</th><th>{{th?'สถานะ':'Status'}}</th></tr></thead><tbody><tr v-for="row in data.coverage" :key="row.agentId"><td>{{row.hostname||row.name}} #{{row.agentId}}</td><td>{{row.sources||'—'}}</td><td>{{date(row.lastLog)}}</td><td>{{row.enabled?receipt(row.lastLog):(th?'Agent ถูกปิด':'Agent disabled')}}</td></tr></tbody></table></div><p v-if="data.coverageTruncated">{{th?'แสดง 500 เครื่องแรก กรุณาเลือกเครื่อง':'First 500 machines shown; select a machine to narrow results'}}</p></details>
  </section>
</template>
<style scoped>
.threat-overview{margin-bottom:20px}.threat-cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.threat-cards .panel{padding:18px}.threat-cards strong{display:block;font-size:28px;margin-top:10px}.threat-overview details{padding:18px;margin-top:12px}.threat-overview summary{cursor:pointer;font-weight:600}.threat-overview p{color:#a9bcd2;font-size:13px;line-height:1.7}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}td,th{padding:12px;border-bottom:1px solid #29364a}td{overflow-wrap:anywhere}@media(max-width:700px){.threat-cards{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
