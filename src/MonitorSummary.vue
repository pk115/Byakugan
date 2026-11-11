<script setup lang="ts">
import { computed } from "vue";
import { locale } from "./i18n";
import CertificateInfo from "./CertificateInfo.vue";
defineProps<{stats:{currentResponseMs:number|null;averageResponse24hMs:number|null;uptime24h:number|null;uptime30d:number|null;checks24h:number;checks30d:number;certificate?:{applicable?:boolean;expiresAt:string|null;checkedAt:string|null;valid:boolean|null;error:string|null}}|null}>();
const th=computed(()=>locale.value==='th-TH');
function number(value:number|null|undefined,suffix:string,digits=0){return value==null?'—':`${new Intl.NumberFormat(locale.value,{maximumFractionDigits:digits,minimumFractionDigits:digits}).format(value)}${suffix}`}
</script>
<template>
  <section class="detail-metrics monitor-summary">
    <article><small>{{ th?'การตอบสนอง':'Response time' }}</small><span>{{ th?'(ปัจจุบัน)':'(current)' }}</span><strong>{{ number(stats?.currentResponseMs,' ms') }}</strong></article>
    <article><small>{{ th?'ค่าตอบสนองเฉลี่ย':'Average response' }}</small><span>{{ th?'(24 ชั่วโมง)':'(24 hours)' }}</span><strong>{{ number(stats?.averageResponse24hMs,' ms',2) }}</strong></article>
    <article><small>{{ th?'เวลาที่ใช้งานได้':'Uptime' }}</small><span>{{ th?'(24 ชั่วโมง)':'(24 hours)' }}</span><strong>{{ number(stats?.uptime24h,'%',2) }}</strong><span>{{ stats?.checks24h??0 }} {{ th?'ผลตรวจ':'checks' }}</span></article>
    <article><small>{{ th?'เวลาที่ใช้งานได้':'Uptime' }}</small><span>{{ th?'(30 วัน)':'(30 days)' }}</span><strong>{{ number(stats?.uptime30d,'%',2) }}</strong><span>{{ stats?.checks30d??0 }} {{ th?'ผลตรวจ':'checks' }}</span></article>
    <article><CertificateInfo :certificate="stats?.certificate" /></article>
  </section>
</template>
<style scoped>
.monitor-summary article>small,.monitor-summary article>span{display:block}.monitor-summary{width:100%;margin:14px 0}.monitor-summary article{padding:22px 12px}
</style>
