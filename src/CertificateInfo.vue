<script setup lang="ts">
import { computed } from "vue";
import { locale } from "./i18n";
const props=defineProps<{certificate?:{applicable?:boolean;expiresAt:string|null;checkedAt:string|null;valid:boolean|null;error:string|null}|null}>();
const th=computed(()=>locale.value==='th-TH');
const days=computed(()=>props.certificate?.expiresAt?Math.floor((Date.parse(props.certificate.expiresAt)-Date.now())/86400000):null);
</script>
<template>
  <div class="certificate-info">
    <small>{{ th ? 'วันหมดอายุใบรับรอง' : 'Certificate expiry' }}</small>
    <span class="expiry-date">{{ certificate?.expiresAt ? `(${certificate.expiresAt.slice(0,10)} UTC)` : '—' }}</span>
    <strong :class="{'certificate-danger':certificate?.valid===false || (days!==null&&days<=15),'certificate-warning':days!==null&&days>15&&days<=30}">{{ days===null?'—':days<0?(th?`หมดอายุ ${Math.abs(days)} วัน`:`Expired ${Math.abs(days)} days ago`):(th?`${days} วัน`:`${days} days`) }}</strong>
    <span v-if="certificate?.applicable===false">{{ th ? 'ไม่ใช่ HTTPS/TLS' : 'Not an HTTPS/TLS target' }}</span>
    <span v-else-if="certificate?.valid===false" class="certificate-danger" :title="certificate.error??''">{{ th ? 'ตรวจสอบ TLS ไม่ผ่าน' : 'TLS validation failed' }}</span>
    <span v-else-if="!certificate?.checkedAt">{{ th ? 'ยังไม่ได้ตรวจ — กดตรวจตอนนี้' : 'Not checked — run now' }}</span>
    <span v-else-if="days===null">{{ th ? 'อ่านวันหมดอายุไม่ได้' : 'Expiry unavailable' }}</span>
    <span v-else :title="certificate?.checkedAt??''">{{ th ? 'ตามผลตรวจใบรับรองล่าสุด' : 'From last certificate inspection' }}</span>
  </div>
</template>
<style scoped>
.certificate-info{display:flex;align-items:center;flex-direction:column;gap:5px;min-width:0}.certificate-info small,.certificate-info span{color:#8ba0bc;font-size:11px}.certificate-info strong{font-size:22px;color:#dbe9fa;margin:8px 0}.certificate-info .certificate-danger{color:#ff7b85}.certificate-info .certificate-warning{color:#ffce71}
</style>
