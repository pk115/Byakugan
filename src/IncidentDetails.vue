<script setup lang="ts">
import { computed } from "vue";
import { locale } from "./i18n";
import { incidentGuidance, type IncidentContext } from "./incident-guidance";
const props=defineProps<{ incident: IncidentContext & { id:number; message:string|null; projectName:string; resolvedAt:string|null; closedAt:string|null }; started:string; recovered:string; reviewed:string }>();
const th=computed(()=>locale.value==='th-TH');
const guide=computed(()=>incidentGuidance(props.incident,th.value));
</script>
<template>
  <section class="incident-details">
    <h3>{{ th ? 'หลักฐานของเหตุการณ์' : 'Incident evidence' }} #{{ incident.id }}</h3>
    <p><strong>{{ incident.projectName }}</strong> · {{ incident.healthMetricKey || incident.monitorType || (th ? 'ไม่ทราบประเภท' : 'Unknown type') }}</p>
    <p class="incident-message">{{ incident.message || (th ? 'ไม่มีข้อความหลักฐานเพิ่มเติมที่บันทึกไว้' : 'No additional evidence message was recorded.') }}</p>
    <dl><div><dt>{{ th ? 'เริ่มเหตุการณ์' : 'Started' }}</dt><dd>{{ started }}</dd></div><div><dt>{{ th ? 'ผลตรวจพบการฟื้นตัว' : 'Recorded recovery' }}</dt><dd>{{ incident.resolvedAt ? recovered : (th ? 'ยังไม่มีบันทึกการฟื้นตัว — ไม่ใช่ผลตรวจสด' : 'No recovery recorded — not a live probe') }}</dd></div><div><dt>{{ th ? 'อนุมัติทบทวนล่าสุด' : 'Last approved review' }}</dt><dd>{{ reviewed }}</dd></div></dl>
    <h3>{{ th ? 'เหตุการณ์นี้คืออะไร' : 'What this incident means' }}</h3><p>{{ guide.meaning }}</p>
    <h3>{{ th ? 'ความเสี่ยงและผลกระทบที่ควรตรวจ' : 'Risks and potential impact' }}</h3><p>{{ guide.risk }}</p>
    <h3>{{ th ? 'ควรตรวจสอบและดำเนินการอะไร' : 'Investigation and next actions' }}</h3><ol><li v-for="step in guide.steps" :key="step">{{ step }}</li></ol>
    <h3>{{ th ? 'ยืนยันผลหลังแก้อย่างไร' : 'How to verify recovery' }}</h3><p>{{ guide.verify }}</p>
    <p class="workflow-note">{{ th ? 'ข้อความหลักฐานและเวลาเป็นข้อมูลที่บันทึกไว้ คำแนะนำอิงประเภท Monitor/นโยบายปัจจุบัน ไม่ใช่ผลวิเคราะห์สาเหตุอัตโนมัติ การอนุมัติหรือปิดเคสไม่ได้ยืนยันว่าบริการฟื้นตัว ให้กรอกสาเหตุจากสิ่งที่ตรวจยืนยันจริง พร้อมวิธีแก้และผลทดสอบ' : 'Evidence and timestamps are recorded data. Guidance uses the current monitor/policy type and is not an automatic root-cause diagnosis. Approval or case closure does not establish service recovery. Record the verified cause, remediation and test results.' }}</p>
  </section>
</template>
<style scoped>
.incident-details{padding:18px;margin:16px 0 22px;border:1px solid #29384d;border-radius:12px;background:#0c1422}.incident-details h3{font-size:14px;margin:18px 0 8px}.incident-details h3:first-child{margin-top:0}.incident-details p,.incident-details li{line-height:1.7;overflow-wrap:anywhere}.incident-details li+li{margin-top:8px}.incident-message{white-space:pre-wrap}.incident-details ol{padding-left:24px}.incident-details dl{font-size:12px;color:#9bb0c8}.incident-details dl>div{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}.incident-details dd{margin:0}.incident-details dt{font-weight:600}
</style>
