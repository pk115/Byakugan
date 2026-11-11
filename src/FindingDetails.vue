<script setup lang="ts">
import { computed } from "vue";
import { locale } from "./i18n";
import { findingGuidance, type FindingContext } from "./finding-guidance";
const props = defineProps<{ finding: FindingContext & { explanation: string; firstDetectedAt: string; lastDetectedAt?: string }; firstDetected: string; lastDetected: string }>();
const th = computed(() => locale.value === "th-TH");
const guide = computed(() => findingGuidance(props.finding, th.value));
</script>
<template>
  <section class="finding-details">
    <h3>{{ th ? 'หลักฐานที่ระบบตรวจพบ' : 'Detection evidence' }}</h3>
    <p class="finding-evidence">{{ finding.explanation }}</p>
    <small>{{ th ? 'ตรวจพบครั้งแรก' : 'First detected' }}: {{ firstDetected }} · {{ th ? 'พบล่าสุด' : 'Last detected' }}: {{ lastDetected }}</small>
    <h3>{{ th ? 'ผลกระทบที่ควรตรวจสอบ' : 'Potential impact to investigate' }}</h3>
    <p>{{ guide.impact }}</p>
    <h3>{{ th ? 'ต้องดำเนินการอะไร' : 'Recommended actions' }}</h3>
    <ol><li v-for="step in guide.steps" :key="step">{{ step }}</li></ol>
    <h3>{{ th ? 'ยืนยันว่าแก้แล้วอย่างไร' : 'How to verify recovery' }}</h3>
    <p>{{ guide.verify }}</p>
    <p class="workflow-note">{{ th ? 'คำแนะนำเป็นจุดเริ่มต้นในการตรวจสอบ ไม่ใช่การยืนยันสาเหตุ รับทราบ = รับผิดชอบติดตาม; แก้ไขแล้ว = มีผลตรวจยืนยัน พร้อมบันทึกวิธีแก้และผลทดสอบ หากต้นเหตุยังอยู่ระบบอาจเปิดรายการอีกครั้ง' : 'These steps guide investigation, not a confirmed diagnosis. Acknowledge to take ownership; resolve after verifying recovery and recording remediation evidence. Unfixed conditions may reopen.' }}</p>
  </section>
</template>
<style scoped>
.finding-details { margin:16px 0 22px; padding:18px; border:1px solid #29384d; border-radius:12px; background:#0c1422; }
.finding-details h3 { font-size:14px; margin:16px 0 8px; }
.finding-details h3:first-child { margin-top:0; }
.finding-details p,.finding-details li { line-height:1.7; overflow-wrap:anywhere; }
.finding-details ol { padding-left:24px; }
.finding-details li + li { margin-top:8px; }
.finding-details small { color:#91a2ba; }
.finding-evidence { white-space:pre-wrap; }
</style>
