<script setup lang="ts">
import { computed, ref } from "vue";
import { api } from "./api";
import { locale } from "./i18n";
import AppIcon from "./AppIcon.vue";

const th = computed(() => locale.value === "th-TH");
const categories = computed(() => [
  ["logs", th.value ? "Logs จาก Agent / Windows / ระบบต่าง ๆ" : "Agent / Windows / system logs"],
  ["monitors", th.value ? "ประวัติการตรวจ Monitor" : "Monitor check history"],
  ["hosts", th.value ? "ประวัติ CPU, RAM, Disk และ Inventory" : "Host metrics and inventory history"],
  ["databases", th.value ? "ประวัติ Metric ฐานข้อมูล" : "Database metric history"],
  ["health", th.value ? "ประวัติ Health Check และ WebSocket ที่จบแล้ว" : "Health transitions and completed WebSocket gaps"],
  ["notifications", th.value ? "ประวัติการส่งแจ้งเตือน" : "Notification delivery history"],
  ["incidents", th.value ? "เหตุการณ์ที่ปิดเคสและระบบฟื้นตัวแล้ว" : "Closed and recovered incidents"],
  ["findings", th.value ? "รายการ Compliance ที่แก้ไขแล้ว" : "Resolved compliance findings"]
]);
const selected = ref<string[]>([]), days = ref("90"), confirmation = ref(""), busy = ref(false), error = ref("");
type Preview = { id: string; cutoff: string; expiresAt: string; total: number; counts: { category: string; table: string; count: number }[] };
const preview = ref<Preview | null>(null);
const result = ref<{ total: number; backup: string } | null>(null);
function reset() { preview.value = null; confirmation.value = ""; result.value = null; error.value = ""; }
async function inspect() {
  reset(); busy.value = true;
  try { preview.value = await api<Preview>("/api/settings/data/preview", { method: "POST", body: JSON.stringify({ categories: selected.value, olderThanDays: days.value === "all" ? null : Number(days.value) }) }); }
  catch (e) { error.value = String(e instanceof Error ? e.message : e); }
  finally { busy.value = false; }
}
async function clean() {
  if (!preview.value || confirmation.value !== "DELETE HISTORY") return;
  busy.value = true; error.value = "";
  try {
    result.value = await api("/api/settings/data/cleanup", { method: "POST", body: JSON.stringify({ previewId: preview.value.id, confirmation: confirmation.value }) });
    preview.value = null; confirmation.value = "";
  } catch (e) { error.value = String(e instanceof Error ? e.message : e); preview.value = null; confirmation.value = ""; }
  finally { busy.value = false; }
}
</script>

<template>
  <section class="settings-card regional-card data-management" :aria-busy="busy">
    <h3><AppIcon name="history" /> {{ th ? 'จัดการข้อมูลและประวัติ' : 'Data and history management' }}</h3>
    <p>{{ th ? 'สำหรับ Admin: เลือกข้อมูล ดูจำนวน แล้วพิมพ์ยืนยันก่อนล้าง ระบบจะสำรองฐานข้อมูลก่อนลบ หากสำรองไม่สำเร็จจะไม่ลบข้อมูล' : 'Admin only: select history, preview counts, then type to confirm. A database backup must succeed before deletion.' }}</p>
    <p class="workflow-note">{{ th ? 'เก็บผู้ใช้ การตั้งค่า Monitor/Agent ค่าล่าสุด และรายการที่ยังไม่จบไว้เสมอ รวมถึง Audit trail, หลักฐาน Backup/Restore, รายงาน และข้อมูลช่องโหว่ หน้านี้ไม่ใช่ Factory reset' : 'Preserves users, configuration, monitors, agents, latest readings, active records, audit trail, backup/restore evidence, reports and vulnerability records. This is not a factory reset.' }}</p>
    <fieldset :disabled="busy">
      <legend>{{ th ? 'เลือกประเภทประวัติ' : 'History categories' }}</legend>
      <div class="cleanup-categories">
        <label v-for="[key, label] in categories" :key="key"><input v-model="selected" type="checkbox" :value="key" @change="reset" /> {{ label }}</label>
      </div>
      <label class="cleanup-age">{{ th ? 'ช่วงข้อมูลที่จะล้าง' : 'History to delete' }}
        <select v-model="days" @change="reset">
          <option v-for="n in [7,30,90,180,365,730]" :key="n" :value="String(n)">{{ th ? `เก่ากว่า ${n} วัน` : `Older than ${n} days` }}</option>
          <option value="all">{{ th ? 'ประวัติทั้งหมดที่เข้าเงื่อนไข' : 'All eligible history' }}</option>
        </select>
      </label>
      <button class="secondary" :disabled="!selected.length" @click="inspect"><AppIcon name="search" /> {{ th ? 'ตรวจจำนวนก่อนล้าง' : 'Preview cleanup' }}</button>
    </fieldset>
    <div v-if="preview" class="workflow-result" aria-live="polite">
      <strong>{{ th ? `พบ ${preview.total.toLocaleString()} รายการที่ล้างได้` : `${preview.total.toLocaleString()} eligible records` }}</strong>
      <p>{{ th ? 'ก่อนเวลา' : 'Before' }} {{ new Date(preview.cutoff).toLocaleString(locale) }} · {{ th ? 'ผลตรวจใช้ได้ 10 นาที' : 'Preview valid for 10 minutes' }}</p>
      <ul><li v-for="key in selected" :key="key">{{ categories.find(c => c[0] === key)?.[1] }}: {{ preview.counts.filter(c => c.category === key).reduce((sum, c) => sum + c.count, 0).toLocaleString() }}</li></ul>
      <label v-if="preview.total">{{ th ? 'ลบแล้วเรียกคืนจากหน้าจอนี้ไม่ได้ พิมพ์ DELETE HISTORY เพื่อยืนยัน' : 'Deletion cannot be undone here. Type DELETE HISTORY to confirm' }}
        <input v-model="confirmation" :disabled="busy" autocomplete="off" placeholder="DELETE HISTORY" />
      </label>
      <button v-if="preview.total" class="secondary cleanup-delete" :disabled="busy || confirmation !== 'DELETE HISTORY'" @click="clean"><AppIcon name="trash" /> {{ busy ? (th ? 'กำลังสำรองและล้างข้อมูล…' : 'Backing up and deleting…') : (th ? 'สำรองและล้างตามรายการข้างต้น' : 'Back up and delete listed history') }}</button>
    </div>
    <p v-if="error" role="alert" class="cleanup-delete">{{ error }}</p>
    <div v-if="result" class="workflow-result" role="status">
      <strong>{{ th ? `ล้างแล้ว ${result.total.toLocaleString()} รายการ` : `Deleted ${result.total.toLocaleString()} records` }}</strong>
      <p>{{ th ? 'ฐานข้อมูลสำรองก่อนล้าง (อยู่บน Server):' : 'Database backup before cleanup (on server):' }} <code>{{ result.backup }}</code></p>
    </div>
    <p class="workflow-note">{{ th ? 'ไฟล์สำรองอยู่ใน data/maintenance-backups บน Volume เดิม ไม่ถูกล้างจากหน้านี้ และใช้พื้นที่ดิสก์เพิ่ม ควรคัดลอกออกเก็บพร้อม Master key เดิม การกู้คืนต้องหยุดแอพและให้ผู้ดูแลแทนที่ฐานข้อมูล สำรองนี้มีเฉพาะฐานข้อมูล ไม่รวมไฟล์รายงาน การล้างทำให้พื้นที่ใน SQLite นำกลับมาใช้ได้ แต่ขนาดไฟล์อาจยังไม่ลดลง' : 'Backups remain in data/maintenance-backups on the same volume and consume disk space. Copy them elsewhere and retain the original master key. Restore requires stopping the app and an administrator replacing the database. These backups contain the database only, not report files. SQLite reuses deleted space; its file may not shrink.' }}</p>
  </section>
</template>

<style scoped>
.data-management h3 { display:flex; align-items:center; gap:8px; }
.data-management fieldset { border:0; padding:0; margin:18px 0; min-width:0; }
.data-management legend { margin-bottom:12px; font-weight:600; }
.cleanup-categories { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:12px; margin-bottom:20px; }
.cleanup-categories label { display:flex; align-items:center; gap:8px; }
.cleanup-categories input { width:auto; margin:0; }
.cleanup-age { display:flex; flex-wrap:wrap; align-items:center; gap:12px; margin-bottom:16px; }
.cleanup-age select { width:auto; max-width:100%; }
.data-management .workflow-result label { display:block; margin:16px 0; }
.data-management .workflow-result input { display:block; max-width:360px; margin-top:8px; }
.cleanup-delete { color:var(--danger, #ef4444); }
.data-management code { overflow-wrap:anywhere; }
</style>
