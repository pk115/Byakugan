<script setup lang="ts">
import { computed, ref } from "vue";
import { locale } from "./i18n";
import AppIcon from "./AppIcon.vue";
const props = defineProps<{ agents: {id:number;name:string;hostname:string|null}[]; projects: {id:number;name:string}[]; from: string; to: string }>();
const th = computed(() => locale.value === "th-TH"), scope = ref("all"), busy = ref(false), error = ref(""), checksum = ref("");
async function download() {
  busy.value = true; error.value = ""; checksum.value = "";
  try {
    const from = new Date(`${props.from}T00:00:00.000Z`).toISOString(), to = new Date(`${props.to}T23:59:59.999Z`).toISOString();
    if (from > to) throw new Error(th.value ? "วันเริ่มต้นต้องไม่เกินวันสิ้นสุด" : "Start must not be after end");
    const response = await fetch(`/api/audit/report.servers.xlsx?${new URLSearchParams({from,to,scope:scope.value})}`, { headers: { "Accept-Language": locale.value } });
    if (!response.ok) throw new Error((await response.json()).error ?? `Export failed (${response.status})`);
    const blob = await response.blob(), url = URL.createObjectURL(blob), link = document.createElement("a");
    link.href = url; link.download = `byakugan-server-evidence-${scope.value.replace(":","-")}-${props.from}.xlsx`;
    document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 60000);
    checksum.value = response.headers.get("X-Content-SHA256") ?? "—";
  } catch (e) { error.value = e instanceof Error ? e.message : String(e); }
  finally { busy.value = false; }
}
</script>
<template>
  <section class="server-evidence-export">
    <h3>{{ th ? 'Export หลักฐานเซิร์ฟเวอร์ — Excel ไฟล์เดียว' : 'Server evidence — one Excel workbook' }}</h3>
    <p>{{ th ? 'แยกชีทตามเรื่อง พร้อมสรุปจำนวนและสิ่งที่ยังขาด ใช้ช่วงวันที่ออดิทด้านบนตั้งแต่ 00:00 ถึง 23:59 UTC ข้อมูลสถานะปัจจุบันจะแยกระบุว่าเป็นค่าขณะ Export' : 'Separate topic sheets with counts and evidence gaps. Uses the audit dates above, 00:00–23:59 UTC. Current-state sheets are explicitly marked as-of export.' }}</p>
    <div class="evidence-export-controls">
      <label>{{ th ? 'ขอบเขตข้อมูล' : 'Evidence scope' }}
        <select v-model="scope" :disabled="busy" @change="checksum=''; error=''">
          <option value="all">{{ th ? 'ทั้งหมด — ทุกเซิร์ฟเวอร์และ Monitor' : 'All servers and monitors' }}</option>
          <optgroup :label="th ? 'เซิร์ฟเวอร์ที่ติดตั้ง Agent' : 'Agent servers'"><option v-for="agent in agents" :key="agent.id" :value="`agent:${agent.id}`">{{ agent.hostname || agent.name }} · #{{ agent.id }}</option></optgroup>
          <optgroup :label="th ? 'Monitor บริการหรือฐานข้อมูล' : 'Service or database monitors'"><option v-for="project in projects" :key="project.id" :value="`project:${project.id}`">{{ project.name }} · #{{ project.id }}</option></optgroup>
        </select>
      </label>
      <button class="primary" :disabled="busy || !from || !to" @click="download"><AppIcon :name="busy ? 'refresh' : 'download'" :class="{'icon-spin':busy}" /> {{ busy ? (th ? 'กำลังสร้างไฟล์…' : 'Creating workbook…') : (th ? 'Export Excel ครบชุด' : 'Export evidence Excel') }}</button>
    </div>
    <p class="workflow-note">{{ th ? 'มีข้อมูล ≠ ผ่าน ISO: ต้องตรวจ SoA ความเสี่ยง และเอกสารกระบวนการเพิ่ม เลือกรายเครื่องจะไม่เดาการเชื่อม Backup/Restore หรือ Monitor จากชื่อ จึงอาจมีชีท NOT_LINKED_TO_SCOPE ให้ตรวจในชีทความครอบคลุม หากข้อมูลมากเกินจะขอให้ลดช่วงเวลา โดยไม่ตัดข้อมูลเงียบ ๆ' : 'Evidence presence is not ISO conformity. Review the SoA, risks and process records separately. Individual scope does not guess backup/restore or monitor-to-host links from names; check NOT_LINKED_TO_SCOPE in Coverage. Oversized exports fail explicitly; no silent row truncation.' }}</p>
    <p v-if="error" class="error-banner" role="alert">{{ error }}</p>
    <p v-if="checksum" class="evidence-export-result" role="status">{{ th ? 'สร้างไฟล์แล้ว SHA-256' : 'Workbook created. SHA-256' }}: {{ checksum }}</p>
  </section>
</template>
<style scoped>
.server-evidence-export { padding:20px; margin:18px 0; border:1px solid #2a435e; background:#101d2e; border-radius:12px; }
.server-evidence-export h3 { margin-top:0; }
.server-evidence-export p { line-height:1.7; }
.evidence-export-controls { display:flex; align-items:end; flex-wrap:wrap; gap:16px; margin:16px 0; }
.evidence-export-controls label { display:flex; flex-direction:column; gap:8px; flex:1; min-width:220px; }
.evidence-export-result { overflow-wrap:anywhere; color:#67dfa9; }
</style>
