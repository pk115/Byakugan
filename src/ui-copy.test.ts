import { afterEach, expect, it } from "vitest";
import { locale, normalizeLocale, setLocale, t } from "./i18n";
import { ui, uiCopy } from "./ui-copy";
import { readFileSync } from "node:fs";
const initial=locale.value;
afterEach(()=>setLocale(initial));
it("changes existing labels reactively in both directions without changing data",()=>{
  setLocale("th-TH"); expect(ui("Run now")).toBe("ตรวจตอนนี้");expect(t("nav.settings")).toBe("ตั้งค่าระบบ");
  setLocale("en-US"); expect(ui("Run now")).toBe("Run now");expect(ui("ยังไม่มีเหตุการณ์บริการล่ม")).toBe("No downtime incidents recorded");
  expect(ui("CVE-2026-1234")).toBe("CVE-2026-1234");
  expect(ui("WIN-PROD-01")).toBe("WIN-PROD-01");
});
it("rejects unsupported stored locale and has nonempty translations",()=>{
  expect(normalizeLocale("bad-value")).toBe("th-TH");
  expect(Object.keys(uiCopy).length).toBeGreaterThan(350);
  expect(Object.values(uiCopy).every(value=>Boolean(value.trim()))).toBe(true);
});
it("preserves backend enum values when translating select labels",()=>{
  const source=readFileSync(new URL("./App.vue",import.meta.url),"utf8");
  for(const value of ["OPEN","RESOLVED","APPROVED","HIGH","LOW"])expect(source).toContain(`value="${value}">{{ ui("${value}") }}`);
  expect(source).toContain('value instanceof ApiError && value.status === 401');
});
