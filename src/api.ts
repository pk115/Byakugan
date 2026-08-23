import { locale } from "./i18n";

const thaiErrors:Record<string,string>={"Authentication required":"กรุณาเข้าสู่ระบบ","Invalid username or password":"ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง","Validation failed":"ข้อมูลที่กรอกไม่ถูกต้อง","Administrator role required":"ต้องใช้สิทธิ์ผู้ดูแลระบบ","Invalid authentication code":"รหัสยืนยันตัวตนไม่ถูกต้อง","MFA challenge expired":"คำขอยืนยันตัวตนหมดอายุ กรุณาเข้าสู่ระบบใหม่","MFA enrollment is required for this role":"บัญชีนี้ต้องตั้งค่าการยืนยันตัวตนสองขั้นตอนก่อนใช้งาน","Cross-origin state change rejected":"คำขอจากต้นทางอื่นถูกปฏิเสธเพื่อความปลอดภัย","Enable MFA for every affected user before enforcing this policy":"ผู้ใช้ที่ได้รับผลกระทบทุกคนต้องเปิด MFA ก่อนบังคับใช้นโยบาย"};
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept-Language",locale.value);
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, {
    ...options,
    headers
  });
  if (response.status === 204) return undefined as T;
  const body = await response.json().catch(() => ({}));
  if (!response.ok){const original=body.error??`Request failed (${response.status})`,message=locale.value==="th-TH"?(thaiErrors[original]??original):original,details=body.details?` (${Object.values(body.details as Record<string,string[]>).flat().join(", ")})`:"";throw new Error(message+details)}
  return body as T;
}
