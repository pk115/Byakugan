const authentication = {
  th: { title: "ยืนยันตัวตนไม่สำเร็จ", meaning: "อาจเกิดจากรหัสผ่านผิด โปรแกรมตั้งค่าผิด หรือความพยายามเข้าถึงโดยไม่ได้รับอนุญาต เหตุการณ์เดียวไม่ยืนยันว่าเป็นการโจมตี", action: "ตรวจบัญชี IP ต้นทาง และความถี่ แล้วตรวจว่ามีการเข้าสู่ระบบสำเร็จที่เกี่ยวข้องหรือไม่", outcome: "ยืนยันตัวตนไม่สำเร็จ — ไม่ยืนยันว่า IP ถูกบล็อก" },
  en: { title: "Authentication failed", meaning: "This may be a mistyped password, a misconfigured application or an unauthorized access attempt. One event does not establish an attack.", action: "Check the account, source IP and frequency, then investigate related successful logins.", outcome: "Authentication failed — IP blocking is not established" }
};
const denied = {
  th: { title: "Firewall ปฏิเสธการเชื่อมต่อ", meaning: "แหล่ง Log รายงานว่าปฏิเสธการเชื่อมต่อนี้ ไม่ยืนยันว่า IP ถูกแบนถาวรหรือว่าการเชื่อมต่ออื่นถูกป้องกันทั้งหมด", action: "ตรวจพอร์ตปลายทาง กฎ Firewall และ IP ต้นทาง ยืนยันว่าเป็นการปฏิเสธที่คาดหมายและตรวจการเชื่อมต่อที่ได้รับอนุญาตประกอบ", outcome: "การเชื่อมต่อนี้ถูกปฏิเสธตาม Log" },
  en: { title: "Firewall denied a connection", meaning: "The log source reports denying this connection. This does not establish a permanent IP ban or protection of other connections.", action: "Check the destination port, firewall rule and source IP. Verify the denial is expected and review allowed connections as well.", outcome: "This connection was denied according to the log" }
};
const authEvents = new Set(["LOGIN_FAILED", "SSH_LOGIN_FAILED", "SUDO_AUTH_FAILED", "ROOT_LOGIN_DENIED", "VPN_AUTH_FAILED", "DB_AUTH_FAILED"]);
export function threatGuidance(event: string, thai: boolean) {
  const entry = event === "FIREWALL_DENY" ? denied : authEvents.has(event) ? authentication : null;
  return entry ? entry[thai ? "th" : "en"] : null;
}
