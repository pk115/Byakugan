const authentication = {
  th: { title: "ยืนยันตัวตนไม่สำเร็จ", meaning: "อาจเกิดจากรหัสผ่านผิด โปรแกรมตั้งค่าผิด หรือความพยายามเข้าถึงโดยไม่ได้รับอนุญาต เหตุการณ์เดียวไม่ยืนยันว่าเป็นการโจมตี", action: "ตรวจบัญชี IP ต้นทาง และความถี่ แล้วตรวจว่ามีการเข้าสู่ระบบสำเร็จที่เกี่ยวข้องหรือไม่", outcome: "ยืนยันตัวตนไม่สำเร็จ — ไม่ยืนยันว่า IP ถูกบล็อก" },
  en: { title: "Authentication failed", meaning: "This may be a mistyped password, a misconfigured application or an unauthorized access attempt. One event does not establish an attack.", action: "Check the account, source IP and frequency, then investigate related successful logins.", outcome: "Authentication failed — IP blocking is not established" }
};
const denied = {
  th: { title: "Firewall ปฏิเสธการเชื่อมต่อ", meaning: "แหล่ง Log รายงานว่าปฏิเสธการเชื่อมต่อนี้ ไม่ยืนยันว่า IP ถูกแบนถาวรหรือว่าการเชื่อมต่ออื่นถูกป้องกันทั้งหมด", action: "ตรวจพอร์ตปลายทาง กฎ Firewall และ IP ต้นทาง ยืนยันว่าเป็นการปฏิเสธที่คาดหมายและตรวจการเชื่อมต่อที่ได้รับอนุญาตประกอบ", outcome: "การเชื่อมต่อนี้ถูกปฏิเสธตาม Log" },
  en: { title: "Firewall denied a connection", meaning: "The log source reports denying this connection. This does not establish a permanent IP ban or protection of other connections.", action: "Check the destination port, firewall rule and source IP. Verify the denial is expected and review allowed connections as well.", outcome: "This connection was denied according to the log" }
};
const ban = {
 th:{title:"Fail2ban รายงานการแบน IP",meaning:"กฎของ jail รายงานการแบนในเวลานั้น ไม่ได้ยืนยันว่าปัจจุบันยังแบนหรือครอบคลุมทุกบริการ",action:"ตรวจ jail ระยะเวลาแบน และเหตุการณ์ปลดแบนก่อนตัดสินใจดำเนินการ",outcome:"รายงานการแบนตาม Log"},
 en:{title:"Fail2ban reported an IP ban",meaning:"A jail reported a ban at this time. This does not prove the IP remains banned or all services are covered.",action:"Review the jail, ban duration and subsequent unban events.",outcome:"Ban reported by the source"}
};
const probe = {
 th:{title:"ร้องขอเส้นทางไฟล์สำคัญ",meaning:"URL ตรงกับรูปแบบที่มักใช้สำรวจไฟล์สำคัญ อาจเป็นการทดสอบที่ได้รับอนุญาต ไม่ยืนยันว่าดึงข้อมูลสำเร็จ",action:"ตรวจ URL สถานะ HTTP และผู้ทดสอบที่ได้รับอนุญาต ตรวจเนื้อหาที่ตอบกลับผ่านเครื่องมือภายในหากจำเป็น",outcome:"ตรวจพบรูปแบบ URL — ไม่ทราบว่าถูกบล็อกหรือไม่"},
 en:{title:"Sensitive path requested",meaning:"The URL matches a sensitive-file probe pattern. It may be an authorized test and does not establish data disclosure.",action:"Review the URL, HTTP status and authorized scanners. Inspect the actual response internally if needed.",outcome:"URL pattern detected — blocking not established"}
};
const ids = {
 th:{title:"IDS ตรวจพบรูปแบบตาม signature",meaning:"Sensor พบทราฟฟิกที่ตรงกฎ ไม่ยืนยันว่าเจาะสำเร็จ IP ต้นทางของ packet อาจไม่ใช่ผู้โจมตี ต้องตรวจ direction และเป้าหมายในหลักฐาน",action:"ตรวจ signature, flow_id, ต้นทาง/ปลายทาง และ action/verdict ตรวจ false positive และบริการที่เกี่ยวข้อง",outcome:"ตรวจ result และ action/verdict ในหลักฐาน: detected ไม่ยืนยันการบล็อก"},
 en:{title:"IDS signature matched",meaning:"A sensor observed a rule match, not confirmed compromise. Packet source may not be the attacker; review direction and target evidence.",action:"Inspect signature, flow_id, endpoints and action/verdict. Check for false positives and affected services.",outcome:"Inspect result and action/verdict: detected does not establish blocking"}
};
const authEvents = new Set(["LOGIN_FAILED", "SSH_LOGIN_FAILED", "SUDO_AUTH_FAILED", "ROOT_LOGIN_DENIED", "VPN_AUTH_FAILED", "DB_AUTH_FAILED"]);
export function threatGuidance(event: string, thai: boolean) {
  const entry = event === "IDS_ALERT" ? ids : event === "IP_BANNED" ? ban : event === "HTTP_PROBE" ? probe : event === "FIREWALL_DENY" ? denied : authEvents.has(event) ? authentication : null;
  return entry ? entry[thai ? "th" : "en"] : null;
}
