# แหล่งข้อมูลภัยคุกคาม

อัปเดต Linux Agent image รุ่นเดียวกับ server ก่อนใช้ตัวแปรใหม่ เพิ่มเฉพาะ path ที่มีจริงและอ่านได้
ไม่ต้องเปิด inbound port เพิ่ม Agent ส่งข้อมูลผ่าน HTTPS เดิม

```yaml
# เพิ่มใน environment ของ Agent เดิม
SUPAPULSE_NPM_LOG: /logs/npm/proxy-host-1_access.log
SUPAPULSE_UFW_LOG: /host/var/log/ufw.log
SUPAPULSE_FAIL2BAN_LOG: /host/var/log/fail2ban.log
# หาก Log แบบไม่มี timezone ใช้เวลาท้องถิ่น ให้ตั้ง TZ ตรงกับเครื่องต้นทาง
TZ: Asia/Bangkok
```

Mount directory log ของ NPM เป็น `/logs/npm:ro` เช่น `/srv/npm/data/logs:/logs/npm:ro`
ใช้ directory ไม่ใช่ bind ไฟล์เดี่ยว เพื่อให้ตามไฟล์ใหม่หลัง rotation ได้
รองรับ NPM proxy/standard format และ Nginx combined ผ่าน SUPAPULSE_NGINX_LOG
ไฟล์แต่ละตัวมี offset แยก เริ่มท้ายไฟล์โดยปริยาย ตั้ง SUPAPULSE_LOG_BACKFILL=1 เฉพาะเมื่อต้องการอ่านไฟล์ตั้งแต่ต้นครั้งแรก
การส่งซ้ำถูก deduplicate ที่ server ไม่บันทึก token หรือ HTTP headers

NPM ต้องบันทึก client IP ที่เชื่อถือได้ก่อนเข้า Agent: กำหนด trusted proxy เฉพาะ proxy/CDN ที่ใช้งานจริง
อย่าเชื่อ X-Forwarded-For จากทุก IP และอย่านับ IP ของ Cloudflare/NPM ว่าเป็นผู้โจมตีโดยไม่ตรวจ topology
ตัวอ่านใช้ค่า Client ที่ NPM บันทึก ไม่ตีความ header ที่ผู้ร้องขอส่งเอง

Fail2ban: Ban เป็นหลักฐานของการแบน ณ เวลานั้น Unban ดูได้ใน Event logs และลำดับเหตุการณ์ ไม่ได้หมายถึงแบนตลอดไป
UFW: รับเฉพาะ BLOCK/REJECT ไม่สรุปว่าทุก packet เป็นการโจมตี
HTTP_PROBE: URL รูปแบบไฟล์สำคัญเป็นเพียง heuristic ไม่ใช้ HTTP 404/500 ทั้งหมดเป็นภัย และ 200 ไม่ยืนยันข้อมูลรั่ว

ตรวจ `docker compose logs --tail 100 supapulse-agent` และหน้า Coverage
การไม่มี Log อาจเกิดจาก path/สิทธิ์/ไม่มีเหตุการณ์ ต้องตรวจ source จริงด้วย
ข้อจำกัดตัวอ่านไฟล์: บรรทัดที่เขียนลงไฟล์เก่าระหว่าง rotation กับรอบอ่านอาจไม่ถูกเก็บ

แหล่งอ้างอิงรูปแบบ: https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/docker/rootfs/etc/nginx/conf.d/include/log-proxy.conf
