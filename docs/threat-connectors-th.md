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

## แผนที่ / GeoIP

ใช้ฐานข้อมูล DB-IP City Lite (CC BY 4.0) ใน volume ของแอพ ไม่ส่ง IP ของคุณไปหา API ภายนอก
หน้าแผนที่แสดง attribution ของ DB-IP และใช้ Natural Earth public-domain land outline
ติดตั้งฐานข้อมูลรุ่นเดือนที่มีเผยแพร่แล้ว เช่น:

```bash
docker exec byakugan node scripts/install-threat-geoip.mjs 2026-11 /app/data
```

คำสั่งดาวน์โหลดจาก download.db-ip.com ผ่าน HTTPS ตรวจว่าอ่าน MMDB ได้ และแทนไฟล์หลังดาวน์โหลดสำเร็จเท่านั้น
ระบบจะโหลดฐานข้อมูลภายใน 1 นาที หรือ reload เมื่อไฟล์เปลี่ยน หากใช้ฐานข้อมูลอื่นให้ตั้ง SUPAPULSE_GEOIP_PATH
อัปเดตเดือนถัดไปด้วยคำสั่งเดิมเปลี่ยน YYYY-MM ไม่มีการดาวน์โหลดอัตโนมัติ
ADMIN ตั้งตำแหน่งเซิร์ฟเวอร์ในหน้าแผนที่ ใช้ตำแหน่งศูนย์ข้อมูลโดยประมาณ ไม่ต้องใส่ที่อยู่บุคคล
private IP/loopback/documentation ranges ไม่ถูก geolocate; IP ที่ไม่ทราบพิกัดยังอยู่ในตาราง
แผนที่/อันดับประเทศแสดง 100 คู่ IP-เครื่องที่พบบ่อยที่สุดตามตัวกรอง ไม่ใช่ยอดรวมทุกประเทศ
กราฟแสดงล่าสุด 168 ชั่วโมงที่มีข้อมูลภายในช่วงที่เลือก ไม่เติมช่องว่างว่าเป็นศูนย์
