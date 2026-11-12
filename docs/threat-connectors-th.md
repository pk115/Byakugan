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

## Suricata EVE (เฟส 7)

Sensor ต้องมี Suricata ที่ตั้งกฎและมองเห็น traffic อยู่แล้ว Byakugan ไม่ติดตั้ง sensor หรือเปิด inline IPS ให้อัตโนมัติ
เพิ่มใน Agent ของเครื่อง sensor:

```yaml
SUPAPULSE_SURICATA_LOG: /host/var/log/suricata/eve.json
```

อ่านเฉพาะ `event_type: alert` เก็บ signature/category/severity, source/destination IP/port, flow_id และ action/verdict
ไม่ส่ง packet payload, HTTP headers หรือไฟล์ที่จับได้
สร้างเคสแยก sensor/IP/signature โดย IP ต้นทางของ packet ไม่จำเป็นต้องเป็นผู้โจมตี และเครื่อง Agent คือ sensor ไม่จำเป็นต้องเป็นปลายทางที่ถูกโจมตี
ดู `dst_ip` และ `alert_target_ip` ในหลักฐานก่อนระบุเครื่องที่ได้รับผล; ไม่เดาจับคู่ asset จาก IP ที่อาจซ้ำ/NAT
แผนที่แสดงเส้นไปยังเครื่องที่รายงาน Log หากเป็น IDS จึงเป็นตำแหน่ง sensor ที่ตั้งไว้ ไม่อ้างว่าเป็นเครื่องเหยื่อ
`allowed` แสดง detected; `blocked` หรือ verdict drop/reject แสดงหลักฐานการบล็อก ไม่สรุปว่าถูกเจาะสำเร็จ
อ้างอิง: https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html

## กฎและการจัดการเคส

- กฎเริ่มต้น: ยืนยันตัวตนผิด 10 ครั้ง/15 นาที แยก IP+บัญชี, Firewall ปฏิเสธ 20 พอร์ตไม่ซ้ำ/15 นาที, เว็บขอไฟล์สำคัญ 10 ครั้ง/15 นาที, IDS 1 signature match
- ADMIN ปรับเกณฑ์และข้อยกเว้นได้ในหน้า Threats (บันทึก audit) ข้อยกเว้นต้องมีเหตุผลและเวลาหมดอายุ และไม่ลบ Log
- เคสไม่ปิดอัตโนมัติเพียงเพราะไม่มี Log ใหม่ การปิดต้องบันทึกผลตรวจสอบ; หลังปิดต้องมีหลักฐานใหม่ครบเกณฑ์จึงเปิดซ้ำ
- ลำดับเหตุการณ์แสดงเครื่อง/IP เดียวกันจากช่วงหลักฐานจนถึง 1 ชั่วโมงหลังการตรวจพบล่าสุด ไม่ยืนยันว่าผู้กระทำคนเดียวกัน
- การแจ้งเตือนปิดโดยปริยาย เปิดได้โดย ADMIN เมื่อมีช่องทางพร้อมแล้ว รวมหมายเลขเคสใหม่เป็นกลุ่มตาม cooldown และไม่ส่ง raw Log
- การส่งแต่ละกลุ่มเป็น at-most-once หากส่งล้มเหลวดู notification history ไม่มี retry อัตโนมัติ
- Excel เดิมเพิ่ม Threat Events และ Threat Cases ตามช่วงเวลาและ scope เดิม ไม่เก็บข้อมูลเป็นซ้ำอีกชุด
- เกณฑ์ auth รายเครื่องเดิมหยุดเปิดเคสใหม่เมื่อรับ Agent log ผ่าน API; เคสใหม่แยกละเอียดตาม IP/บัญชี
