import { db, type ProjectRow } from "./database.js";
import { decrypt } from "./crypto.js";
import { systemRegional, systemText } from "./localization.js";

export type NotificationType = "WEBHOOK" | "DISCORD" | "TELEGRAM";

type NotificationRow = {
  id: number;
  name: string;
  type: NotificationType;
  encrypted_config: string;
  enabled: number;
};

type NotificationConfig = {
  url?: string;
  botToken?: string;
  chatId?: string;
};

function eventText(event: string, project: ProjectRow, message: string) {
  const icon = event === "RECOVERY" ? "🟢" : event === "PAUSED" ? "🟠" : "🔴";
  const {locale,timezone}=systemRegional(),state=event === "RECOVERY" ? systemText("recovered","กลับมาทำงานแล้ว") : event === "PAUSED" ? systemText("is paused","หยุดชั่วคราว") : systemText("is down","ไม่สามารถใช้งานได้"),labelMonitor=systemText("Monitor","มอนิเตอร์"),labelTime=systemText("Time","เวลา"),time=new Intl.DateTimeFormat(locale,{dateStyle:"medium",timeStyle:"long",timeZone:timezone}).format(new Date());
  return `${icon} ${project.name} ${state}\n${message}\n${labelMonitor}: ${project.monitor_type}\n${labelTime}: ${time} (${timezone})\nUTC: ${new Date().toISOString()}`;
}

async function deliver(row: NotificationRow, config: NotificationConfig, text: string) {
  if (row.type === "TELEGRAM") {
    if (!config.botToken || !config.chatId) throw new Error("Telegram bot token and chat ID are required");
    const response = await fetch(`https://api.telegram.org/bot${config.botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: config.chatId, text })
    });
    if (!response.ok) throw new Error(`Telegram returned HTTP ${response.status}`);
    return;
  }

  if (!config.url) throw new Error("Webhook URL is required");
  const payload = row.type === "DISCORD" ? { content: text } : { event: "supapulse", text };
  const response = await fetch(config.url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "Byakugan/0.2.0" },
    body: JSON.stringify(payload),
    redirect: "error"
  });
  if (!response.ok) throw new Error(`Webhook returned HTTP ${response.status}`);
}

export async function dispatchNotifications(project: ProjectRow, event: "DOWN" | "RECOVERY" | "PAUSED", message: string) {
  const rows = db.prepare(`SELECT n.* FROM notifications n
    JOIN project_notifications pn ON pn.notification_id = n.id
    WHERE pn.project_id = ? AND n.enabled = 1`).all(project.id) as NotificationRow[];
  const text = eventText(event, project, message);
  await Promise.all(rows.map(async (row) => {
    let success = 1;
    let errorMessage: string | null = null;
    try {
      const config = JSON.parse(decrypt(row.encrypted_config)) as NotificationConfig;
      await deliver(row, config, text);
    } catch (error) {
      success = 0;
      errorMessage = error instanceof Error ? error.message : "Notification failed";
    }
    db.prepare(`INSERT INTO notification_deliveries
      (notification_id, project_id, event, success, error_message) VALUES (?, ?, ?, ?, ?)`)
      .run(row.id, project.id, event, success, errorMessage);
  }));
}

export async function testNotification(type: NotificationType, config: NotificationConfig) {
  const row = { id: 0, name: "Test", type, encrypted_config: "", enabled: 1 } satisfies NotificationRow;
  const {locale,timezone}=systemRegional(),time=new Intl.DateTimeFormat(locale,{dateStyle:"medium",timeStyle:"long",timeZone:timezone}).format(new Date());await deliver(row, config, `🟢 ${systemText("Byakugan test notification","ทดสอบการแจ้งเตือน Byakugan")}\n${systemText("Time","เวลา")}: ${time} (${timezone})\nUTC: ${new Date().toISOString()}`);
}

export async function dispatchSecurityNotification(event:"VULNERABILITY_NEW"|"SCAN_FAILED",text:string){
  const rows=db.prepare("SELECT * FROM notifications WHERE enabled=1").all() as NotificationRow[];
  await Promise.all(rows.map(async row=>{let success=1,errorMessage:null|string=null;try{await deliver(row,JSON.parse(decrypt(row.encrypted_config)) as NotificationConfig,text)}catch(error){success=0;errorMessage=error instanceof Error?error.message:"Notification failed"}db.prepare("INSERT INTO notification_deliveries(notification_id,project_id,event,success,error_message) VALUES(?,NULL,?,?,?)").run(row.id,event,success,errorMessage)}));
}
