import { describe, expect, it } from "vitest";
import { findingGuidance } from "./finding-guidance";

describe("finding action guidance", () => {
  it.each(["security_updates", "reboot", "container", "log_auth_failures", "log_db_from_wan", "log_backup_failed", ...["cpu_percent", "ram_percent", "disk_c_free_percent", "wss_dropout_seconds", "network_latency_ms", "mongo_connections_percent", "log_gap_minutes", "ssl_days_left", "uptime_sla_percent", "backup_age_ratio"].map(key => `health_${key}`)])("explains impact, concrete steps and verification for %s in both languages", findingKey => {
    for (const thai of [true, false]) {
      const guide = findingGuidance({ findingKey, category: "HEALTH", title: "Test" }, thai);
      expect(guide.steps).toHaveLength(3);
      expect(guide.impact.length).toBeGreaterThan(20);
      expect(guide.verify.length).toBeGreaterThan(20);
    }
  });
  it("uses stable rule keys rather than the translated title", () => {
    const guide = findingGuidance({ findingKey: "reboot", category: "PATCH", title: "ชื่อที่เปลี่ยนได้" }, false);
    expect(guide.verify).toContain("rebootRequired=false");
  });
  it("does not claim a confirmed cause for an unknown detector", () => {
    expect(findingGuidance({ findingKey: "unknown", category: "CUSTOM", title: "Test" }, false).impact).toContain("not yet established");
  });
  it("explains the backup log window rather than promising immediate resolution", () => {
    expect(findingGuidance({ findingKey: "log_backup_failed", category: "LOG", title: "Test" }, false).verify).toContain("24-hour");
  });
});
