import { describe, expect, it } from "vitest";
import { incidentGuidance } from "./incident-guidance";
describe("incident explanation and risk", () => {
  it.each(["HTTP","TCP","DNS","DATABASE","SUPABASE","PING","SSL","WEBSOCKET","DOCKER"])("explains %s with actionable verification in both languages", monitorType => {
    for (const thai of [true,false]) {
      const guide=incidentGuidance({monitorType,status:"DOWN"},thai);
      expect(guide.meaning.length).toBeGreaterThan(20);
      expect(guide.risk.length).toBeGreaterThan(20);
      expect(guide.steps).toHaveLength(3);
      expect(guide.verify.length).toBeGreaterThan(20);
    }
  });
  it("uses the recorded health policy link rather than matching free-form messages", () => {
    const guide=incidentGuidance({monitorType:null,healthMetricKey:"ram_percent",status:"CRITICAL"},false);
    expect(guide.meaning).toContain("Health Check");
    expect(guide.risk).toContain("Memory");
  });
  it("explains a monitoring pause without claiming an outage", () => {
    const guide=incidentGuidance({monitorType:"HTTP",status:"PAUSED"},false);
    expect(guide.meaning).toContain("distinguish");
    expect(guide.risk).toContain("monitoring gap");
  });
  it("does not infer compromise or data loss for unknown legacy incidents", () => {
    expect(incidentGuidance({status:"DOWN"},false).risk).toContain("does not establish compromise or data loss");
  });
});
