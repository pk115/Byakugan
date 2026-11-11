import { describe, expect, it } from "vitest";
import { threatGuidance } from "./threat-guidance";
describe("threat evidence explanations", () => {
  it("does not claim an authentication failure blocks the IP", () => {
    expect(threatGuidance("LOGIN_FAILED", false)?.outcome).toContain("not established");
    expect(threatGuidance("FIREWALL_DENY", false)?.outcome).toContain("according to the log");
  });
  it("keeps ordinary HTTP requests and successful logins out of threat classification", () => {
    expect(threatGuidance("HTTP_REQUEST", false)).toBeNull();
    expect(threatGuidance("LOGIN_SUCCESS", true)).toBeNull();
  });
  it("provides both languages for all supported events", () => {
    for (const event of ["LOGIN_FAILED","SSH_LOGIN_FAILED","SUDO_AUTH_FAILED","ROOT_LOGIN_DENIED","VPN_AUTH_FAILED","DB_AUTH_FAILED","FIREWALL_DENY"]) {
      const th = threatGuidance(event, true), en = threatGuidance(event, false);
      expect(th?.title).toBeTruthy(); expect(en?.title).toBeTruthy();
      expect(th?.meaning).not.toEqual(en?.meaning);
    }
  });
});
