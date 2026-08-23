import { describe, expect, it } from "vitest";
import { statusFromHttp } from "./monitor.js";

describe("statusFromHttp", () => {
  it.each([
    [540, "PAUSED"],
    [401, "UNAUTHORIZED"],
    [403, "FORBIDDEN"],
    [404, "MISCONFIGURED"],
    [500, "DOWN"]
  ])("maps HTTP %i to %s", (code, status) => {
    expect(statusFromHttp(code)).toBe(status);
  });
});
