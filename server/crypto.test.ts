import { describe, expect, it } from "vitest";
import { decrypt, encrypt } from "./crypto.js";

describe("credential encryption", () => {
  it("round-trips sensitive configuration without storing plaintext", () => {
    const plaintext = JSON.stringify({ botToken: "secret-token", chatId: "123" });
    const encrypted = encrypt(plaintext);
    expect(encrypted).not.toContain("secret-token");
    expect(decrypt(encrypted)).toBe(plaintext);
  });

  it("uses a unique nonce for every encryption", () => {
    expect(encrypt("same value")).not.toBe(encrypt("same value"));
  });
});
