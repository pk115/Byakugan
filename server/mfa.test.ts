import { describe, expect, it } from "vitest";
import { createMfaSecret, createRecoveryCodes, mfaUri, recoveryCodeHash, verifyMfaCode } from "./mfa.js";

describe("TOTP MFA",()=>{
  it("verifies the RFC 6238 SHA-1 vector reduced to six digits",()=>{expect(verifyMfaCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","287082",59_000)).toBe(true);expect(verifyMfaCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","287083",59_000)).toBe(false)});
  it("creates a 160-bit base32 secret and safe otpauth URI",()=>{const secret=createMfaSecret();expect(secret).toMatch(/^[A-Z2-7]{32}$/);expect(mfaUri(secret,"audit user")).toContain(`secret=${secret}`);expect(mfaUri(secret,"audit user")).toContain("audit%20user")});
  it("creates unique printable recovery codes and stable hashes",()=>{const codes=createRecoveryCodes();expect(new Set(codes).size).toBe(10);expect(codes.every(code=>/^[A-F0-9]{4}(?:-[A-F0-9]{4}){2}$/.test(code))).toBe(true);expect(recoveryCodeHash(codes[0])).toHaveLength(64);expect(recoveryCodeHash(codes[0].toLowerCase())).toBe(recoveryCodeHash(codes[0]))});
});
