import { expect, it } from "vitest";
import { certificateDays, certificateTarget } from "./certificates.js";
it("uses real expiration instants with whole remaining days",()=>{
  expect(certificateDays("2026-11-22T00:00:00Z",Date.parse("2026-11-11T00:00:00Z"))).toBe(11);
  expect(certificateDays(null)).toBe(null);
  expect(certificateDays("invalid")).toBe(null);
});
it("selects HTTPS, WSS, Supabase and explicit SSL targets without probing plaintext HTTP",()=>{
  const target=(monitor_type:"HTTP"|"WEBSOCKET"|"SSL"|"SUPABASE",target:string)=>certificateTarget({monitor_type,target,supabase_url:"https://db.example.test",ssl_port:8443});
  expect(target("HTTP","http://example.test")).toBe(null);
  expect(target("HTTP","https://example.test:9443/path")).toEqual({host:"example.test",port:9443});
  expect(target("WEBSOCKET","wss://example.test/socket")).toEqual({host:"example.test",port:443});
  expect(target("SSL","example.test")).toEqual({host:"example.test",port:8443});
  expect(target("SUPABASE","ignored")).toEqual({host:"db.example.test",port:443});
});
