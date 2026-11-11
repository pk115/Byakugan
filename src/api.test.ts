import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";
import { locale, setLocale } from "./i18n";
const initial=locale.value;
afterEach(()=>{setLocale(initial);vi.unstubAllGlobals()});
it.each(["th-TH","en-US"] as const)("keeps HTTP status independent of translated error text in %s",async value=>{
  setLocale(value);
  vi.stubGlobal("fetch",vi.fn(async()=>new Response(JSON.stringify({error:"Authentication required"}),{status:401,headers:{"Content-Type":"application/json"}})));
  try{await api("/api/projects");throw new Error("Expected authentication failure")}catch(error){
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
    expect((error as Error).message).toBe(value==="th-TH"?"กรุณาเข้าสู่ระบบ":"Authentication required");
  }
});
