import {describe,expect,it} from "vitest";
import {allowedEmail,chooseRole} from "./oidc.js";
describe("OIDC policy",()=>{
  it("uses the highest mapped role",()=>expect(chooseRole(["staff","security"],{ADMIN:["security"],OPERATOR:["staff"]},"VIEWER")).toBe("ADMIN"));
  it("falls back safely",()=>expect(chooseRole([],{},"VIEWER")).toBe("VIEWER"));
  it("enforces exact email domains",()=>{expect(allowedEmail("a@example.com",["example.com"])).toBe(true);expect(allowedEmail("a@evil-example.com",["example.com"])).toBe(false)});
});
