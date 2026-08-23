import {describe,expect,it} from "vitest";
import {collectAuditReport,createPdfReport,createXlsxReport} from "./reports.js";

describe("localized audit reports",()=>{const to=new Date().toISOString(),from=new Date(Date.now()-86400000).toISOString(),data=collectAuditReport(from,to);
  it("creates Thai PDF with timezone metadata",async()=>{const report=await createPdfReport(data,"th-TH","Asia/Bangkok");expect(report.subarray(0,4).toString()).toBe("%PDF");expect(report.length).toBeGreaterThan(1000)});
  it("creates Thai XLSX workbook",async()=>{const report=await createXlsxReport(data,"th-TH","Asia/Bangkok");expect(report.subarray(0,2).toString()).toBe("PK");expect(report.length).toBeGreaterThan(1000)});
});
