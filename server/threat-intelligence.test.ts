import { describe,expect,it } from "vitest";
import { parseEpss,parseKev } from "./threat-intelligence.js";

describe("threat intelligence parsers",()=>{
  it("normalizes CISA KEV entries",()=>{const result=parseKev({catalogVersion:"2026.08.24",dateReleased:"2026-08-24",vulnerabilities:[{cveID:"CVE-2026-12345",dateAdded:"2026-08-01",dueDate:"2026-08-22",knownRansomwareCampaignUse:"Known",requiredAction:"Apply mitigations"},{cveID:"invalid"}]});expect(result.items.size).toBe(1);expect(result.items.get("CVE-2026-12345")?.dueDate).toBe("2026-08-22");expect(result.catalogVersion).toBe("2026.08.24")});
  it("parses FIRST probabilities as numeric values",()=>{const result=parseEpss({data:[{cve:"CVE-2025-9876",epss:"0.428100000",percentile:"0.981200000"}]});expect(result.get("CVE-2025-9876")).toEqual({score:.4281,percentile:.9812})});
  it("rejects malformed upstream data",()=>{expect(()=>parseKev({})).toThrow("Invalid CISA KEV feed");expect(()=>parseEpss({data:null})).toThrow("Invalid FIRST EPSS feed")});
});
