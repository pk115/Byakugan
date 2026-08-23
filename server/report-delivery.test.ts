import {describe,expect,it} from "vitest";
import {deliveryDestination,deliveryErrorCode} from "./report-delivery.js";
describe("report delivery safety",()=>{it("returns only a non-secret S3 destination",()=>expect(deliveryDestination({type:"S3",config:{region:"us-east-1",bucket:"audit",prefix:"iso/",accessKeyId:"secret-id",secretAccessKey:"secret",forcePathStyle:true,wormMode:"COMPLIANCE",retentionDays:365}})).toBe("s3://audit/iso"));it("sanitizes provider error codes",()=>expect(deliveryErrorCode({code:"AUTH failed: password=x"})).toBe("AUTHfailedpasswordx"))});
