const origin=(process.argv[2]??process.env.SUPAPULSE_TEST_ORIGIN??"http://127.0.0.1:3010").replace(/\/$/,"");let failures=0;
function check(condition,message){if(condition)console.log(`PASS ${message}`);else{console.error(`FAIL ${message}`);failures++}}
const health=await fetch(`${origin}/health`);check(health.status===200,"liveness returns 200");check(health.headers.get("cache-control")==="no-store","health is not cached");
const ready=await fetch(`${origin}/ready`);check(ready.status===200,"readiness returns 200");
const session=await fetch(`${origin}/api/session`);check(session.status===200,"session endpoint remains public");for(const [header,expected] of [["x-content-type-options","nosniff"],["x-frame-options","DENY"],["referrer-policy","no-referrer"]])check(session.headers.get(header)===expected,`${header} is hardened`);check((session.headers.get("content-security-policy")??"").includes("frame-ancestors 'none'"),"CSP blocks framing");
const protectedResponse=await fetch(`${origin}/api/users`);check(protectedResponse.status===401,"protected API rejects anonymous access");const body=await protectedResponse.text();check(!/password|master.key|session.secret/i.test(body),"anonymous error does not leak secrets");
const crossOrigin=await fetch(`${origin}/api/auth/logout`,{method:"POST",headers:{Origin:"https://attacker.invalid"}});check(crossOrigin.status===403,"cross-origin state change is rejected");
const missing=await fetch(`${origin}/api/definitely-not-real`);check(missing.status===401||missing.status===404,"unknown API is not served by SPA fallback");
if(failures){console.error(`${failures} security check(s) failed`);process.exit(1)}console.log("All production security smoke checks passed");
