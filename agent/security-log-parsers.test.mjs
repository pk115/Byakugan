import test from 'node:test';
import assert from 'node:assert/strict';
import {parseNpmLine,parseUfwLine,parseFail2banLine,classifyWebEvent,parseSuricataLine} from './security-log-parsers.mjs';
test('NPM preserves effective client IP and detects probes, not ordinary 404s',()=>{
 const line='[12/Nov/2026:10:00:00 +0700] - - 404 - GET https example.test "/.env" [Client 192.0.2.9] [Length 12] [Gzip -] [Sent-to web] "curl" "-"';
 const e=parseNpmLine(line,'proxy');assert.equal(parseNpmLine(line.replace('] - - 404','] 404'),'proxy').event,'HTTP_PROBE');assert.equal(e.srcIp,'192.0.2.9');assert.equal(e.event,'HTTP_PROBE');assert.equal(e.timestamp,'2026-11-12T03:00:00.000Z');
 assert.equal(parseNpmLine(line.replace('/.env','/missing'),'proxy').event,'HTTP_REQUEST');
 assert.equal(parseNpmLine(line.replace('192.0.2.9','spoofed, 10.0.0.1'),'proxy'),null);
 assert.equal(classifyWebEvent({source:'nginx',timestamp:e.timestamp,srcIp:e.srcIp,details:{request_uri:'/%2e%2e/etc/passwd',method:'GET',status:403}}).event,'HTTP_PROBE');
});
test('UFW uses explicit block/reject evidence and supports IPv6',()=>{
 const e=parseUfwLine('2026-11-12T10:00:00+07:00 host kernel: [UFW BLOCK] IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP SPT=123 DPT=22','host');
 assert.equal(e.srcIp,'2001:db8::1');assert.equal(e.details.dst_port,'22');assert.equal(e.result,'deny');
 assert.equal(parseUfwLine('2026-11-12T10:00:00Z host [UFW ALLOW] SRC=192.0.2.1','host'),null);
});
test('Fail2ban distinguishes ban/unban and ignores malformed lines',()=>{
 const line='2026-11-12 10:00:00,001 fail2ban.actions [123]: NOTICE [sshd] Ban 192.0.2.1';
 assert.equal(parseFail2banLine(line,'h').event,'IP_BANNED');
 assert.equal(parseFail2banLine(line.replace(' Ban ',' Unban '),'h').event,'IP_UNBANNED');
 assert.equal(parseFail2banLine('garbage','h'),null);
});
test('Suricata alerts retain bounded metadata, not payload, and distinguish detection from block',()=>{
 const row={timestamp:'2026-11-12T03:00:00.123456+0000',event_type:'alert',src_ip:'192.0.2.1',dest_ip:'10.0.0.2',dest_port:443,proto:'TCP',flow_id:123,alert:{signature_id:1001,signature:'Fixture detection',category:'Test',severity:1,action:'allowed'},payload:'SECRET_PACKET'};
 const e=parseSuricataLine(JSON.stringify(row),'sensor');assert.equal(e.event,'IDS_ALERT');assert.equal(e.result,'detected');assert.equal(e.severity,'critical');assert.equal(e.details.dst_ip,'10.0.0.2');assert.equal(JSON.stringify(e).includes('SECRET_PACKET'),false);
 assert.equal(parseSuricataLine(JSON.stringify({...row,verdict:{action:'drop'}}),'sensor').result,'blocked');
 assert.equal(parseSuricataLine(JSON.stringify({...row,event_type:'flow'}),'sensor'),null);
 assert.equal(parseSuricataLine('{','sensor'),null);
 assert.equal(parseSuricataLine(JSON.stringify(row).replace('"flow_id":123','"flow_id":18446744073709551615'),'sensor').details.flow_id,'18446744073709551615');
});
