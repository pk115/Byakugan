// Run: node --test agent/
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, appendFile, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAuthLine, parseNginxLine, parseJournalEntry, readNewLines, collectLogs } from "./log-collector.mjs";

const now = new Date("2026-11-04T12:00:00Z");
const auth = (m) => parseAuthLine(`Nov  4 10:00:01 web01 ${m}`, now);

test("auth.log mapping", () => {
  assert.deepEqual(auth("sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 5555 ssh2: RSA SHA256:x"), { source: "host", timestamp: auth("sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 1 ssh2").timestamp, host: "web01", event: "SSH_LOGIN_SUCCESS", actor: "deploy", srcIp: "10.0.0.5", result: "success", severity: "info", details: { auth_method: "publickey" } });
  assert.equal(auth("sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2").event, "SSH_LOGIN_FAILED");
  assert.equal(auth("sshd[1]: ROOT LOGIN REFUSED FROM 1.2.3.4").event, "ROOT_LOGIN_DENIED");
  assert.equal(auth("sshd[1]: User root from 1.2.3.4 not allowed because not listed in AllowUsers").event, "ROOT_LOGIN_DENIED");
  const sudo = auth("sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update");
  assert.equal(sudo.event, "SUDO_COMMAND"); assert.equal(sudo.details.command, "/usr/bin/apt update"); assert.equal(sudo.details.run_as, "root");
  assert.equal(auth("sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob").event, "SUDO_AUTH_FAILED");
  assert.equal(auth("sudo:    bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"), null);
  assert.equal(auth("CRON[9]: pam_unix(cron:session): session opened"), null);
  assert.equal(parseAuthLine("2026-11-04T10:00:01.123456+07:00 web01 sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2").timestamp, "2026-11-04T03:00:01.123Z");
});

test("nginx combined line", () => {
  const e = parseNginxLine('203.0.113.9 - - [04/Nov/2026:10:00:01 +0700] "GET /api/x?y=1 HTTP/1.1" 502 12 "-" "curl/8" 0.031', "web01");
  assert.equal(e.timestamp, "2026-11-04T03:00:01.000Z"); assert.equal(e.severity, "error"); assert.equal(e.details.status, 502); assert.equal(e.details.request_uri, "/api/x?y=1");
});

test("journal start/stop/restart", () => {
  const j = (MESSAGE) => parseJournalEntry({ UNIT: "nginx.service", MESSAGE, __REALTIME_TIMESTAMP: "1793761201000000", _HOSTNAME: "web01" });
  assert.equal(j("Started nginx.service - web").event, "SERVICE_START");
  assert.equal(j("Stopped nginx.service - web").event, "SERVICE_STOP");
  assert.equal(j("nginx.service: Scheduled restart job, restart counter is at 1.").event, "SERVICE_RESTART");
  assert.equal(parseJournalEntry({ UNIT: "x.scope", MESSAGE: "Started x" }), null);
});

test("offsets persist across runs and survive rotation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "byk-"));
  const log = join(dir, "auth.log"), cfg = { hostname: "h", stateDir: join(dir, "state"), authLog: log };
  await writeFile(log, "Nov  4 10:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2\n");
  const r0 = await collectLogs(cfg); assert.equal(r0.events.length, 0); await r0.commit(); // first run starts at EOF
  await appendFile(log, "Nov  4 10:00:01 h sshd[1]: Failed password for b from 1.1.1.1 port 1 ssh2\nNov  4 10:00:02 h sshd[1]: Fail"); // trailing partial line
  const r1 = await collectLogs(cfg); assert.equal(r1.events.length, 1); await r1.commit();
  assert.equal((await collectLogs(cfg)).events.length, 0); // nothing new, partial line kept back
  await rename(log, log + ".1");
  await writeFile(log, "Nov  4 10:05:00 h sshd[1]: Accepted password for c from 2.2.2.2 port 1 ssh2\n");
  const r2 = await collectLogs(cfg); assert.deepEqual(r2.events.map((e) => e.actor), ["c"]);
  const { state } = await readNewLines(log, undefined, { backfill: true }); assert.equal(state.offset > 0, true);
});
