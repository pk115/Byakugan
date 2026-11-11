import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:https";
import { once } from "node:events";
import { expect, it } from "vitest";
import { X509Certificate } from "node:crypto";

process.env.SUPAPULSE_DATA_DIR = mkdtempSync(join(tmpdir(), "byakugan-http-"));
const { db } = await import("./database.js");
const { checkProject } = await import("./monitor.js");

it("only skips certificate verification for the selected HTTP monitor, including redirects", async () => {
  // Public test-only key: never use this certificate outside this local fixture.
  const server = createServer({
    key: readFileSync(new URL("./fixtures/localhost-test-key.pem", import.meta.url)),
    cert: readFileSync(new URL("./fixtures/localhost-test-cert.pem", import.meta.url))
  }, (req, res) => {
    if (req.url === "/") { res.writeHead(302, { location: "/health" }); res.end(); }
    else { res.end("healthy"); }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing test port");
  const id = Number(db.prepare(`INSERT INTO projects(name,supabase_url,encrypted_key,monitor_type,target,retry_count,timeout_seconds,keyword)
    VALUES('TLS test','unused','unused','HTTP',?,0,3,'healthy')`).run(`https://127.0.0.1:${address.port}/`).lastInsertRowid);
  try {
    expect((await checkProject(id)).status).toBe("DOWN");
    db.prepare("UPDATE projects SET ignore_tls_errors=1 WHERE id=?").run(id);
    expect((await checkProject(id)).status).toBe("UP");
    const certificate=db.prepare("SELECT tls_expires_at,tls_checked_at,tls_valid,tls_error FROM projects WHERE id=?").get(id) as {tls_expires_at:string;tls_checked_at:string;tls_valid:number;tls_error:string};
    expect(Number.isFinite(Date.parse(certificate.tls_expires_at))).toBe(true);
    expect(certificate.tls_expires_at).toBe(new Date(new X509Certificate(readFileSync(new URL("./fixtures/localhost-test-cert.pem",import.meta.url))).validTo).toISOString());
    expect(certificate.tls_checked_at).toBeTruthy();
    expect(certificate.tls_valid).toBe(0); // Skipping the service check never makes an invalid certificate trusted.
    expect(certificate.tls_error).toMatch(/self.signed|certificate/i);
    db.prepare("UPDATE projects SET keyword='missing' WHERE id=?").run(id);
    expect((await checkProject(id)).message).toContain("keyword");
    db.prepare("UPDATE projects SET ignore_tls_errors=0 WHERE id=?").run(id);
    const strict = await checkProject(id);
    expect(strict.status).toBe("DOWN");
    expect(strict.message).toMatch(/self.signed|certificate/i);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  }
});
