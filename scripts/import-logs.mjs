#!/usr/bin/env node
// Ships CSV log exports (audit, db, firewall, host, nginx, vpn) to POST /api/agent/logs.
// Usage: node scripts/import-logs.mjs <dir> --url https://byakugan.example.com --token <agent token> [--dry-run]
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { mappers, normalize, parseCsv } from "../agent/log-mapping.mjs";

export { parseCsv, normalize };

async function main() {
  const args = process.argv.slice(2);
  const opt = (name) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
  const dir = args.find((a) => !a.startsWith("--") && a !== opt("url") && a !== opt("token"));
  const dryRun = args.includes("--dry-run");
  const url = (opt("url") ?? "").replace(/\/$/, ""), token = opt("token") ?? process.env.BYAKUGAN_AGENT_TOKEN;
  if (!dir || (!dryRun && (!url || !token))) { console.error("Usage: import-logs.mjs <dir> --url <server> --token <agent token> [--dry-run]"); process.exit(2); }
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".csv")).sort()) {
    const kind = Object.keys(mappers).find((k) => file.endsWith(`${k}.csv`));
    if (!kind) { console.log(`skip ${file}`); continue; }
    const events = parseCsv(readFileSync(join(dir, file), "utf8")).map((r) => normalize(kind, r));
    let accepted = 0, duplicates = 0;
    for (let i = 0; i < events.length && !dryRun; i += 500) {
      const response = await fetch(`${url}/api/agent/logs`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ events: events.slice(i, i + 500) }) });
      if (!response.ok) { console.error(`${file}: HTTP ${response.status} ${await response.text()}`); process.exit(1); }
      const result = await response.json(); accepted += result.accepted; duplicates += result.duplicates;
    }
    console.log(dryRun ? `${file}: ${events.length} events (dry run) e.g. ${JSON.stringify(events[0])}` : `${file}: ${accepted} accepted, ${duplicates} duplicates`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
