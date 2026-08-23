# Byakugan

Version 2.2 adds daily and on-demand CVE risk intelligence from the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS. Known exploitation, probability, source provenance, and synchronization evidence are included in vulnerability workflows and audit exports.

## Security scan jobs

Version 2.1 introduces an original cyber-operations guardian illustration on the responsive login experience while keeping the pearl-white Byakugan eye as the primary product mark. The character, clothing, telemetry, and hand pose are original and do not reproduce franchise characters or symbols. Existing `SUPAPULSE_*` environment variables, the `supapulse.db` database filename, and the `supapulse-data` Docker volume remain unchanged for backward compatibility and safe upgrades.

New High/Critical findings and failed scans are sent to enabled notification channels. Findings are deduplicated, resolved when absent from a later scan, and reopened with a counter when detected again. Install Trivy on each scanning agent and update the agent script before using **Scan now**.

## Production operations

- [Production deployment guide](docs/PRODUCTION-DEPLOYMENT.md)
- [Disaster recovery runbook](docs/DISASTER-RECOVERY.md)
- [PostgreSQL migration and HA roadmap](docs/POSTGRESQL-HA-MIGRATION.md)
- Hardened `compose.production.yaml` with automatic HTTPS, non-root execution, read-only root filesystem, dropped capabilities, resource limits, and no Docker socket.
- `npm run backup -- /backup/path` creates a SQLite online backup bundle with per-file SHA-256 manifest.
- `npm run restore -- /backup/bundle` verifies hashes and SQLite integrity before restore and creates a pre-restore safety copy.
- `npm run test:security -- https://monitor.example.com` validates production security headers and anonymous-access boundaries.

## PostgreSQL migration foundation

Version 1.11 adds maintenance/drain mode and a transactional SQLite-to-PostgreSQL migration command with table-by-table row-count and SHA-256 reconciliation. This is a migration rehearsal and target-preparation tool; the application runtime in this release still uses SQLite and must not be pointed at PostgreSQL yet. See the migration/HA roadmap before planning a production cutover.

## Immutable / WORM evidence storage

S3 report delivery channels can apply Object Lock in `GOVERNANCE` or `COMPLIANCE` mode, a fixed retention period, an indefinite Legal Hold, or both. Byakugan verifies that Object Lock is enabled on the destination bucket before saving a WORM-enabled channel.

Successful deliveries record the retention mode, retain-until timestamp, legal-hold state, S3 object version ID, and immutable-verification flag in both the tamper-evident audit chain and `report-deliveries.csv`. Compliance retention cannot be shortened or bypassed before expiry; validate organizational retention requirements before enabling it.

## Automatic audit report delivery

Scheduled PDF and XLSX evidence reports can be delivered through reusable SMTP Email or S3-compatible channels. Channel credentials are encrypted with `SUPAPULSE_MASTER_KEY` and are never returned by the API. Each channel is tested before it can be saved.

Schedules may target multiple channels. Delivery is retried up to three times, and every success or failure is recorded in the tamper-evident audit chain and exported as `report-deliveries.csv`. S3 uploads include the report SHA-256 as object metadata. For MinIO and other compatible services, configure a custom endpoint and enable path-style addressing when required.

## Database health monitoring

Byakugan supports encrypted, scheduled health probes for PostgreSQL, MySQL/MariaDB, Microsoft SQL Server, and MongoDB. Create a **Database health** monitor and supply a dedicated read-only connection string. The connection string is encrypted at rest and is never returned by the API, shared dashboards, or evidence exports.

Collected evidence includes response time, current and maximum connections, database size, replication lag where the engine exposes it, and queries/operations running longer than 30 seconds. Advanced metrics are best-effort: a restricted monitoring account may still report connectivity while privileged server telemetry remains unavailable. Historical metrics are included in `database-metrics.csv` inside the Audit Evidence ZIP.

## OpenID Connect / SSO

Administrators can add Generic OIDC, Microsoft Entra ID, Google Workspace, or Keycloak providers in **Settings → OpenID Connect / SSO**. Byakugan uses Authorization Code flow with PKCE, state, and nonce validation. Provider secrets are encrypted with `SUPAPULSE_MASTER_KEY`; API responses never return them.

Before creating a provider, set `SUPAPULSE_PUBLIC_ORIGIN` to the externally reachable HTTPS origin, for example `https://monitor.example.com`, and set `SUPAPULSE_SECURE_COOKIES=true`. Register the callback URL returned by Byakugan in the identity provider. The format is:

```text
https://monitor.example.com/api/auth/oidc/PROVIDER_ID/callback
```

Use an email-domain allowlist, keep the default role at `VIEWER`, and map trusted IdP group values to elevated roles only when required. JIT provisioning can be disabled when accounts must be pre-approved. Local username/password login intentionally remains available as an emergency recovery path; protect the local administrator with MFA and a strong unique password.

Byakugan is an independent, self-hosted heartbeat dashboard for multiple Supabase projects. It performs a real PostgREST table query on a schedule, records response time and status, and helps low-traffic projects maintain genuine database activity.

> Byakugan is not affiliated with or endorsed by Supabase or Uptime Kuma. Free-plan availability is controlled by Supabase; this project does not guarantee that a project will never be paused.

## Features

- One Docker container and one persistent SQLite volume
- Supabase database, HTTP/HTTPS, keyword, TCP, Ping, DNS, SSL certificate, and Docker container monitors
- Multiple monitors from a single dashboard
- Scheduled real database queries, manual checks, retries, and timeouts
- Explicit `UP`, `DOWN`, `PAUSED`, `UNAUTHORIZED`, `FORBIDDEN`, and `MISCONFIGURED` states
- Encrypted publishable keys at rest
- Heartbeat history and response times
- Telegram, Discord, and generic webhook notifications
- Down, paused, and recovery state transitions with incident history
- Per-monitor notification assignment and maintenance mode
- Responsive dark dashboard inspired by the simplicity of Uptime Kuma
- Public status page at `/status`, with per-monitor publishing and 24-hour uptime
- Custom Byakugan application logo
- Full monitor detail page with status timeline, response graph, 24-hour averages, and 24-hour/30-day uptime
- Secure share dashboards with unguessable encrypted link tokens, monitor selection, custom groups, status timelines, and response graphs
- ISO/IEC 27001 audit evidence profiles with asset owner, environment, criticality, threshold policy, and control mapping
- Tamper-evident SHA-256 audit chain and evidence ZIP export containing CSV datasets, manifests, and per-file hashes
- Secure Linux agent enrollment, automated inventory/health/patch/Docker snapshots, and an exception-first Action Required dashboard

The detailed product, architecture, data-retention, UX, security, and delivery specification is in `docs/PRODUCT-UX-ROADMAP.md`.

## Sharing and project URL privacy

Supabase project URLs and publishable/anon keys are designed to be usable by public clients, but Row Level Security remains mandatory. Never enter a `service_role` key into Byakugan. Shared dashboards intentionally exclude project URLs, hostnames, Docker container names, API keys, and internal error messages. Share links use random 192-bit bearer tokens; the token is encrypted at rest and only its SHA-256 hash is used for public lookup. Anyone who receives a share link can view its health data until the administrator revokes it.

### Docker monitor security

Docker monitoring requires access to `/var/run/docker.sock`. The included Compose file mounts the socket and adds the `DOCKER_GID` supplementary group. On Linux, set `DOCKER_GID` in `.env` to the group ID that owns the Docker socket if it is not `0`. Remove the socket mount and `group_add` block if Docker monitoring is not needed. Docker API access is highly privileged even when the socket file is mounted read-only.

## Quick start

Clone the repository and create local secrets:

```bash
cp .env.example .env
openssl rand -hex 32
openssl rand -hex 32
```

Put the generated values in `.env` as `SUPAPULSE_MASTER_KEY` and `SUPAPULSE_SESSION_SECRET`, then start it:

```bash
docker compose up -d --build
```

Byakugan listens only on `127.0.0.1:3010` by default. Put it behind an HTTPS reverse proxy, or change the port mapping only if you understand the exposure risk.

Keep `SUPAPULSE_SECURE_COOKIES=false` for local HTTP access. Change it to `true` when the application is served through HTTPS.

Open `http://127.0.0.1:3010` and create the first administrator.

## Prepare each Supabase project

Run this in the project's SQL Editor:

```sql
create table if not exists public.supapulse_heartbeat (
  id smallint primary key,
  value text not null
);

insert into public.supapulse_heartbeat (id, value)
values (1, 'alive')
on conflict (id) do update set value = excluded.value;

alter table public.supapulse_heartbeat enable row level security;

create policy "Allow Byakugan heartbeat read"
on public.supapulse_heartbeat
for select
to anon
using (id = 1);
```

If the policy already exists, remove that `create policy` statement or drop the old policy before re-running it.

Add the project URL and its **publishable/anon key** in Byakugan. Never provide a `service_role` key.

## Local development

Requires Node.js 22 or newer:

```bash
npm install
npm run dev
```

The Vue development server runs on `http://localhost:5173` and proxies API calls to the backend on port `3000`.

```bash
npm test
npm run typecheck
npm run build
```

## Data and backups

SQLite is stored at `/app/data/supapulse.db`. The Compose setup uses the `supapulse-data` Docker volume. Back up that volume while the application is stopped, or use SQLite's online backup facilities.

The master key is not stored in the database. Losing `SUPAPULSE_MASTER_KEY` makes stored project keys unrecoverable, so keep a protected backup of the `.env` file.

## Monitor types

- **Supabase:** performs a real Data API table query. A one-time setup assistant is built into the add-project screen.
- **HTTP/HTTPS:** checks any HTTP endpoint, an optional exact status code, and an optional response keyword.
- **TCP:** checks whether a host and port accept a connection.

Supabase heartbeats should normally run every 6–8 hours. Availability monitors generally use 30–60 second intervals.

## Notifications

Open **Notifications** and add a Telegram bot, Discord webhook, or generic webhook. Use **Send test** before saving. Edit a monitor and select one or more alert channels.

Notifications are sent only on state transitions:

- `UP` to a failure state: down/paused notification
- failure state back to `UP`: recovery notification

This prevents repeated alerts on every scheduled check. Notification credentials are encrypted with `SUPAPULSE_MASTER_KEY`.

## Updating

Pull or replace the source, then rebuild while retaining the Docker volume:

```bash
docker compose build --no-cache supapulse
docker compose up -d --force-recreate supapulse
```

Database migrations run automatically and preserve existing monitors and heartbeat history.

## Current scope

Version `1.5.3` completes the extensible Thai/English setup experience for project monitors, backup connectors, and TOTP/recovery-code enrollment. All primary monitoring, audit, administration, security, reporting, notification, and workflow paths now use locale catalogs with automatic English fallback.

## Linux server agent

Build the agent image from the repository root:

```bash
docker build -t supapulse-agent:local agent
```

Create an enrollment token in **Server Agents**, copy `agent/compose.example.yaml` to the target Linux server, set `SUPAPULSE_URL`, `SUPAPULSE_AGENT_TOKEN`, and the host Docker group ID, then start it with `docker compose up -d`. The token is displayed only once and Byakugan stores only its SHA-256 hash.

For vulnerability evidence, install Trivy where the agent runs and set `SUPAPULSE_TRIVY_TARGET` to the filesystem to scan (for example `/` for a direct host installation). The agent transmits normalized CVE metadata only and caps each report at 2,000 findings.

## License

MIT. See [LICENSE](LICENSE).
