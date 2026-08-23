# Byakugan production deployment

## Scope and target architecture

This guide deploys one Byakugan application instance behind Caddy with automatic HTTPS. The application container has no published host port, runs as a non-root user, drops Linux capabilities, uses a read-only root filesystem, and writes only to its data volume and temporary filesystem.

This release still uses SQLite and therefore supports one active application replica. Do not scale the `supapulse` service beyond one replica. Host or VM redundancy is achieved through tested backup/restore and infrastructure replacement, not concurrent writers.

## Prerequisites

- A supported Linux server with current Docker Engine and Compose plugin.
- A DNS A/AAAA record for the monitoring hostname pointing to the server.
- Inbound TCP 80 and 443. Keep SSH restricted to the administration network.
- At least 2 CPU, 2 GB RAM, and storage sized for metrics, reports, and retention.
- An external encrypted backup destination. Keep recovery secrets separately.

## Secrets and environment

Create `.env` with restrictive permissions (`chmod 600 .env`):

```dotenv
SUPAPULSE_DOMAIN=monitor.example.com
SUPAPULSE_PUBLIC_ORIGIN=https://monitor.example.com
SUPAPULSE_MASTER_KEY=generate-an-independent-64-character-secret
SUPAPULSE_SESSION_SECRET=generate-another-independent-64-character-secret
```

Generate secrets with `openssl rand -hex 32`. Never reuse these values. The master key decrypts stored monitor, OIDC, SMTP, S3, and MFA configuration. Losing it makes encrypted configuration unrecoverable. The session secret invalidates browser sessions when changed.

Store a protected copy of `.env` in an organizational password vault. It must not be stored inside the database backup, Git repository, evidence ZIP, or the same S3 credentials used by Byakugan.

## Deploy

```bash
docker compose -f compose.production.yaml config
docker compose -f compose.production.yaml build --pull
docker compose -f compose.production.yaml up -d
docker compose -f compose.production.yaml ps
curl --fail https://monitor.example.com/ready
```

Create the local administrator, enable TOTP MFA, record recovery codes in the password vault, configure the application timezone, then configure OIDC. Keep one local MFA-protected emergency administrator.

## Verification checklist

- `/health` and `/ready` return HTTP 200 without authentication.
- `/api/users` returns HTTP 401 without a valid session.
- Browser session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
- TLS certificate is valid and HSTS is present.
- `docker inspect` confirms `ReadonlyRootfs=true`, non-root user, and no Docker socket.
- The audit evidence chain reports valid.
- SMTP/S3, backup connector, and notification channels are tested with non-production test events.
- `npm run test:security -- https://monitor.example.com` passes from an administration workstation.
- A backup and isolated restore drill has been completed.

## Updating

Take a verified backup first. Review release notes and dependency audit output, then:

```bash
docker compose -f compose.production.yaml build --pull
docker compose -f compose.production.yaml up -d
docker compose -f compose.production.yaml ps
node scripts/security-test.mjs https://monitor.example.com
```

Keep the previous image tag and backup bundle until post-deployment monitoring and evidence exports have been verified.

## Operational boundaries

- Do not mount `/var/run/docker.sock` in the hardened profile. Use the Byakugan agent for host/container evidence.
- Database monitoring accounts must be read-only and restricted by network policy.
- OIDC, SMTP, and S3 endpoints should be allowlisted at the egress firewall where practical.
- Forward container and reverse-proxy logs to the organization's centralized log platform.
- Caddy data contains TLS private keys and must be protected and backed up according to the PKI policy.
