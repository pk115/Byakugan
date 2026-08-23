# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository.

Include the affected version, reproduction steps, impact, and any suggested mitigation. Do not include real Supabase keys or user data.

## Deployment guidance

- Expose Byakugan only through an HTTPS reverse proxy.
- Use long, independent values for `SUPAPULSE_MASTER_KEY` and `SUPAPULSE_SESSION_SECRET`.
- Use only Supabase publishable/anon keys. Never enter a `service_role` key.
- Back up the data volume and master key separately.
- Keep the container image updated.

Supabase monitors accept only HTTPS `supabase.co` project URLs. Generic HTTP, database, OIDC, SMTP, and S3 integrations are administrative network clients and should be restricted with outbound firewall allowlists in production.

Use `compose.production.yaml` for the hardened deployment profile and run `node scripts/security-test.mjs https://monitor.example.com` after every deployment. Follow `docs/PRODUCTION-DEPLOYMENT.md` and `docs/DISASTER-RECOVERY.md` for secret custody, backup verification, and recovery exercises.
