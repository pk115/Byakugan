# Byakugan disaster recovery runbook

## Recovery objectives

Define approved RPO and RTO before production use. A practical baseline for a small installation is an RPO of 24 hours and an RTO of 4 hours. Increase backup frequency when evidence loss within 24 hours is unacceptable.

The recoverable set contains:

1. The `supapulse-data` volume: SQLite database and generated reports.
2. `SUPAPULSE_MASTER_KEY`: required to decrypt all protected configuration.
3. Deployment configuration and image version.
4. `SUPAPULSE_SESSION_SECRET`: optional for continuity; rotating it safely signs everyone out.
5. Caddy data if retaining the existing ACME account and certificate material is required.

## Create and verify a backup

The online backup script uses SQLite's backup API, hashes every copied file, and writes a manifest. It deliberately excludes the master key.

```bash
mkdir -p /srv/supapulse-backups
docker compose -f compose.production.yaml run --rm \
  -v /srv/supapulse-backups:/backup \
  supapulse node scripts/backup.mjs /backup
```

Copy the resulting bundle to encrypted off-host storage. Record its manifest SHA-256 in the backup job evidence. Keep at least one copy protected by immutable/WORM retention.

## Restore procedure

1. Declare the incident and record incident owner, start time, approved restore point, expected RPO impact, and change ticket.
2. Provision a clean server with the required Docker version.
3. Restore the exact `.env` master key from the password vault.
4. Copy the selected backup bundle to `/srv/supapulse-backups`.
5. Stop the application before replacement.
6. Run the restore helper. It verifies every file hash and SQLite integrity before replacement and creates a pre-restore safety copy.

```bash
docker compose -f compose.production.yaml stop supapulse
docker compose -f compose.production.yaml run --rm \
  -v /srv/supapulse-backups:/backup:ro \
  supapulse node scripts/restore.mjs /backup/supapulse-TIMESTAMP
docker compose -f compose.production.yaml up -d
```

## Post-restore validation

- `/ready` returns HTTP 200.
- Administrator login and MFA work.
- Audit chain validation passes.
- Monitor/project count matches the selected restore point.
- At least one safe monitor can run successfully.
- Generated reports open and their stored SHA-256 matches.
- OIDC discovery, notification, SMTP, and S3 tests succeed.
- Evidence export succeeds for a known historical period.
- Record actual recovery duration, restored backup ID, manifest hash, data-loss window, deviations, and approver.

## Failed restore and rollback

Stop Byakugan. Preserve logs and the failed restored database for analysis. The restore script reports the path of its `supapulse.db.pre-restore-*` safety copy. Restore that copy only after verifying it with SQLite `integrity_check`, then restart and reassess the incident. Never repeatedly overwrite the only known-good backup.

## Mandatory restore exercises

Perform an isolated restore at least quarterly and after material schema, encryption, or deployment changes. A backup job succeeding is not proof of recoverability. Store each drill as Restore Test evidence with actual recovery minutes, checksum, scope, result, exceptions, and approval.
