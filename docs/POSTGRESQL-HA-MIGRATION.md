# PostgreSQL migration and high-availability roadmap

## Release status

Byakugan 1.11 still runs on SQLite. It provides a verified migration rehearsal to PostgreSQL, but it does **not** provide a PostgreSQL application runtime or multi-replica HA yet. Do not change the application database URL or remove the SQLite volume in this release.

The migration command introspects the live SQLite schema, creates equivalent PostgreSQL tables, loads all rows in one transaction, recreates primary keys, foreign keys, unique constraints and indexes, resets identity sequences, and compares a deterministic SHA-256 digest and row count for every table. Any mismatch rolls back the complete target transaction. A successful run writes `supapulse_migration_metadata` to the PostgreSQL target.

## Safe rehearsal

1. Create a normal Byakugan backup and retain it outside the host.
2. Start an empty PostgreSQL target:

   ```bash
   docker compose -f compose.postgres-migration.yaml up -d
   ```

3. Keep PostgreSQL bound to localhost. Set the migration process variables without committing credentials:

   ```bash
   export SUPAPULSE_SQLITE_PATH=/absolute/path/to/supapulse.db
   export SUPAPULSE_POSTGRES_URL='postgresql://supapulse:password@127.0.0.1:5432/supapulse'
   npm run migrate:postgres
   ```

4. Archive the JSON reconciliation result and query the target metadata:

   ```sql
   select * from supapulse_migration_metadata order by migrated_at desc;
   ```

The target `public` schema must be empty. `--drop-existing` is intentionally explicit and destructive; use it only against a verified disposable migration target.

## Consistent production snapshot

For a later approved cutover window, set `SUPAPULSE_MAINTENANCE_MODE=true` and restart Byakugan. Mutating API requests return HTTP 503 with `Retry-After`, `/ready` reports `draining`, and the scheduler does not start. Create and verify a backup before migration. Version 1.11 must then be returned to its SQLite runtime; it cannot complete the PostgreSQL runtime cutover.

## Required work before runtime cutover

1. Replace synchronous `better-sqlite3` calls with an asynchronous repository interface implemented for both SQLite and PostgreSQL.
2. Run API, scheduler, report, authentication, encryption and audit-chain parity tests against both engines.
3. Add versioned PostgreSQL-native schema migrations rather than runtime SQLite introspection.
4. Add a PostgreSQL advisory-lock leader election so exactly one application replica runs scheduled checks and report delivery.
5. Move generated report artifacts to shared S3-compatible storage; local replica files cannot be authoritative in HA.
6. Test expand/contract upgrades, rollback, point-in-time recovery and restore into an isolated environment.
7. Perform a controlled cutover, soak test, reconciliation, and documented rollback exercise.

## Target HA topology

```text
Users -> HTTPS load balancer -> Byakugan replica A
                           +-> Byakugan replica B
                                  |
                                  +-> PostgreSQL HA endpoint
                                  +-> S3-compatible report/evidence storage

PostgreSQL primary -> synchronous/asynchronous standby -> off-site backups/PITR
```

Use a managed PostgreSQL HA service where possible. For self-hosting, use an established operator or Patroni-based platform with an external distributed consensus store; a plain two-container PostgreSQL Compose file is not HA. Terminate TLS at a trusted proxy, use separate migration/runtime roles, enforce encrypted PostgreSQL connections, and monitor replication lag, backup age and restore-test evidence.

## Cutover acceptance gates

- 100% table count, row count and SHA-256 reconciliation.
- All automated tests pass against PostgreSQL.
- Two application replicas serve requests while one replica is terminated.
- Only one scheduler leader executes each due job.
- PostgreSQL primary failover succeeds within the declared RTO and does not exceed the RPO.
- Backup restore and audit-chain verification succeed in an isolated environment.
- Rollback procedure is timed, witnessed and attached to the audit evidence package.
