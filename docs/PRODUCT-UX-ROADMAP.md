# Byakugan Infrastructure Compliance Automation

## Product outcome

Byakugan continuously collects operational evidence and turns it into auditor-ready records. The operating model is: enroll once, collect automatically, work only on exceptions, approve human-only evidence, export by audit scope and period.

## Personas and permissions

| Persona | Primary job | Permissions |
|---|---|---|
| Administrator | Configure platform, users, policies and agents | Full access |
| Operator | Resolve alerts, incidents, patches, backups and vulnerabilities | Operational write, no security settings |
| Control owner | Review exceptions and approve evidence | Assigned scope only |
| Auditor | Inspect immutable evidence and exports | Read-only, scoped audit workspace |
| Viewer | View dashboards/status | Read-only operational data |

## Information architecture

```text
Overview
  Dashboard
  Action Required

Infrastructure
  Assets
  Monitoring
  Server Health
  Containers
  Certificates

Security
  Patches
  Vulnerabilities
  Access Reviews

Operations
  Backups
  Restore Tests
  Changes
  Incidents

Compliance
  Audit Mode
  Control Mapping
  Evidence Library
  Audit Log
  Exports

Settings
  Agents
  Policies
  Notifications
  Users & Roles
  Retention
```

## UX principles

1. Exception first: the landing page shows work requiring action, not raw telemetry.
2. Evidence by default: every automated observation is timestamped and retained without requiring screenshots.
3. Progressive disclosure: summary, evidence timeline, then raw record.
4. Human input only where automation cannot decide: owner, justification, approval, RCA and restore notes.
5. Every status explains why it passed or failed and links to its source evidence.
6. Auditor views never expose credentials, private targets or unrestricted administrator controls.

## Global UI system

- Dark infrastructure dashboard with semantic green/yellow/red/grey states.
- Persistent left navigation grouped by business function.
- Global filters: audit period, environment, owner, criticality and asset group.
- Status vocabulary: PASS, WARNING, FAIL, NO EVIDENCE, EXEMPTED.
- Tables support filter, sort, saved view and CSV export.
- Detail pages use header summary, status timeline, metrics, evidence, incidents and audit history tabs.
- Mobile layout prioritizes status and assigned actions; dense evidence tables remain desktop-first.

## Functional modules

### Dashboard and Action Required

- Counts for assets online/offline, critical alerts, security updates, backup failures, expiring certificates, incidents and overdue reviews.
- Action queue grouped by severity, owner, due date and control.
- Acknowledge, assign, due date, justification, risk acceptance and resolve workflow.
- Daily/weekly digest and overdue escalation.

### Asset inventory

- Asset ID, hostname, IP, OS/version, kernel, environment, owner, department, location/provider, criticality, services and tags.
- Automated agent discovery plus controlled manual metadata.
- Immutable inventory snapshots and field-change history.
- Lifecycle: discovered, active, maintenance, decommissioned.

### Secure agent platform

- One-time enrollment token; stored only as SHA-256 hash centrally.
- Per-agent credential rotation, revoke and last-seen state.
- HTTPS-only production transport, payload size/rate limits, schema validation and replay-resistant observation timestamps.
- Agent never transmits passwords, private keys, application secrets or environment values.
- Linux first; Windows service follows the same protocol.

### Server health

- CPU, memory, swap, disk, inode, load, uptime, network, services and containers.
- Warning/critical threshold, continuous duration, recovery threshold and maintenance window.
- Raw time series, hourly/daily rollups and configurable retention.

### Patch compliance

- OS/kernel, installed package count, pending updates, security updates, reboot required and scan time.
- Daily snapshots and approved patch SLA policies.
- Exception justification and remediation evidence.

### Availability and certificates

- Supabase, HTTP/S, TCP, Ping, DNS, SSL and Docker monitoring.
- Response graph, uptime, downtime, incident creation and certificate expiry policy.

### Backup and restore

- Backup job, system, schedule, retention, location class, last success and freshness.
- Push heartbeat/API/SQL adapters; no backup credentials stored in evidence.
- Restore tests track date, performer, result, RTO/RPO measurement, notes, attachment hashes and next due date.

### Vulnerability management

- Trivy JSON import/agent collection.
- CVE, package, installed/fixed version, severity and affected asset.
- Lifecycle: detected, assigned, fixing, resolved, verified, accepted risk.
- SLA clock, exception expiry and remediation evidence.

### Access review

- Privileged identities and permissions captured by agent/integration or import.
- Review campaign, reviewer, decision, reason, next review and evidence.
- Pending, reviewed, approved and revoked workflow.

### Change management

- Change ID, asset/system, description, requester, approver, commit/PR, deployment, result and rollback.
- Manual record first; GitHub/GitLab/CI adapters later.

### Incident and corrective action

- Severity, detector, timestamps, downtime, owner, status, RCA, corrective action and lessons learned.
- Detected, investigating, resolved, RCA pending, closed.
- MTTA/MTTR and recurrence reporting.

### Compliance policy engine

- Templates for Standard Server, Database, Public Web Service and Backup System.
- Rules evaluate PASS/WARNING/FAIL/NO EVIDENCE over a period.
- Rules cover availability, agent freshness, resource thresholds, patch SLA, backup freshness, restore-test age, SSL, vulnerabilities and access review.
- Each result records policy version, source evidence IDs, evaluation time and explanation.

### Audit mode and evidence

- Audit workspace defines period, scope, framework, controls, auditor access and redaction level.
- Control dashboard shows status, evidence coverage, exceptions and corrective actions.
- Evidence package: executive summary, assets, health, availability, patches, backups, restore tests, vulnerabilities, access, changes, incidents, control matrix, raw CSV/JSON, manifest and hashes.
- Audit chain is append-only and tamper-evident. Export includes policy versions and retention declaration.

## Data retention

- Raw metrics: configurable, default 90 days.
- Hourly rollups: default 400 days.
- Daily compliance and inventory snapshots: default 7 years or organizational policy.
- Audit events and export manifests: never deleted by ordinary UI.
- Destruction requires a records-management workflow, reason, approver and audit event.

## Delivery phases

### Phase 1 — automated server evidence

Agent enrollment, Linux agent, inventory snapshots, health metrics, patch snapshots, agent freshness, Action Required and base compliance policies.

### Phase 2 — operational evidence

Backup heartbeat, restore tests, incident/RCA workflow, evidence attachments and audit-period filters.

### Phase 3 — security evidence

Trivy lifecycle, access reviews, exception/risk acceptance and change records.

### Phase 4 — audit workspace

RBAC, auditor accounts, scoped workspaces, PDF/XLSX reports, scheduled packages, signing and external archive/WORM integration.

## Acceptance criteria

- A new Linux server can enroll without central SSH access.
- Within five minutes it appears with inventory, health and patch evidence.
- A failed policy produces one actionable item with owner, reason and evidence link.
- An auditor can select a period and trace every reported result to immutable source records.
- Shared/auditor APIs contain no credentials or unredacted infrastructure targets.
- Export hashes validate and audit-chain verification passes.

