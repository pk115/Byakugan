import { mkdirSync } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { config } from "./config.js";

mkdirSync(config.dataDir, { recursive: true });
export const db = new Database(join(config.dataDir, "supapulse.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    supabase_url TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 21600,
    timeout_seconds INTEGER NOT NULL DEFAULT 15,
    retry_count INTEGER NOT NULL DEFAULT 2,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_status TEXT NOT NULL DEFAULT 'PENDING',
    last_message TEXT,
    last_checked_at TEXT,
    next_check_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    http_status INTEGER,
    response_time_ms INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    error_message TEXT,
    checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_heartbeats_project_checked
    ON heartbeats(project_id, checked_at DESC);

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    encrypted_config TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS project_notifications (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, notification_id)
  );

  CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    message TEXT,
    started_at TEXT NOT NULL,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notification_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);
function ensureColumn(table: string, name: string, definition: string) {
  const columns = db.pragma(`table_info(${table})`) as Array<{ name: string }>;
  if (!columns.some((column) => column.name === name)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
  }
}

ensureColumn("projects", "monitor_type", "TEXT NOT NULL DEFAULT 'SUPABASE'");
ensureColumn("projects", "target", "TEXT");
ensureColumn("projects", "http_method", "TEXT NOT NULL DEFAULT 'GET'");
ensureColumn("projects", "expected_status", "INTEGER");
ensureColumn("projects", "keyword", "TEXT");
ensureColumn("projects", "tcp_host", "TEXT");
ensureColumn("projects", "tcp_port", "INTEGER");
ensureColumn("projects", "maintenance", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("projects", "consecutive_failures", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("projects", "last_notified_at", "TEXT");
ensureColumn("projects", "dns_record_type", "TEXT NOT NULL DEFAULT 'A'");
ensureColumn("projects", "ssl_port", "INTEGER NOT NULL DEFAULT 443");
ensureColumn("projects", "ssl_expiry_days", "INTEGER NOT NULL DEFAULT 14");
ensureColumn("projects", "docker_container", "TEXT");
ensureColumn("projects", "published", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("projects", "asset_tag", "TEXT");
ensureColumn("projects", "asset_owner", "TEXT");
ensureColumn("projects", "environment", "TEXT NOT NULL DEFAULT 'Production'");
ensureColumn("projects", "criticality", "TEXT NOT NULL DEFAULT 'Medium'");
ensureColumn("projects", "warning_threshold", "REAL");
ensureColumn("projects", "critical_threshold", "REAL");
ensureColumn("projects", "threshold_operator", "TEXT NOT NULL DEFAULT '>='");
ensureColumn("projects", "threshold_duration_seconds", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("projects", "database_engine", "TEXT");
ensureColumn("users", "role", "TEXT NOT NULL DEFAULT 'ADMIN'");
ensureColumn("users", "enabled", "INTEGER NOT NULL DEFAULT 1");
ensureColumn("users", "updated_at", "TEXT");
ensureColumn("users", "last_login_at", "TEXT");
ensureColumn("users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("users", "encrypted_mfa_secret", "TEXT");
ensureColumn("users", "locale", "TEXT NOT NULL DEFAULT 'en-US'");
ensureColumn("users", "timezone", "TEXT NOT NULL DEFAULT 'SYSTEM'");
ensureColumn("users", "auth_source", "TEXT NOT NULL DEFAULT 'LOCAL'");
ensureColumn("users", "oidc_provider_id", "INTEGER");
ensureColumn("users", "external_subject", "TEXT");
ensureColumn("incidents", "severity", "TEXT NOT NULL DEFAULT 'MEDIUM'");
ensureColumn("incidents", "owner", "TEXT");
ensureColumn("incidents", "root_cause", "TEXT");
ensureColumn("incidents", "corrective_action", "TEXT");
ensureColumn("incidents", "lessons_learned", "TEXT");
ensureColumn("incidents", "review_status", "TEXT NOT NULL DEFAULT 'PENDING'");
ensureColumn("incidents", "reviewed_by", "INTEGER");
ensureColumn("incidents", "reviewed_at", "TEXT");
db.exec(`CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
db.exec(`CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  used_at TEXT
); CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id,used_at);`);
db.exec(`
  CREATE TABLE IF NOT EXISTS database_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    connections_used INTEGER,
    connections_max INTEGER,
    database_size_bytes INTEGER,
    replication_lag_seconds REAL,
    long_running_queries INTEGER,
    details_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_database_metrics_project_time ON database_metrics(project_id,observed_at DESC);
  CREATE TABLE IF NOT EXISTS oidc_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    preset TEXT NOT NULL DEFAULT 'GENERIC',
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT 'openid email profile',
    username_claim TEXT NOT NULL DEFAULT 'email',
    groups_claim TEXT NOT NULL DEFAULT 'groups',
    allowed_domains_json TEXT NOT NULL DEFAULT '[]',
    role_mapping_json TEXT NOT NULL DEFAULT '{}',
    default_role TEXT NOT NULL DEFAULT 'VIEWER',
    jit_provisioning INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_identity
    ON users(oidc_provider_id,external_subject) WHERE external_subject IS NOT NULL;
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS shared_dashboards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS shared_dashboard_projects (
    dashboard_id INTEGER NOT NULL REFERENCES shared_dashboards(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_name TEXT NOT NULL DEFAULT 'Services',
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dashboard_id, project_id)
  );
`);
ensureColumn("shared_dashboards", "token_hash", "TEXT");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_dashboards_token_hash ON shared_dashboards(token_hash) WHERE token_hash IS NOT NULL");
db.exec(`
  CREATE TABLE IF NOT EXISTS iso_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    framework TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS project_controls (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES iso_controls(id) ON DELETE CASCADE,
    evidence_note TEXT,
    PRIMARY KEY (project_id, control_id)
  );
  CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS evidence_exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    date_from TEXT NOT NULL,
    date_to TEXT NOT NULL,
    sha256 TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    hostname TEXT,
    agent_version TEXT,
    last_seen_at TEXT,
    last_ip TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
  );
  CREATE TABLE IF NOT EXISTS asset_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    os_name TEXT NOT NULL,
    os_version TEXT,
    kernel TEXT,
    architecture TEXT,
    cpu_model TEXT,
    cpu_count INTEGER,
    total_memory_bytes INTEGER,
    installed_package_count INTEGER,
    pending_update_count INTEGER,
    security_update_count INTEGER,
    reboot_required INTEGER NOT NULL DEFAULT 0,
    docker_available INTEGER NOT NULL DEFAULT 0,
    container_count INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS host_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cpu_percent REAL NOT NULL,
    memory_percent REAL NOT NULL,
    swap_percent REAL,
    load_1 REAL,
    load_5 REAL,
    load_15 REAL,
    uptime_seconds INTEGER NOT NULL,
    disks_json TEXT NOT NULL DEFAULT '[]',
    containers_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_host_metrics_agent_time ON host_metrics(agent_id, observed_at DESC);
  CREATE TABLE IF NOT EXISTS compliance_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    owner TEXT,
    due_at TEXT,
    first_detected_at TEXT NOT NULL,
    last_detected_at TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(agent_id, finding_key)
  );
  CREATE TABLE IF NOT EXISTS backup_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name TEXT NOT NULL,
    backup_type TEXT NOT NULL,
    storage_location TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    size_bytes INTEGER,
    checksum TEXT,
    notes TEXT,
    recorded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS restore_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_evidence_id INTEGER REFERENCES backup_evidence(id) ON DELETE SET NULL,
    asset_name TEXT NOT NULL,
    test_scope TEXT NOT NULL,
    result TEXT NOT NULL,
    tested_at TEXT NOT NULL,
    rto_minutes INTEGER,
    actual_minutes INTEGER,
    evidence_note TEXT,
    tested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_backup_evidence_time ON backup_evidence(started_at DESC);
  CREATE INDEX IF NOT EXISTS idx_restore_tests_time ON restore_tests(tested_at DESC);
  CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL DEFAULT 'Trivy',
    target TEXT NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    vulnerability_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    installed_version TEXT,
    fixed_version TEXT,
    severity TEXT NOT NULL,
    title TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    owner TEXT,
    due_at TEXT,
    risk_reason TEXT,
    risk_expires_at TEXT,
    first_detected_at TEXT NOT NULL,
    last_detected_at TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(agent_id,vulnerability_id,package_name,installed_version)
  );
  CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_status ON vulnerability_findings(status,severity);
  CREATE TABLE IF NOT EXISTS threat_intelligence_syncs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL CHECK(status IN ('RUNNING','COMPLETED','PARTIAL','FAILED')),
    cisa_catalog_version TEXT,
    cisa_released_at TEXT,
    cve_count INTEGER NOT NULL DEFAULT 0,
    kev_matches INTEGER NOT NULL DEFAULT 0,
    epss_matches INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_vulnerability_scans_agent_time ON vulnerability_scans(agent_id,observed_at DESC);
  CREATE TABLE IF NOT EXISTS report_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    frequency TEXT NOT NULL,
    formats TEXT NOT NULL DEFAULT 'PDF,XLSX',
    period_days INTEGER NOT NULL DEFAULT 30,
    enabled INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT NOT NULL,
    last_run_at TEXT,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS generated_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id INTEGER REFERENCES report_schedules(id) ON DELETE SET NULL,
    format TEXT NOT NULL,
    date_from TEXT NOT NULL,
    date_to TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'READY',
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_generated_reports_created ON generated_reports(created_at DESC);
  CREATE TABLE IF NOT EXISTS report_delivery_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    encrypted_config TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS report_schedule_channels (
    schedule_id INTEGER NOT NULL REFERENCES report_schedules(id) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES report_delivery_channels(id) ON DELETE CASCADE,
    PRIMARY KEY(schedule_id,channel_id)
  );
  CREATE TABLE IF NOT EXISTS report_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_report_id INTEGER REFERENCES generated_reports(id) ON DELETE SET NULL,
    schedule_id INTEGER REFERENCES report_schedules(id) ON DELETE SET NULL,
    channel_id INTEGER REFERENCES report_delivery_channels(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    destination TEXT,
    object_key TEXT,
    error_code TEXT,
    delivered_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_report_deliveries_created ON report_deliveries(created_at DESC);
  CREATE TABLE IF NOT EXISTS backup_connectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    asset_name TEXT NOT NULL,
    backup_type TEXT NOT NULL DEFAULT 'DATABASE',
    max_age_hours INTEGER NOT NULL DEFAULT 24,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_received_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
  );
  CREATE TABLE IF NOT EXISTS backup_policy_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connector_id INTEGER NOT NULL UNIQUE REFERENCES backup_connectors(id) ON DELETE CASCADE,
    severity TEXT NOT NULL DEFAULT 'HIGH',
    status TEXT NOT NULL DEFAULT 'OPEN',
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    first_detected_at TEXT NOT NULL,
    last_detected_at TEXT NOT NULL,
    resolved_at TEXT
  );
`);
ensureColumn("backup_evidence", "connector_id", "INTEGER REFERENCES backup_connectors(id) ON DELETE SET NULL");
ensureColumn("compliance_findings", "resolution_note", "TEXT");
ensureColumn("compliance_findings", "updated_at", "TEXT");
ensureColumn("report_deliveries", "worm_mode", "TEXT");
ensureColumn("report_deliveries", "retain_until", "TEXT");
ensureColumn("report_deliveries", "legal_hold", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("report_deliveries", "object_version_id", "TEXT");
ensureColumn("report_deliveries", "immutable_verified", "INTEGER NOT NULL DEFAULT 0");
db.exec(`
  CREATE TABLE IF NOT EXISTS vulnerability_scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK(target_type IN ('FILESYSTEM','ROOTFS','IMAGE')),
    target TEXT NOT NULL,
    scanners TEXT NOT NULL DEFAULT 'vuln,misconfig,secret',
    severity TEXT NOT NULL DEFAULT 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
    status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED')),
    progress INTEGER NOT NULL DEFAULT 0,
    requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT,
    heartbeat_at TEXT,
    error_code TEXT,
    error_message TEXT,
    result_summary_json TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_vulnerability_scan_jobs_agent_status ON vulnerability_scan_jobs(agent_id,status,requested_at);
  CREATE INDEX IF NOT EXISTS idx_vulnerability_scan_jobs_requested ON vulnerability_scan_jobs(requested_at DESC);
`);
ensureColumn("vulnerability_scans", "job_id", "INTEGER REFERENCES vulnerability_scan_jobs(id) ON DELETE SET NULL");
ensureColumn("vulnerability_scans", "scanner_version", "TEXT");
ensureColumn("vulnerability_findings", "finding_type", "TEXT NOT NULL DEFAULT 'VULNERABILITY'");
ensureColumn("vulnerability_findings", "resource_path", "TEXT");
ensureColumn("vulnerability_findings", "primary_url", "TEXT");
ensureColumn("vulnerability_findings", "reopened_count", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("vulnerability_findings", "last_scan_job_id", "INTEGER REFERENCES vulnerability_scan_jobs(id) ON DELETE SET NULL");
ensureColumn("vulnerability_findings", "kev", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("vulnerability_findings", "kev_date_added", "TEXT");
ensureColumn("vulnerability_findings", "kev_due_date", "TEXT");
ensureColumn("vulnerability_findings", "kev_ransomware", "TEXT");
ensureColumn("vulnerability_findings", "kev_required_action", "TEXT");
ensureColumn("vulnerability_findings", "epss_score", "REAL");
ensureColumn("vulnerability_findings", "epss_percentile", "REAL");
ensureColumn("vulnerability_findings", "threat_intel_updated_at", "TEXT");
db.exec(`
  CREATE TABLE IF NOT EXISTS vulnerability_scan_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    target_type TEXT NOT NULL CHECK(target_type IN ('FILESYSTEM','ROOTFS','IMAGE')),
    scanners TEXT NOT NULL,
    severity TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 900,
    system_profile INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS vulnerability_scan_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    profile_id INTEGER NOT NULL REFERENCES vulnerability_scan_profiles(id) ON DELETE RESTRICT,
    target TEXT NOT NULL,
    frequency TEXT NOT NULL CHECK(frequency IN ('DAILY','WEEKLY')),
    enabled INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT NOT NULL,
    last_run_at TEXT,
    last_job_id INTEGER REFERENCES vulnerability_scan_jobs(id) ON DELETE SET NULL,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_vulnerability_scan_schedules_due ON vulnerability_scan_schedules(enabled,next_run_at);
`);
ensureColumn("vulnerability_scan_jobs", "profile_id", "INTEGER REFERENCES vulnerability_scan_profiles(id) ON DELETE SET NULL");
ensureColumn("vulnerability_scan_jobs", "schedule_id", "INTEGER REFERENCES vulnerability_scan_schedules(id) ON DELETE SET NULL");
ensureColumn("vulnerability_scan_jobs", "timeout_seconds", "INTEGER NOT NULL DEFAULT 900");
const insertScanProfile=db.prepare("INSERT OR IGNORE INTO vulnerability_scan_profiles(name,description,target_type,scanners,severity,timeout_seconds,system_profile) VALUES(?,?,?,?,?,?,1)");
insertScanProfile.run("Quick vulnerabilities","Fast OS and application package vulnerability scan","FILESYSTEM","vuln","HIGH,CRITICAL",600);
insertScanProfile.run("Full server security","Vulnerabilities, configuration weaknesses, and exposed secrets","ROOTFS","vuln,misconfig,secret","UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",900);
insertScanProfile.run("Container image security","Container vulnerabilities, misconfiguration, and secrets","IMAGE","vuln,misconfig,secret","UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",900);
const defaultControls = [
  ['9.1', 'Monitoring, measurement, analysis and evaluation'],
  ['A.5.24', 'Information security incident management planning and preparation'],
  ['A.5.25', 'Assessment and decision on information security events'],
  ['A.5.26', 'Response to information security incidents'],
  ['A.5.27', 'Learning from information security incidents'],
  ['A.5.28', 'Collection of evidence'],
  ['A.5.30', 'ICT readiness for business continuity'],
  ['A.8.6', 'Capacity management'],
  ['A.8.13', 'Information backup'],
  ['A.8.14', 'Redundancy of information processing facilities'],
  ['A.8.15', 'Logging'],
  ['A.8.16', 'Monitoring activities']
];
const insertControl = db.prepare("INSERT OR IGNORE INTO iso_controls (code, title) VALUES (?, ?)");
for (const control of defaultControls) insertControl.run(...control);
db.exec("UPDATE projects SET target = supabase_url WHERE target IS NULL AND monitor_type = 'SUPABASE'");

export type ProjectRow = {
  id: number;
  name: string;
  supabase_url: string;
  encrypted_key: string;
  interval_seconds: number;
  timeout_seconds: number;
  retry_count: number;
  enabled: number;
  last_status: string;
  last_message: string | null;
  last_checked_at: string | null;
  next_check_at: string | null;
  created_at: string;
  updated_at: string;
  monitor_type: "SUPABASE" | "HTTP" | "TCP" | "PING" | "DNS" | "SSL" | "DOCKER" | "DATABASE";
  target: string | null;
  http_method: string;
  expected_status: number | null;
  keyword: string | null;
  tcp_host: string | null;
  tcp_port: number | null;
  maintenance: number;
  consecutive_failures: number;
  last_notified_at: string | null;
  dns_record_type: string;
  ssl_port: number;
  ssl_expiry_days: number;
  docker_container: string | null;
  published: number;
  asset_tag: string | null;
  asset_owner: string | null;
  environment: string;
  criticality: string;
  warning_threshold: number | null;
  critical_threshold: number | null;
  threshold_operator: string;
  threshold_duration_seconds: number;
  database_engine: "POSTGRESQL"|"MYSQL"|"SQLSERVER"|"MONGODB"|null;
};

export function publicProject(row: ProjectRow) {
  return {
    id: row.id,
    name: row.name,
    supabaseUrl: row.supabase_url,
    intervalSeconds: row.interval_seconds,
    timeoutSeconds: row.timeout_seconds,
    retryCount: row.retry_count,
    enabled: Boolean(row.enabled),
    lastStatus: row.maintenance ? "MAINTENANCE" : row.enabled ? row.last_status : "DISABLED",
    lastMessage: row.last_message,
    lastCheckedAt: row.last_checked_at,
    nextCheckAt: row.next_check_at,
    createdAt: row.created_at,
    keyConfigured: true
    ,monitorType: row.monitor_type
    ,target: row.target
    ,httpMethod: row.http_method
    ,expectedStatus: row.expected_status
    ,keyword: row.keyword
    ,tcpHost: row.tcp_host
    ,tcpPort: row.tcp_port
    ,maintenance: Boolean(row.maintenance)
    ,dnsRecordType: row.dns_record_type
    ,sslPort: row.ssl_port
    ,sslExpiryDays: row.ssl_expiry_days
    ,dockerContainer: row.docker_container
    ,published: Boolean(row.published)
    ,assetTag: row.asset_tag
    ,assetOwner: row.asset_owner
    ,environment: row.environment
    ,criticality: row.criticality
    ,warningThreshold: row.warning_threshold
    ,criticalThreshold: row.critical_threshold
    ,thresholdOperator: row.threshold_operator
    ,thresholdDurationSeconds: row.threshold_duration_seconds
    ,databaseEngine: row.database_engine
    ,connectionConfigured: row.monitor_type === "DATABASE"
  };
}
