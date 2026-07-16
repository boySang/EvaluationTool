CREATE TABLE IF NOT EXISTS projects (
    id TEXT NOT NULL PRIMARY KEY,
    customer_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    evidence_root TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT NOT NULL PRIMARY KEY,
    project_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    credential_reference TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    UNIQUE (project_id, id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS executions (
    id TEXT NOT NULL PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    connection_protocol INTEGER NOT NULL,
    command_pack_version TEXT NOT NULL,
    command_id TEXT NOT NULL,
    command_text TEXT NOT NULL,
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT NULL,
    status INTEGER NOT NULL,
    exit_code INTEGER NULL,
    raw_output_path TEXT NULL,
    raw_output_sha256 TEXT NULL,
    error_text TEXT NULL,
    UNIQUE (project_id, id),
    UNIQUE (project_id, device_id, id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, device_id) REFERENCES devices(project_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id TEXT NOT NULL PRIMARY KEY,
    execution_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    evidence_kind INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    created_at_utc TEXT NOT NULL,
    UNIQUE (execution_id, relative_path),
    UNIQUE (execution_id, ordinal),
    FOREIGN KEY (project_id, device_id, execution_id)
        REFERENCES executions(project_id, device_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS ix_devices_project_id ON devices(project_id);
CREATE INDEX IF NOT EXISTS ix_executions_project_id ON executions(project_id);
CREATE INDEX IF NOT EXISTS ix_evidence_files_project_id ON evidence_files(project_id);
