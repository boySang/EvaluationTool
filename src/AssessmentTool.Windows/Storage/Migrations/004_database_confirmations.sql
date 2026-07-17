CREATE TABLE database_confirmations (
    id TEXT NOT NULL PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NULL,
    installation_type INTEGER NOT NULL CHECK (installation_type IN (0, 1)),
    instance_name TEXT NOT NULL,
    port_evidence TEXT NULL,
    detection_evidence TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    confirmed_at_utc TEXT NOT NULL,
    confirmation_source TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT
);

CREATE INDEX ix_database_confirmations_project_time
    ON database_confirmations(project_id, confirmed_at_utc, id);

CREATE INDEX ix_database_confirmations_device_time
    ON database_confirmations(device_id, confirmed_at_utc, id);
