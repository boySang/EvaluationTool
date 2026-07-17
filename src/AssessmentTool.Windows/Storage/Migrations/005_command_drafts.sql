CREATE TABLE command_drafts (
    id TEXT NOT NULL PRIMARY KEY,
    source_file_name TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    imported_at_utc TEXT NOT NULL,
    review_status INTEGER NOT NULL DEFAULT 0 CHECK (review_status = 0),
    is_executable INTEGER NOT NULL DEFAULT 0 CHECK (is_executable = 0)
);

CREATE TABLE command_draft_items (
    draft_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    command_id TEXT NULL,
    title TEXT NULL,
    command_text TEXT NULL,
    target_category TEXT NULL,
    declared_risk_level TEXT NULL,
    is_executable INTEGER NOT NULL DEFAULT 0 CHECK (is_executable = 0),
    PRIMARY KEY (draft_id, ordinal),
    FOREIGN KEY (draft_id) REFERENCES command_drafts(id) ON DELETE RESTRICT
);

CREATE TABLE command_draft_findings (
    draft_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    severity INTEGER NOT NULL CHECK (severity IN (0, 1, 2)),
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    command_index INTEGER NULL CHECK (command_index IS NULL OR command_index >= 0),
    PRIMARY KEY (draft_id, ordinal),
    FOREIGN KEY (draft_id) REFERENCES command_drafts(id) ON DELETE RESTRICT
);

CREATE INDEX ix_command_drafts_imported_at
    ON command_drafts(imported_at_utc);
