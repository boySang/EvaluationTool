CREATE TABLE published_command_packs (
    pack_id TEXT NOT NULL CHECK (length(trim(pack_id)) > 0),
    pack_name TEXT NOT NULL CHECK (length(trim(pack_name)) > 0),
    pack_version TEXT NOT NULL CHECK (length(trim(pack_version)) > 0),
    official_source TEXT NOT NULL CHECK (length(trim(official_source)) > 0),
    raw_sha256 TEXT NOT NULL CHECK (
        length(raw_sha256) = 64
        AND raw_sha256 = lower(raw_sha256)
        AND raw_sha256 NOT GLOB '*[^0-9a-f]*'),
    raw_json TEXT NOT NULL CHECK (length(trim(raw_json)) > 0),
    source_draft_id TEXT NOT NULL,
    source_draft_sha256 TEXT NOT NULL CHECK (
        length(source_draft_sha256) = 64
        AND source_draft_sha256 = lower(source_draft_sha256)
        AND source_draft_sha256 NOT GLOB '*[^0-9a-f]*'),
    reviewed_by TEXT NOT NULL CHECK (length(trim(reviewed_by)) > 0),
    reviewed_at_utc TEXT NOT NULL,
    published_at_utc TEXT NOT NULL,
    PRIMARY KEY (pack_id, pack_version),
    FOREIGN KEY (source_draft_id) REFERENCES command_drafts(id) ON DELETE RESTRICT
);

CREATE TABLE project_command_pack_locks (
    id TEXT NOT NULL PRIMARY KEY,
    project_id TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    pack_version TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    previous_lock_id TEXT NULL,
    lock_source TEXT NOT NULL CHECK (length(trim(lock_source)) > 0),
    locked_at_utc TEXT NOT NULL,
    UNIQUE (project_id, pack_id, revision),
    UNIQUE (id, project_id, pack_id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT,
    FOREIGN KEY (pack_id, pack_version)
        REFERENCES published_command_packs(pack_id, pack_version) ON DELETE RESTRICT,
    FOREIGN KEY (previous_lock_id, project_id, pack_id)
        REFERENCES project_command_pack_locks(id, project_id, pack_id) ON DELETE RESTRICT
);

CREATE INDEX ix_published_command_packs_published
    ON published_command_packs(published_at_utc DESC, pack_id, pack_version);

CREATE INDEX ix_project_command_pack_locks_latest
    ON project_command_pack_locks(project_id, pack_id, revision DESC);

CREATE TRIGGER project_command_pack_locks_validate_append
BEFORE INSERT ON project_command_pack_locks
BEGIN
    SELECT CASE
        WHEN NEW.revision != COALESCE(
            (SELECT MAX(revision) + 1
             FROM project_command_pack_locks
             WHERE project_id = NEW.project_id AND pack_id = NEW.pack_id),
            1)
        THEN RAISE(ABORT, 'project command pack lock revision must append to latest')
    END;
    SELECT CASE
        WHEN NEW.revision = 1 AND NEW.previous_lock_id IS NOT NULL
        THEN RAISE(ABORT, 'first project command pack lock cannot have a predecessor')
        WHEN NEW.revision > 1 AND NEW.previous_lock_id IS NOT (
            SELECT id
            FROM project_command_pack_locks
            WHERE project_id = NEW.project_id AND pack_id = NEW.pack_id
            ORDER BY revision DESC
            LIMIT 1)
        THEN RAISE(ABORT, 'project command pack lock must reference the latest predecessor')
    END;
END;

CREATE TRIGGER published_command_packs_no_update
BEFORE UPDATE ON published_command_packs
BEGIN
    SELECT RAISE(ABORT, 'published command packs are immutable');
END;

CREATE TRIGGER published_command_packs_no_delete
BEFORE DELETE ON published_command_packs
BEGIN
    SELECT RAISE(ABORT, 'published command packs are immutable');
END;

CREATE TRIGGER project_command_pack_locks_no_update
BEFORE UPDATE ON project_command_pack_locks
BEGIN
    SELECT RAISE(ABORT, 'project command pack locks are append-only');
END;

CREATE TRIGGER project_command_pack_locks_no_delete
BEFORE DELETE ON project_command_pack_locks
BEGIN
    SELECT RAISE(ABORT, 'project command pack locks are append-only');
END;
