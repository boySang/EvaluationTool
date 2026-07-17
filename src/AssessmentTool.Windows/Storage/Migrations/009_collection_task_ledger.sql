CREATE TABLE collection_tasks (
    id TEXT NOT NULL PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    identification_revision INTEGER NOT NULL CHECK (identification_revision >= 1),
    connection_protocol INTEGER NOT NULL CHECK (connection_protocol = 0),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    user_name TEXT NOT NULL,
    authentication_method INTEGER NOT NULL CHECK (authentication_method IN (0, 1)),
    host_key_algorithm TEXT NOT NULL,
    host_key_fingerprint TEXT NOT NULL,
    command_count INTEGER NOT NULL CHECK (command_count >= 1),
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY(project_id, device_id) REFERENCES devices(project_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(device_id, identification_revision)
        REFERENCES device_identifications(device_id, revision) ON DELETE RESTRICT
);

CREATE TABLE collection_task_commands (
    task_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    command_pack_id TEXT NOT NULL,
    command_pack_version TEXT NOT NULL,
    command_pack_sha256 TEXT NOT NULL CHECK (length(command_pack_sha256) = 64),
    command_id TEXT NOT NULL,
    command_text TEXT NOT NULL,
    check_item TEXT NOT NULL,
    result_description TEXT NOT NULL,
    risk_level INTEGER NOT NULL CHECK (risk_level IN (0, 1, 2)),
    is_optional INTEGER NOT NULL CHECK (is_optional IN (0, 1)),
    safety_validated_at_utc TEXT NOT NULL,
    PRIMARY KEY(task_id, ordinal),
    UNIQUE(task_id, command_id),
    FOREIGN KEY(task_id) REFERENCES collection_tasks(id) ON DELETE RESTRICT
);

CREATE TABLE collection_task_events (
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3, 4, 5, 6, 7)),
    command_ordinal INTEGER NULL CHECK (command_ordinal IS NULL OR command_ordinal >= 0),
    event_code TEXT NOT NULL,
    occurred_at_utc TEXT NOT NULL,
    PRIMARY KEY(task_id, revision),
    FOREIGN KEY(task_id) REFERENCES collection_tasks(id) ON DELETE RESTRICT,
    FOREIGN KEY(task_id, command_ordinal)
        REFERENCES collection_task_commands(task_id, ordinal) ON DELETE RESTRICT
);

CREATE INDEX ix_collection_tasks_project_created
    ON collection_tasks(project_id, created_at_utc DESC);

CREATE INDEX ix_collection_task_events_latest
    ON collection_task_events(task_id, revision DESC);

CREATE TRIGGER collection_tasks_no_update
BEFORE UPDATE ON collection_tasks
BEGIN
    SELECT RAISE(ABORT, 'collection tasks are immutable');
END;

CREATE TRIGGER collection_tasks_no_delete
BEFORE DELETE ON collection_tasks
BEGIN
    SELECT RAISE(ABORT, 'collection tasks are immutable');
END;

CREATE TRIGGER collection_task_commands_no_update
BEFORE UPDATE ON collection_task_commands
BEGIN
    SELECT RAISE(ABORT, 'collection task commands are immutable');
END;

CREATE TRIGGER collection_task_commands_no_delete
BEFORE DELETE ON collection_task_commands
BEGIN
    SELECT RAISE(ABORT, 'collection task commands are immutable');
END;

CREATE TRIGGER collection_task_events_no_update
BEFORE UPDATE ON collection_task_events
BEGIN
    SELECT RAISE(ABORT, 'collection task events are append-only');
END;

CREATE TRIGGER collection_task_events_no_delete
BEFORE DELETE ON collection_task_events
BEGIN
    SELECT RAISE(ABORT, 'collection task events are append-only');
END;
