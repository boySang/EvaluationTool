CREATE TABLE host_software_discovery_batches (
    batch_id TEXT NOT NULL PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    collection_task_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    previous_batch_id TEXT NULL,
    discovery_source TEXT NOT NULL CHECK (length(trim(discovery_source)) > 0),
    candidate_count INTEGER NOT NULL CHECK (candidate_count >= 1 AND candidate_count <= 64),
    recorded_at_utc TEXT NOT NULL,
    UNIQUE(device_id, revision),
    UNIQUE(batch_id, device_id),
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE RESTRICT,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE RESTRICT,
    FOREIGN KEY(collection_task_id) REFERENCES collection_tasks(id) ON DELETE RESTRICT,
    FOREIGN KEY(previous_batch_id, device_id)
        REFERENCES host_software_discovery_batches(batch_id, device_id) ON DELETE RESTRICT
);

CREATE TABLE host_software_discovery_candidates (
    candidate_id TEXT NOT NULL PRIMARY KEY,
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 64),
    category INTEGER NOT NULL CHECK (category IN (1, 2)),
    product TEXT NOT NULL CHECK (length(trim(product)) > 0),
    version TEXT NULL,
    installation_type INTEGER NOT NULL CHECK (installation_type IN (0, 1)),
    instance_name TEXT NOT NULL CHECK (length(trim(instance_name)) > 0),
    port_evidence TEXT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_count INTEGER NOT NULL CHECK (evidence_count >= 1 AND evidence_count <= 64),
    UNIQUE(batch_id, ordinal),
    FOREIGN KEY(batch_id) REFERENCES host_software_discovery_batches(batch_id) ON DELETE RESTRICT
);

CREATE TABLE host_software_discovery_evidence (
    evidence_id TEXT NOT NULL PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 64),
    collection_task_id TEXT NOT NULL,
    command_ordinal INTEGER NOT NULL CHECK (command_ordinal >= 0),
    evidence_kind INTEGER NOT NULL CHECK (evidence_kind IN (1, 2, 3, 4, 5, 6)),
    source_command_id TEXT NOT NULL CHECK (length(trim(source_command_id)) > 0),
    evidence_excerpt TEXT NOT NULL CHECK (length(trim(evidence_excerpt)) > 0),
    raw_output_sha256 TEXT NOT NULL CHECK (
        length(raw_output_sha256) = 64
        AND raw_output_sha256 = lower(raw_output_sha256)
        AND raw_output_sha256 NOT GLOB '*[^0-9a-f]*'),
    UNIQUE(candidate_id, ordinal),
    FOREIGN KEY(candidate_id) REFERENCES host_software_discovery_candidates(candidate_id) ON DELETE RESTRICT,
    FOREIGN KEY(collection_task_id, command_ordinal)
        REFERENCES collection_task_commands(task_id, ordinal) ON DELETE RESTRICT
);

CREATE TABLE host_software_candidate_decisions (
    decision_id TEXT NOT NULL PRIMARY KEY,
    candidate_id TEXT NOT NULL UNIQUE,
    decision INTEGER NOT NULL CHECK (decision IN (1, 2)),
    decided_by TEXT NOT NULL CHECK (length(trim(decided_by)) > 0),
    decision_source TEXT NOT NULL CHECK (length(trim(decision_source)) > 0),
    reason TEXT NULL CHECK (
        reason IS NULL OR length(trim(reason)) > 0),
    decided_at_utc TEXT NOT NULL,
    CHECK (decision != 2 OR reason IS NOT NULL),
    FOREIGN KEY(candidate_id) REFERENCES host_software_discovery_candidates(candidate_id) ON DELETE RESTRICT
);

CREATE INDEX ix_host_software_discovery_batches_latest
    ON host_software_discovery_batches(device_id, revision DESC);

CREATE INDEX ix_host_software_discovery_candidates_batch
    ON host_software_discovery_candidates(batch_id, ordinal);

CREATE INDEX ix_host_software_candidate_decisions_time
    ON host_software_candidate_decisions(decided_at_utc, decision_id);

CREATE TRIGGER host_software_discovery_batches_validate_append
BEFORE INSERT ON host_software_discovery_batches
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM devices d
            WHERE d.id = NEW.device_id AND d.project_id = NEW.project_id)
        THEN RAISE(ABORT, 'host software discovery device does not belong to project')
    END;
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM collection_tasks t
            WHERE t.id = NEW.collection_task_id
              AND t.device_id = NEW.device_id
              AND t.project_id = NEW.project_id
              AND t.created_at_utc <= NEW.recorded_at_utc)
        THEN RAISE(ABORT, 'host software discovery task does not belong to project and device')
    END;
    SELECT CASE
        WHEN NEW.revision != COALESCE(
            (SELECT MAX(revision) + 1
             FROM host_software_discovery_batches
             WHERE device_id = NEW.device_id),
            1)
        THEN RAISE(ABORT, 'host software discovery revision must append to latest')
    END;
    SELECT CASE
        WHEN NEW.revision = 1 AND NEW.previous_batch_id IS NOT NULL
        THEN RAISE(ABORT, 'first host software discovery batch cannot have a predecessor')
        WHEN NEW.revision > 1 AND NEW.previous_batch_id IS NOT (
            SELECT batch_id
            FROM host_software_discovery_batches
            WHERE device_id = NEW.device_id
            ORDER BY revision DESC
            LIMIT 1)
        THEN RAISE(ABORT, 'host software discovery batch must reference latest predecessor')
    END;
END;

CREATE TRIGGER host_software_discovery_evidence_validate_task
BEFORE INSERT ON host_software_discovery_evidence
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM host_software_discovery_candidates c
            INNER JOIN host_software_discovery_batches b ON b.batch_id = c.batch_id
            INNER JOIN collection_task_commands tc
                ON tc.task_id = NEW.collection_task_id
               AND tc.ordinal = NEW.command_ordinal
               AND tc.command_id = NEW.source_command_id
            INNER JOIN collection_task_events te
                ON te.task_id = tc.task_id
               AND te.command_ordinal = tc.ordinal
               AND te.event_code = 'CommandEvidenceCommitted'
               AND te.occurred_at_utc <= b.recorded_at_utc
            WHERE c.candidate_id = NEW.candidate_id
              AND b.collection_task_id = NEW.collection_task_id)
        THEN RAISE(ABORT, 'host software evidence must reference committed task command evidence')
    END;
END;

CREATE TRIGGER host_software_candidate_decisions_validate_time
BEFORE INSERT ON host_software_candidate_decisions
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM host_software_discovery_candidates c
            INNER JOIN host_software_discovery_batches b ON b.batch_id = c.batch_id
            WHERE c.candidate_id = NEW.candidate_id
              AND NEW.decided_at_utc >= b.recorded_at_utc)
        THEN RAISE(ABORT, 'host software decision cannot precede discovery')
    END;
END;

CREATE TRIGGER host_software_discovery_batches_no_update
BEFORE UPDATE ON host_software_discovery_batches
BEGIN
    SELECT RAISE(ABORT, 'host software discovery batches are append-only');
END;

CREATE TRIGGER host_software_discovery_batches_no_delete
BEFORE DELETE ON host_software_discovery_batches
BEGIN
    SELECT RAISE(ABORT, 'host software discovery batches are append-only');
END;

CREATE TRIGGER host_software_discovery_candidates_no_update
BEFORE UPDATE ON host_software_discovery_candidates
BEGIN
    SELECT RAISE(ABORT, 'host software discovery candidates are append-only');
END;

CREATE TRIGGER host_software_discovery_candidates_no_delete
BEFORE DELETE ON host_software_discovery_candidates
BEGIN
    SELECT RAISE(ABORT, 'host software discovery candidates are append-only');
END;

CREATE TRIGGER host_software_discovery_evidence_no_update
BEFORE UPDATE ON host_software_discovery_evidence
BEGIN
    SELECT RAISE(ABORT, 'host software discovery evidence is append-only');
END;

CREATE TRIGGER host_software_discovery_evidence_no_delete
BEFORE DELETE ON host_software_discovery_evidence
BEGIN
    SELECT RAISE(ABORT, 'host software discovery evidence is append-only');
END;

CREATE TRIGGER host_software_candidate_decisions_no_update
BEFORE UPDATE ON host_software_candidate_decisions
BEGIN
    SELECT RAISE(ABORT, 'host software candidate decisions are append-only');
END;

CREATE TRIGGER host_software_candidate_decisions_no_delete
BEFORE DELETE ON host_software_candidate_decisions
BEGIN
    SELECT RAISE(ABORT, 'host software candidate decisions are append-only');
END;
