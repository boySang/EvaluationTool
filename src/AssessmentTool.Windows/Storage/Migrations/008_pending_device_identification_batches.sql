CREATE TABLE pending_device_identification_batches (
    batch_id TEXT NOT NULL PRIMARY KEY,
    device_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    candidate_count INTEGER NOT NULL CHECK (candidate_count >= 1 AND candidate_count <= 32),
    recorded_at_utc TEXT NOT NULL,
    UNIQUE(device_id, revision),
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE RESTRICT
);

CREATE TABLE pending_device_identification_candidates (
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 32),
    target_category INTEGER NOT NULL CHECK (target_category IN (1, 2, 3, 4, 5)),
    vendor TEXT NULL,
    product_family TEXT NULL,
    model TEXT NULL,
    version TEXT NULL,
    detection_evidence TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    PRIMARY KEY(batch_id, ordinal),
    FOREIGN KEY(batch_id) REFERENCES pending_device_identification_batches(batch_id) ON DELETE RESTRICT
);

CREATE TABLE pending_device_identification_resolutions (
    batch_id TEXT NOT NULL PRIMARY KEY,
    resolution INTEGER NOT NULL CHECK (resolution IN (1, 2, 3)),
    resolved_at_utc TEXT NOT NULL,
    FOREIGN KEY(batch_id) REFERENCES pending_device_identification_batches(batch_id) ON DELETE RESTRICT
);

CREATE INDEX ix_pending_device_identification_batches_latest
    ON pending_device_identification_batches(device_id, revision DESC);

CREATE TRIGGER pending_device_identification_batches_no_update
BEFORE UPDATE ON pending_device_identification_batches
BEGIN
    SELECT RAISE(ABORT, 'pending identification batches are append-only');
END;

CREATE TRIGGER pending_device_identification_batches_no_delete
BEFORE DELETE ON pending_device_identification_batches
BEGIN
    SELECT RAISE(ABORT, 'pending identification batches are append-only');
END;

CREATE TRIGGER pending_device_identification_candidates_no_update
BEFORE UPDATE ON pending_device_identification_candidates
BEGIN
    SELECT RAISE(ABORT, 'pending identification candidates are append-only');
END;

CREATE TRIGGER pending_device_identification_candidates_no_delete
BEFORE DELETE ON pending_device_identification_candidates
BEGIN
    SELECT RAISE(ABORT, 'pending identification candidates are append-only');
END;

CREATE TRIGGER pending_device_identification_resolutions_no_update
BEFORE UPDATE ON pending_device_identification_resolutions
BEGIN
    SELECT RAISE(ABORT, 'pending identification resolutions are append-only');
END;

CREATE TRIGGER pending_device_identification_resolutions_no_delete
BEFORE DELETE ON pending_device_identification_resolutions
BEGIN
    SELECT RAISE(ABORT, 'pending identification resolutions are append-only');
END;
