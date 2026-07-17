CREATE TABLE device_identifications (
    device_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    target_category INTEGER NOT NULL CHECK (target_category IN (1, 2, 3, 4, 5)),
    vendor TEXT NULL,
    product_family TEXT NULL,
    model TEXT NULL,
    version TEXT NULL,
    detection_evidence TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    was_user_confirmed INTEGER NOT NULL CHECK (was_user_confirmed IN (0, 1)),
    confirmation_source TEXT NULL,
    recorded_at_utc TEXT NOT NULL,
    PRIMARY KEY(device_id, revision),
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE RESTRICT,
    CHECK (
        (was_user_confirmed = 0 AND confirmation_source IS NULL)
        OR
        (was_user_confirmed = 1 AND confirmation_source IS NOT NULL)
    )
);

CREATE INDEX ix_device_identifications_latest
    ON device_identifications(device_id, revision DESC);

CREATE TRIGGER device_identifications_no_update
BEFORE UPDATE ON device_identifications
BEGIN
    SELECT RAISE(ABORT, 'device identification audit records are append-only');
END;

CREATE TRIGGER device_identifications_no_delete
BEFORE DELETE ON device_identifications
BEGIN
    SELECT RAISE(ABORT, 'device identification audit records are append-only');
END;
