CREATE TABLE ssh_host_key_trust (
    device_id TEXT NOT NULL PRIMARY KEY,
    state INTEGER NOT NULL CHECK (state IN (0, 2, 3, 4, 5)),
    algorithm TEXT NULL,
    fingerprint TEXT NULL,
    observed_algorithm TEXT NULL,
    observed_fingerprint TEXT NULL,
    observed_at_utc TEXT NULL,
    confirmed_at_utc TEXT NULL,
    confirmation_source TEXT NULL,
    previous_algorithm TEXT NULL,
    previous_fingerprint TEXT NULL,
    previous_confirmed_at_utc TEXT NULL,
    previous_confirmation_source TEXT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT
);
