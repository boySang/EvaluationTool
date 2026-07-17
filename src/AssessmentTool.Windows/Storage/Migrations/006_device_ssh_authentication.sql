ALTER TABLE devices
    ADD COLUMN ssh_authentication_method INTEGER NOT NULL DEFAULT 0
    CHECK (ssh_authentication_method IN (0, 1));

ALTER TABLE devices
    ADD COLUMN private_key_reference TEXT NULL
    CHECK (
        (ssh_authentication_method = 0 AND private_key_reference IS NULL)
        OR
        (ssh_authentication_method = 1 AND private_key_reference IS NOT NULL)
    );
