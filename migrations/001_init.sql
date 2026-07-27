CREATE TABLE IF NOT EXISTS panel_users (
    id            SERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS charger_registrations (
    id                 SERIAL PRIMARY KEY,
    email              TEXT NOT NULL,
    serial_number      TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    cve_charge_box_pk  INTEGER,
    license_code       TEXT,
    error_message      TEXT,
    form_data          JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_charger_registrations_email  ON charger_registrations (email);
CREATE INDEX IF NOT EXISTS idx_charger_registrations_serial ON charger_registrations (serial_number);
CREATE INDEX IF NOT EXISTS idx_charger_registrations_status ON charger_registrations (status);
