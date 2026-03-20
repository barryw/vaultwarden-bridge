CREATE TYPE audit_action AS ENUM (
    'secret_retrieved',
    'secret_not_found',
    'access_denied',
    'ip_denied'
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_key_id UUID REFERENCES machine_keys(id) ON DELETE SET NULL,
    action audit_action NOT NULL,
    target_requested TEXT NOT NULL,
    target_resolved TEXT,
    source_ip TEXT NOT NULL,
    client_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_key_id ON audit_log(machine_key_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
