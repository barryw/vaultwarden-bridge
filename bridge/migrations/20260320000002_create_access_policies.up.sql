CREATE TYPE target_type AS ENUM ('item', 'collection', 'glob');

CREATE TABLE access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_key_id UUID NOT NULL REFERENCES machine_keys(id) ON DELETE CASCADE,
    target_type target_type NOT NULL,
    target_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_access_policies_key_id ON access_policies(machine_key_id);
