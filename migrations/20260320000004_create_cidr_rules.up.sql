CREATE TYPE cidr_scope AS ENUM ('ui', 'api');

CREATE TABLE cidr_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope cidr_scope NOT NULL,
    cidr TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
