ALTER TABLE machine_keys ADD COLUMN key_prefix VARCHAR(8);
CREATE INDEX idx_machine_keys_prefix ON machine_keys(key_prefix);
