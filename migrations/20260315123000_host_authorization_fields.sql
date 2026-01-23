DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'port_status') THEN
        CREATE TYPE port_status AS ENUM ('BLOCKED', 'OPEN', 'UNKNOWN');
    END IF;
END $$;

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS is_authorized boolean not null default false,
    ADD COLUMN IF NOT EXISTS last_seen timestamptz null,
    ADD COLUMN IF NOT EXISTS port_status port_status not null default 'UNKNOWN';
