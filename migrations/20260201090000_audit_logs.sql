create table if not exists audit_logs (
  id bigserial primary key,
  timestamp timestamptz not null default now(),
  user_id uuid null references users(id) on delete set null,
  action text not null,
  details jsonb null
);

create index if not exists audit_logs_timestamp_idx on audit_logs (timestamp desc);
create index if not exists audit_logs_action_idx on audit_logs (action);
