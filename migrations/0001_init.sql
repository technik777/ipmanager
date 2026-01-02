create extension if not exists pgcrypto;
create extension if not exists citext;
create extension if not exists pg_trgm;

create or replace function set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create table users (
  id uuid primary key default gen_random_uuid(),
  username citext not null unique,
  password_hash text not null,
  role text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create trigger users_set_updated_at
before update on users
for each row execute function set_updated_at();

create table sessions (
  id text primary key,
  data jsonb not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index sessions_expires_at_idx on sessions (expires_at);
create trigger sessions_set_updated_at
before update on sessions
for each row execute function set_updated_at();

create table subnets (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  cidr text not null,
  gateway inet null,
  dns_zone text null,
  reverse_zone text null,
  dhcp_enabled boolean not null default true,
  pxe_enabled boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create trigger subnets_set_updated_at
before update on subnets
for each row execute function set_updated_at();

create table hosts (
  id uuid primary key default gen_random_uuid(),
  hostname text not null unique,
  ip inet not null unique,
  mac text not null unique,
  subnet_id uuid not null references subnets(id) on delete restrict,
  pxe_enabled boolean not null default false,
  description text null,
  owner_email text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index hosts_subnet_id_idx on hosts (subnet_id);
create index hosts_ip_idx on hosts (ip);
create index hosts_mac_idx on hosts (mac);
create index hosts_hostname_trgm_idx on hosts using gin (hostname gin_trgm_ops);
create trigger hosts_set_updated_at
before update on hosts
for each row execute function set_updated_at();

create table dhcp_config_versions (
  id uuid primary key default gen_random_uuid(),
  generated_by_user_id uuid null references users(id),
  content text not null,
  checksum text not null,
  created_at timestamptz not null default now()
);

create table dns_jobs (
  id uuid primary key default gen_random_uuid(),
  host_id uuid not null references hosts(id) on delete cascade,
  operation text not null,
  status text not null,
  retry_count int not null default 0,
  next_retry_at timestamptz null,
  last_error text null,
  last_error_at timestamptz null,
  sync_started_at timestamptz null,
  sync_finished_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index dns_jobs_poll_idx on dns_jobs (status, next_retry_at);
create index dns_jobs_host_id_idx on dns_jobs (host_id);
create trigger dns_jobs_set_updated_at
before update on dns_jobs
for each row execute function set_updated_at();
create unique index dns_jobs_one_pending_per_host
on dns_jobs (host_id)
where status = 'pending';

create table nac_jobs (
  id uuid primary key default gen_random_uuid(),
  host_id uuid not null references hosts(id) on delete cascade,
  operation text not null,
  status text not null,
  external_ref text null,
  payload jsonb null,
  retry_count int not null default 0,
  next_retry_at timestamptz null,
  last_error text null,
  last_error_at timestamptz null,
  sync_started_at timestamptz null,
  sync_finished_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index nac_jobs_poll_idx on nac_jobs (status, next_retry_at);
create index nac_jobs_host_id_idx on nac_jobs (host_id);
create trigger nac_jobs_set_updated_at
before update on nac_jobs
for each row execute function set_updated_at();
create unique index nac_jobs_one_pending_per_host
on nac_jobs (host_id)
where status = 'pending';

create table email_events (
  id uuid primary key default gen_random_uuid(),
  kind text not null,
  status text not null,
  to_addr text not null,
  subject text not null,
  body text not null,
  retry_count int not null default 0,
  next_retry_at timestamptz null,
  last_error text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index email_events_poll_idx on email_events (status, next_retry_at);
create trigger email_events_set_updated_at
before update on email_events
for each row execute function set_updated_at();

create table audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_user_id uuid null references users(id),
  action text not null,
  entity_type text not null,
  entity_id uuid null,
  summary text not null,
  details jsonb null,
  created_at timestamptz not null default now()
);
create index audit_log_entity_idx on audit_log (entity_type, entity_id);
create index audit_log_created_at_idx on audit_log (created_at);
