create table if not exists macmon_exports (
  mac_address text primary key,
  exported_at timestamptz not null default now()
);
