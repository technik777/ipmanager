create table if not exists rooms (
  id uuid primary key default gen_random_uuid(),
  location_id uuid not null references locations(id) on delete restrict,
  name text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(location_id, name)
);
create index if not exists rooms_location_idx on rooms (location_id);
create trigger rooms_set_updated_at
before update on rooms
for each row execute function set_updated_at();
