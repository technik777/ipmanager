-- Locations (einfache Normalisierung)
create table if not exists locations (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create trigger locations_set_updated_at
before update on locations
for each row execute function set_updated_at();

-- LAN Outlets (LAN-Dosen) an einem Standort
create table if not exists lan_outlets (
  id uuid primary key default gen_random_uuid(),
  location_id uuid not null references locations(id) on delete restrict,
  label text not null,
  description text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(location_id, label)
);
create index if not exists lan_outlets_location_idx on lan_outlets(location_id);
create trigger lan_outlets_set_updated_at
before update on lan_outlets
for each row execute function set_updated_at();

-- Hosts: neue FK-Spalten
alter table hosts
  add column if not exists location_id uuid null references locations(id) on delete restrict,
  add column if not exists lan_outlet_id uuid null references lan_outlets(id) on delete restrict;

-- Daten migrieren (best-effort): aus bisherigen Textfeldern
-- 1) locations aus hosts.location
insert into locations (name)
select distinct location
from hosts
where location is not null and btrim(location) <> ''
on conflict (name) do nothing;

-- 2) location_id auf hosts setzen
update hosts h
set location_id = l.id
from locations l
where h.location is not null
  and btrim(h.location) <> ''
  and l.name = h.location;

-- 3) lan_outlets aus hosts.lan_dose + location_id
insert into lan_outlets (location_id, label)
select distinct h.location_id, h.lan_dose
from hosts h
where h.location_id is not null
  and h.lan_dose is not null
  and btrim(h.lan_dose) <> ''
on conflict (location_id, label) do nothing;

-- 4) lan_outlet_id auf hosts setzen
update hosts h
set lan_outlet_id = o.id
from lan_outlets o
where h.location_id = o.location_id
  and h.lan_dose = o.label;

-- Optional: Textfelder behalten (noch), damit nichts bricht. Entfernen wir später.
