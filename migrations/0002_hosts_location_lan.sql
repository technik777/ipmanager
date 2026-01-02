alter table hosts
  add column location text null,
  add column lan_dose text null;

create index if not exists hosts_location_idx on hosts (location);
create index if not exists hosts_lan_dose_idx on hosts (lan_dose);
