alter table hosts
  add column if not exists os_type text;

alter table hosts
  add column if not exists pxe_enabled boolean not null default false;
