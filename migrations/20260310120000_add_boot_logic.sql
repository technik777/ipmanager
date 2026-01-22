alter table hosts
  add column if not exists next_boot_action varchar(50) default 'local',
  add column if not exists boot_action_updated_at timestamp default current_timestamp,
  add column if not exists location varchar(100),
  add column if not exists lan_port varchar(50);
