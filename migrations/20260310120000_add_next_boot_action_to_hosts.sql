alter table hosts
  add column if not exists next_boot_action text;
