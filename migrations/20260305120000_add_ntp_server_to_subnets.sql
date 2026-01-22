alter table subnets
  add column if not exists ntp_server inet null;
