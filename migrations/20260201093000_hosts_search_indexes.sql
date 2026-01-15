create index if not exists hosts_ip_address_trgm_idx
  on hosts using gin (ip_address gin_trgm_ops);

create index if not exists hosts_mac_address_trgm_idx
  on hosts using gin (mac_address gin_trgm_ops);
