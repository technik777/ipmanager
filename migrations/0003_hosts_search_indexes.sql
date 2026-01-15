-- Trigram-Indizes für performante ILIKE-Suche bei ~2000+ Datensätzen
-- pg_trgm ist bereits in 0001 aktiviert.

create index if not exists hosts_location_trgm_idx
on hosts using gin (location gin_trgm_ops);

create index if not exists hosts_lan_dose_trgm_idx
on hosts using gin (lan_dose gin_trgm_ops);

create index if not exists hosts_mac_address_trgm_idx
on hosts using gin (mac_address gin_trgm_ops);
