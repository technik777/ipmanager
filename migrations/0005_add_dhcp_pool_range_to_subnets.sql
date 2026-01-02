-- Add optional DHCP pool range per subnet
alter table subnets
  add column if not exists dhcp_pool_start inet,
  add column if not exists dhcp_pool_end inet;

-- Basic sanity: if one is set, both must be set
alter table subnets
  add constraint subnets_dhcp_pool_both_or_none
  check (
    (dhcp_pool_start is null and dhcp_pool_end is null)
    or (dhcp_pool_start is not null and dhcp_pool_end is not null)
  );
