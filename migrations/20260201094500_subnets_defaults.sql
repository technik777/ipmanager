update subnets
set gateway = coalesce(gateway, host(cidr::inet)),
    dns_primary = coalesce(dns_primary, host(cidr::inet))
where gateway is null or dns_primary is null;
