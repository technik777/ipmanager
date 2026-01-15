create extension if not exists pgcrypto;

create table if not exists subnets (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  cidr inet not null,
  gateway inet null,
  dns_primary inet null
);

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  role text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists hosts (
  id uuid primary key default gen_random_uuid(),
  hostname text not null unique,
  ip_address text not null unique,
  mac_address text not null unique,
  subnet_id uuid not null references subnets(id) on delete restrict,
  sync_status text not null default 'pending',
  pxe_enabled boolean not null default false
);
