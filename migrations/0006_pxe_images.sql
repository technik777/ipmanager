create table if not exists pxe_images (
  id bigserial primary key,
  name text not null unique,
  kind text not null check (kind in ('linux','chain')),
  arch text not null check (arch in ('any','bios','uefi')),
  kernel_path text null,
  initrd_path text null,
  chain_url text null,
  cmdline text null,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint pxe_images_kernel_required check (
    (kind = 'linux' and kernel_path is not null)
    or (kind = 'chain')
  ),
  constraint pxe_images_chain_required check (
    (kind = 'chain' and chain_url is not null)
    or (kind = 'linux')
  )
);
create trigger pxe_images_set_updated_at
before update on pxe_images
for each row execute function set_updated_at();
