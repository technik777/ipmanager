alter table hosts
  add column if not exists pxe_image_id bigint null references pxe_images(id) on delete set null;

create index if not exists hosts_pxe_image_id_idx on hosts (pxe_image_id);
