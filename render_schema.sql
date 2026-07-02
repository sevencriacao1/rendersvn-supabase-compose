create extension if not exists pgcrypto;

create schema if not exists app_private;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type public.user_role as enum ('admin', 'funcionario');
  end if;
end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  nome text,
  role public.user_role not null default 'funcionario',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.empreendimentos (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  nome text not null,
  descricao text,
  cidade text,
  bairro text,
  glb_path text,
  thumbnail_path text,
  publicado boolean not null default false,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists empreendimentos_slug_idx
  on public.empreendimentos (slug);

create index if not exists empreendimentos_publicado_idx
  on public.empreendimentos (publicado);

create or replace function app_private.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
before update on public.profiles
for each row execute function app_private.set_updated_at();

drop trigger if exists empreendimentos_set_updated_at on public.empreendimentos;
create trigger empreendimentos_set_updated_at
before update on public.empreendimentos
for each row execute function app_private.set_updated_at();

create or replace function app_private.current_user_role()
returns public.user_role
language sql
security definer
set search_path = public
stable
as $$
  select role
  from public.profiles
  where id = (select auth.uid())
  limit 1
$$;

create or replace function app_private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, nome)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'name', new.raw_user_meta_data ->> 'full_name')
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function app_private.handle_new_user();

alter table public.profiles enable row level security;
alter table public.empreendimentos enable row level security;

drop policy if exists "profiles_select_own_or_admin" on public.profiles;
create policy "profiles_select_own_or_admin"
on public.profiles
for select
to authenticated
using (
  id = (select auth.uid())
  or app_private.current_user_role() = 'admin'
);

drop policy if exists "profiles_update_own_or_admin" on public.profiles;
create policy "profiles_update_own_or_admin"
on public.profiles
for update
to authenticated
using (
  id = (select auth.uid())
  or app_private.current_user_role() = 'admin'
)
with check (
  id = (select auth.uid())
  or app_private.current_user_role() = 'admin'
);

drop policy if exists "empreendimentos_staff_select" on public.empreendimentos;
create policy "empreendimentos_staff_select"
on public.empreendimentos
for select
to authenticated
using (app_private.current_user_role() in ('admin', 'funcionario'));

drop policy if exists "empreendimentos_staff_insert" on public.empreendimentos;
create policy "empreendimentos_staff_insert"
on public.empreendimentos
for insert
to authenticated
with check (app_private.current_user_role() in ('admin', 'funcionario'));

drop policy if exists "empreendimentos_staff_update" on public.empreendimentos;
create policy "empreendimentos_staff_update"
on public.empreendimentos
for update
to authenticated
using (app_private.current_user_role() in ('admin', 'funcionario'))
with check (app_private.current_user_role() in ('admin', 'funcionario'));

drop policy if exists "empreendimentos_admin_delete" on public.empreendimentos;
create policy "empreendimentos_admin_delete"
on public.empreendimentos
for delete
to authenticated
using (app_private.current_user_role() = 'admin');

insert into storage.buckets (id, name, public)
values ('empreendimentos', 'empreendimentos', true)
on conflict (id) do update set public = excluded.public;

drop policy if exists "staff_upload_empreendimento_assets" on storage.objects;
create policy "staff_upload_empreendimento_assets"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'empreendimentos'
  and app_private.current_user_role() in ('admin', 'funcionario')
);

drop policy if exists "staff_update_empreendimento_assets" on storage.objects;
create policy "staff_update_empreendimento_assets"
on storage.objects
for update
to authenticated
using (
  bucket_id = 'empreendimentos'
  and app_private.current_user_role() in ('admin', 'funcionario')
)
with check (
  bucket_id = 'empreendimentos'
  and app_private.current_user_role() in ('admin', 'funcionario')
);

drop policy if exists "staff_delete_empreendimento_assets" on storage.objects;
create policy "staff_delete_empreendimento_assets"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'empreendimentos'
  and app_private.current_user_role() in ('admin', 'funcionario')
);

revoke all on schema app_private from public;
grant usage on schema app_private to authenticated;
revoke all on all functions in schema app_private from public;
grant execute on function app_private.current_user_role() to authenticated;

grant usage on schema public to anon, authenticated, service_role;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.empreendimentos to authenticated;
grant all on public.profiles to service_role;
grant all on public.empreendimentos to service_role;
grant usage on all sequences in schema public to authenticated, service_role;
