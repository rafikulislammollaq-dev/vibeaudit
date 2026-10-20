-- ---------------------------------------------------------------------------
-- 0001_init.sql - first migration.
--
-- DEMO FIXTURE: deliberately insecure. The profiles table holds names, emails
-- and phone numbers of real customers, and it has no Row Level Security.
-- ---------------------------------------------------------------------------

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  email text,
  phone text,
  role text default 'user',
  company text,
  created_at timestamptz default now()
);

create table public.companies (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid references public.profiles (id),
  plan text default 'free',
  created_at timestamptz default now()
);

-- The admin key bypasses every policy, so a SECURITY DEFINER function is
-- especially dangerous when the search path is not pinned: a caller can
-- hijack the search path and run code as the table owner.
create or replace function public.get_company_stats(company_id uuid)
returns jsonb
language plpgsql
security definer
as $$
declare
  result jsonb;
begin
  select jsonb_build_object(
    'employees', (select count(*) from public.profiles where role = 'employee'),
    'plan', (select plan from public.companies where id = company_id)
  ) into result;
  return result;
end;
$$;
