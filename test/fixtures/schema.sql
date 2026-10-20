-- ---------------------------------------------------------------------------
-- test/fixtures/schema.sql
--
-- A small, self-contained Postgres schema used by the unit tests.
-- It deliberately contains the three mistakes the RLS check looks for:
--   1. a table with no Row Level Security
--   2. a SECURITY DEFINER function with no safe search_path
--   3. a permissive policy (USING (true))
-- ---------------------------------------------------------------------------

create table public.customers (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  full_name text,
  phone text,
  created_at timestamptz default now()
);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.customers (id),
  total numeric(10, 2) not null,
  created_at timestamptz default now()
);

-- This table is protected.
alter table public.invoices enable row level security;

create policy "customers read own invoices" on public.invoices
  for select
  using (auth.uid() = customer_id);

-- SECURITY DEFINER with no `SET search_path` - the classic privilege
-- escalation path in Postgres.
create or replace function public.customer_totals(customer_id uuid)
returns numeric
language plpgsql
security definer
as $$
declare
  total numeric;
begin
  select coalesce(sum(total), 0) into total from public.invoices where customer_id = customer_id;
  return total;
end;
$$;

-- A policy that lets everybody through.
create policy "public can read customers" on public.customers
  for select
  using (true);
