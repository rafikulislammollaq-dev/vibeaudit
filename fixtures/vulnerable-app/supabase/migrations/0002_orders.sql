-- ---------------------------------------------------------------------------
-- 0002_orders.sql - second migration.
--
-- DEMO FIXTURE: deliberately insecure.
-- ---------------------------------------------------------------------------

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id),
  total numeric(10, 2) not null,
  status text default 'pending',
  shipping_address text,
  created_at timestamptz default now()
);

-- RLS is turned on here, but the policy allows every row for every role, so
-- the table is just as exposed as a table with no RLS at all.
alter table public.orders enable row level security;

create policy "anyone can read orders" on public.orders
  for all
  using (true)
  with check (true);

-- The public role is granted direct access to a table that holds addresses
-- and totals, with no row level security protecting it.
grant all on table public.profiles to anon;
