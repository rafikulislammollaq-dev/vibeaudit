# Vibe-coded CRM (DEMO FIXTURE)

This folder is **not** a real application. It is a small, deliberately
insecure sample project that ships with `vibeaudit` so the tool can be
demonstrated without touching anybody's code.

```bash
node audit/cli.js --demo
```

It contains the mistakes that AI code generators actually make:

| What | Where |
|---|---|
| A committed `.env` with a live Supabase **service_role** key | `.env` |
| A table of customer data with **no Row Level Security** | `supabase/migrations/0001_init.sql` |
| A **SECURITY DEFINER** function with no safe `search_path` | `supabase/migrations/0001_init.sql` |
| A policy that allows **every row to everyone** (`USING (true)`) | `supabase/migrations/0002_orders.sql` |
| A direct **GRANT** to the anonymous role | `supabase/migrations/0002_orders.sql` |
| **CORS** with a wildcard origin plus credentials | `src/server.js` |
| The **whole project folder served publicly** (`/.env` is downloadable) | `src/server.js` |
| A **/api/debug** route that dumps the environment | `src/routes/debug.js` |
| An **admin endpoint** with no role check | `src/routes/admin.js` |
| **alg: "none"** accepted in token verification | `src/lib/jwt.js` |
| **`jwt.decode()`** used instead of `jwt.verify()` | `src/lib/jwt.js` |
| A signing secret that **falls back to a hard-coded value** | `src/lib/jwt.js` |
| The **service_role key in the client bundle** | `dist/assets/index-a1b2c3.js` |
| **Source maps** published in the build | `dist/assets/index-a1b2c3.js.map` |

None of these keys are real. They are syntactically valid but point at
nothing.
