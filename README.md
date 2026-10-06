# Paisa — public multi-user edition

Paisa is a responsive personal-finance tracker designed for Vercel and a PostgreSQL-compatible serverless database such as Neon. Registration is public and every user receives a private workspace.

## Security model

- Users register and log in with a unique username and password.
- Passwords are hashed with Node's `scrypt` using a random per-password salt. Plain-text passwords are never stored or logged.
- Sessions use 256-bit random tokens. Only a SHA-256 hash of each token is stored in PostgreSQL; the browser receives the token in a `Secure`, `HttpOnly`, `SameSite=Lax`, host-only cookie.
- Failed logins are locked for 15 minutes after five consecutive failures.
- State-changing requests require a same-origin request, protecting the cookie from cross-site request forgery.
- Every finance query obtains `user_id` from the validated server-side session. The API never accepts a user ID from the browser.
- All finance tables use `(user_id, id)` composite keys. Transaction-to-account references include `user_id`, so the database rejects a transaction linked to another user's account.
- Account deletion cascades only through matching `(user_id, account_id)` records.
- Duplicate-import constraints are scoped per user.

## Free-tier deployment

You need:

1. A free PostgreSQL database. Neon Free is suitable for an initial deployment.
2. A Vercel Hobby account.

### 1. Create the database

Create a PostgreSQL database and copy its pooled connection string. It should look like:

```text
postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=require
```

Do not place this value in the client or commit it to source control.

### 2. Deploy on Vercel

Import this directory as a Vercel project. Add the following environment variable for Production, Preview, and Development:

```text
DATABASE_URL=your-private-postgresql-connection-string
```

The Vercel build runs `scripts/migrate.mjs`, which applies `db/schema.sql`. Deploy the project after saving the environment variable.

CLI equivalent:

```bash
npm install
vercel
vercel env add DATABASE_URL
vercel --prod
```

Never paste the database URL into chat, the browser console, or a client-side file. Enter it directly into the hosting provider's encrypted environment-variable UI or CLI prompt.

### 3. Verify the live application

1. Create two test users with different usernames.
2. Create an account and transaction as User A.
3. Log out and sign in as User B; User A's data must not appear.
4. As User B, send an update/delete request using User A's record ID. The response must be `404` or `{ "deleted": false }`.
5. Log back in as User A and confirm the record is unchanged.

## Local development

```bash
cp .env.example .env.local
# Add a development DATABASE_URL to .env.local
npm install
npm run db:migrate
vercel dev
```

Production cookies require HTTPS. Local development uses a non-`Secure` cookie only when Vercel/production environment indicators are absent.

## Data migration

The v2 schema uses new `paisa_*` tables, so an older single-workspace database is left untouched. To migrate existing Paisa data:

1. Download a complete backup from the older app.
2. Register the intended owner in this edition.
3. Open **Settings → Restore from backup**.

The restore applies only to the signed-in user.

## Main files

- `api/auth.mjs` — registration, login, logout, lockout and session endpoints
- `lib/auth.mjs` — password hashing, session-cookie and authentication helpers
- `api/finance.mjs` — authenticated, user-scoped finance API
- `db/schema.sql` — users, hashed sessions and user-owned finance tables
- `public/index.html` — existing Paisa UI plus registration/login/logout
- `tests/` — validation, authentication and isolation regression tests
