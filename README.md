# Paisa — public multi-user edition

Paisa is a responsive personal-finance tracker designed for Vercel and a PostgreSQL-compatible serverless database such as Neon. Registration is public and every user receives a private workspace.

## Security model

- New users register with a username, password and verified email OTP.
- Existing users can attach a verified email from Settings without losing data.
- Users can enable, re-enroll or disable authenticator-app TOTP and receive eight one-time recovery codes. Setup QR codes are generated locally by the backend; the secret is not sent to a third-party QR service.
- Verified-email OTP supports password recovery. Signed-in users can change their password after confirming the current one; other sessions are revoked.
- Passwords are hashed with Node's `scrypt` using a random per-password salt. Plain-text passwords are never stored or logged.
- Sessions use 256-bit random tokens. Only a SHA-256 hash of each token is stored in PostgreSQL; the browser receives the token in a `Secure`, `HttpOnly`, `SameSite=Lax`, host-only cookie.
- Failed logins are locked for 15 minutes after five consecutive failures.
- State-changing requests require a same-origin request, protecting the cookie from cross-site request forgery.
- Every finance query obtains `user_id` from the validated server-side session. The API never accepts a user ID from the browser.
- Account, category, transaction, budget, recurring-entry, savings-goal and loan contents are encrypted before storage with AES-256-GCM. The authenticated `user_id`, entity type and record ID are bound as additional authenticated data.
- The database stores only encrypted financial payloads, opaque IDs, ownership identifiers and keyed duplicate fingerprints. Dashboard calculations happen after server-side decryption.
- Duplicate-import constraints are scoped per user and use a keyed HMAC fingerprint.

Server-side encryption protects database contents and database backups from being read without the separate Vercel encryption key. It does not protect against a fully compromised running application that can access both the database and the key.

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

Import this directory as a Vercel project. Add these environment variables for Production and Preview:

```text
DATABASE_URL=your-private-postgresql-connection-string
DATA_ENCRYPTION_KEY=a-random-32-byte-base64url-value
BREVO_API_KEY=your-private-brevo-api-key
OTP_FROM_EMAIL=your-verified-brevo-sender-address
OTP_FROM_NAME=Paisa
```

Generate the encryption key locally once:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Save this key in a password manager. Never change or delete it after financial data has been encrypted; losing it makes the encrypted records unrecoverable.

The Vercel build runs `scripts/migrate.mjs`, applies `db/schema.sql`, encrypts any existing plaintext finance records, and then removes those plaintext copies. Deploy only after all environment variables have been saved.

CLI equivalent:

```bash
npm install
vercel
vercel env add DATABASE_URL
vercel env add DATA_ENCRYPTION_KEY
vercel env add BREVO_API_KEY
vercel env add OTP_FROM_EMAIL
vercel --prod
```

Never paste the database URL into chat, the browser console, or a client-side file. Enter it directly into the hosting provider's encrypted environment-variable UI or CLI prompt.

### 3. Verify the live application

1. Create two test users with different usernames and email addresses.
2. Create an account and transaction as User A.
3. Log out and sign in as User B; User A's data must not appear.
4. As User B, send an update/delete request using User A's record ID. The response must be `404` or `{ "deleted": false }`.
5. Log back in as User A and confirm the record is unchanged.

## Local development

```bash
cp .env.example .env.local
# Add development database, encryption and Brevo values to .env.local
npm install
npm run db:migrate
vercel dev
```

Production cookies require HTTPS. Local development uses a non-`Secure` cookie only when Vercel/production environment indicators are absent.

## Data migration

The encrypted schema automatically migrates records from the earlier `paisa_accounts`, `paisa_categories` and `paisa_transactions` tables into `paisa_vault` during deployment. The migration is transactional and removes plaintext finance rows only after encrypted inserts are prepared.

To migrate data from the older offline application:

1. Download a complete backup from the older app.
2. Register the intended owner in this edition.
3. Open **Settings → Restore from backup**.

The restore applies only to the signed-in user.

## Planning features

- Monthly budgets can cover all expense categories or one category.
- Recurring income and expenses are posted when due. Generated transaction IDs are deterministic, preventing the same occurrence from being counted twice.
- Savings goals track a target, saved amount, optional target date and optional linked account.
- Loans track borrowed or lent principal, outstanding balance, interest rate, optional due date and optional linked account.
- Planning records are included in version 2 backups. Version 1 backups remain restorable.

## Main files

- `api/auth.mjs` — registration, email OTP, password recovery/change, TOTP lifecycle, logout, lockout and session endpoints
- `lib/auth.mjs` — password hashing, session-cookie and authentication helpers
- `lib/crypto.mjs` — AES-256-GCM encryption and keyed blind indexes
- `lib/mfa.mjs` — Brevo OTP delivery, TOTP and recovery-code helpers
- `api/finance.mjs` — authenticated encrypted-vault API and recurring-transaction generation
- `db/schema.sql` — users, challenges, hashed sessions and encrypted vault
- `public/index.html` — responsive SPA for authentication, tracking, planning, reports and settings
- `tests/` — validation, authentication and isolation regression tests
