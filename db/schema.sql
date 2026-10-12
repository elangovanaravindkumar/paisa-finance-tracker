CREATE TABLE IF NOT EXISTS paisa_users (
  id uuid PRIMARY KEY,
  username varchar(30) NOT NULL UNIQUE,
  password_hash varchar(255) NOT NULL,
  failed_login_attempts integer NOT NULL DEFAULT 0,
  locked_until bigint NOT NULL DEFAULT 0,
  created_at bigint NOT NULL,
  CONSTRAINT paisa_username_format CHECK (username ~ '^[a-z0-9_]{3,30}$')
);

-- statement-breakpoint
CREATE TABLE IF NOT EXISTS paisa_sessions (
  token_hash char(64) PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES paisa_users(id) ON DELETE CASCADE,
  expires_at bigint NOT NULL,
  created_at bigint NOT NULL
);

-- statement-breakpoint
CREATE INDEX IF NOT EXISTS paisa_sessions_user_idx
  ON paisa_sessions (user_id, expires_at);

-- statement-breakpoint
CREATE TABLE IF NOT EXISTS paisa_accounts (
  user_id uuid NOT NULL REFERENCES paisa_users(id) ON DELETE CASCADE,
  id varchar(100) NOT NULL,
  name varchar(60) NOT NULL,
  type varchar(30) NOT NULL CHECK (type IN ('Bank account', 'Cash', 'Credit card', 'Wallet')),
  opening bigint NOT NULL DEFAULT 0,
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (user_id, id)
);

-- statement-breakpoint
CREATE TABLE IF NOT EXISTS paisa_categories (
  user_id uuid NOT NULL REFERENCES paisa_users(id) ON DELETE CASCADE,
  id varchar(100) NOT NULL,
  name varchar(40) NOT NULL,
  created_at bigint NOT NULL,
  PRIMARY KEY (user_id, id)
);

-- statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS paisa_categories_user_name_unique
  ON paisa_categories (user_id, lower(name));

-- statement-breakpoint
CREATE TABLE IF NOT EXISTS paisa_transactions (
  user_id uuid NOT NULL REFERENCES paisa_users(id) ON DELETE CASCADE,
  id varchar(100) NOT NULL,
  type varchar(10) NOT NULL CHECK (type IN ('income', 'expense')),
  amount bigint NOT NULL CHECK (amount > 0),
  date date NOT NULL,
  category varchar(40) NOT NULL,
  account_id varchar(100) NOT NULL,
  payment_type varchar(20) NOT NULL DEFAULT 'UPI/Cash'
    CHECK (payment_type IN ('Bank/Cheque', 'Credit Card', 'Debit Card', 'UPI/Cash')),
  description varchar(500) NOT NULL DEFAULT '',
  import_source varchar(255),
  import_fingerprint char(64),
  version integer NOT NULL DEFAULT 1,
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (user_id, id),
  FOREIGN KEY (user_id, account_id)
    REFERENCES paisa_accounts(user_id, id) ON DELETE CASCADE
);

-- statement-breakpoint
CREATE INDEX IF NOT EXISTS paisa_transactions_user_date_idx
  ON paisa_transactions (user_id, date DESC);

-- statement-breakpoint
CREATE INDEX IF NOT EXISTS paisa_transactions_user_account_date_idx
  ON paisa_transactions (user_id, account_id, date DESC);

-- statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS paisa_transactions_user_import_unique
  ON paisa_transactions (user_id, import_fingerprint)
  WHERE import_fingerprint IS NOT NULL;

-- statement-breakpoint
CREATE TABLE IF NOT EXISTS paisa_vault (
  user_id uuid NOT NULL REFERENCES paisa_users(id) ON DELETE CASCADE,
  entity_type varchar(20) NOT NULL
    CHECK (entity_type IN ('account', 'category', 'transaction', 'budget', 'recurring', 'goal', 'loan')),
  id varchar(100) NOT NULL,
  account_id varchar(100),
  fingerprint char(64),
  encrypted_payload text NOT NULL,
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (user_id, entity_type, id)
);

-- statement-breakpoint
CREATE INDEX IF NOT EXISTS paisa_vault_user_entity_idx
  ON paisa_vault (user_id, entity_type, created_at);

-- statement-breakpoint
CREATE INDEX IF NOT EXISTS paisa_vault_user_account_idx
  ON paisa_vault (user_id, account_id)
  WHERE entity_type = 'transaction';

-- statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS paisa_vault_user_transaction_fingerprint_unique
  ON paisa_vault (user_id, fingerprint)
  WHERE entity_type = 'transaction' AND fingerprint IS NOT NULL;

-- statement-breakpoint
ALTER TABLE paisa_vault
  DROP CONSTRAINT IF EXISTS paisa_vault_entity_type_check;

-- statement-breakpoint
ALTER TABLE paisa_vault
  ADD CONSTRAINT paisa_vault_entity_type_check
  CHECK (entity_type IN ('account', 'category', 'transaction', 'budget', 'recurring', 'goal', 'loan'));

-- statement-breakpoint
CREATE OR REPLACE FUNCTION paisa_delete_expired_sessions()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE deleted_count integer;
BEGIN
  DELETE FROM paisa_sessions
   WHERE expires_at <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$;

-- statement-breakpoint
ALTER TABLE paisa_users
  ADD COLUMN IF NOT EXISTS email varchar(254),
  ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS totp_secret text,
  ADD COLUMN IF NOT EXISTS totp_pending_secret text,
  ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS backup_code_hashes jsonb NOT NULL DEFAULT '[]'::jsonb;

-- statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS paisa_users_email_unique
  ON paisa_users (lower(email)) WHERE email IS NOT NULL;

-- statement-breakpoint
CREATE TABLE IF NOT EXISTS paisa_auth_challenges (
  token_hash char(64) PRIMARY KEY,
  purpose varchar(30) NOT NULL
    CHECK (purpose IN ('register_email', 'login_email', 'login_totp', 'add_email', 'password_reset')),
  user_id uuid REFERENCES paisa_users(id) ON DELETE CASCADE,
  email varchar(254),
  encrypted_payload text,
  code_hash char(64),
  attempts integer NOT NULL DEFAULT 0,
  expires_at bigint NOT NULL,
  created_at bigint NOT NULL
);

-- statement-breakpoint
CREATE INDEX IF NOT EXISTS paisa_auth_challenges_expiry_idx
  ON paisa_auth_challenges (expires_at);

-- statement-breakpoint
ALTER TABLE paisa_auth_challenges
  DROP CONSTRAINT IF EXISTS paisa_auth_challenges_purpose_check;

-- statement-breakpoint
ALTER TABLE paisa_auth_challenges
  ADD CONSTRAINT paisa_auth_challenges_purpose_check
  CHECK (purpose IN ('register_email', 'login_email', 'login_totp', 'add_email', 'password_reset'));
