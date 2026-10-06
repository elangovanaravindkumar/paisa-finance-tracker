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
