import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { neon } from "@neondatabase/serverless";
import { encryptJson, keyFingerprint } from "../lib/crypto.mjs";
import { transactionFingerprint } from "../lib/model.mjs";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required to apply the Paisa schema.");
  process.exit(1);
}
if (!process.env.DATA_ENCRYPTION_KEY) {
  console.error(
    "DATA_ENCRYPTION_KEY is required to encrypt Paisa financial records.",
  );
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
const source = await readFile(resolve(here, "../db/schema.sql"), "utf8");
const statements = source
  .split("-- statement-breakpoint")
  .map((part) => part.trim())
  .filter(Boolean);
const sql = neon(process.env.DATABASE_URL);
for (const statement of statements) await sql.query(statement);

const [legacyAccounts, legacyCategories, legacyTransactions] =
  await Promise.all([
    sql.query("SELECT * FROM paisa_accounts ORDER BY created_at"),
    sql.query("SELECT * FROM paisa_categories ORDER BY created_at"),
    sql.query("SELECT * FROM paisa_transactions ORDER BY created_at"),
  ]);

const dateValue = (value) =>
  value instanceof Date
    ? value.toISOString().slice(0, 10)
    : String(value).slice(0, 10);
const context = (userId, entity, id) => `${userId}:${entity}:${id}`;
const records = [
  ...legacyAccounts.map((row) => ({
    userId: row.user_id,
    entity: "account",
    record: {
      id: row.id,
      name: row.name,
      type: row.type,
      opening: Number(row.opening),
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    },
  })),
  ...legacyCategories.map((row) => ({
    userId: row.user_id,
    entity: "category",
    record: {
      id: row.id,
      name: row.name,
      createdAt: Number(row.created_at),
    },
  })),
  ...legacyTransactions.map((row) => {
    const record = {
      id: row.id,
      type: row.type,
      amount: Number(row.amount),
      date: dateValue(row.date),
      category: row.category,
      accountId: row.account_id,
      paymentType: row.payment_type,
      description: row.description || "",
      importSource: row.import_source || null,
      importFingerprint: null,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    };
    if (row.import_fingerprint) {
      record.importFingerprint = transactionFingerprint(record);
    }
    return { userId: row.user_id, entity: "transaction", record };
  }),
];

if (records.length) {
  const inserts = records.map(({ userId, entity, record }) =>
    sql.query(
      `INSERT INTO paisa_vault
        (user_id, entity_type, id, account_id, fingerprint, encrypted_payload,
         created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT DO NOTHING`,
      [
        userId,
        entity,
        record.id,
        entity === "transaction" ? record.accountId : null,
        entity === "transaction" ? record.importFingerprint : null,
        encryptJson(record, context(userId, entity, record.id)),
        record.createdAt,
        record.updatedAt ?? record.createdAt,
      ],
    ),
  );
  await sql.transaction([
    ...inserts,
    sql.query("DELETE FROM paisa_transactions"),
    sql.query("DELETE FROM paisa_categories"),
    sql.query("DELETE FROM paisa_accounts"),
  ]);
}
console.log(
  `Paisa database schema is ready (${statements.length} statements; encryption key ${keyFingerprint()}; ${records.length} legacy records secured).`,
);
