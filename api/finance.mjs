import { neon } from "@neondatabase/serverless";
import {
  accountRow,
  categoryRow,
  transactionFingerprint,
  transactionRow,
  validateAccount,
  validateCategory,
  validateTransaction,
} from "../lib/model.mjs";
import {
  bodyOf,
  clearSessionCookie,
  currentUser,
  reply,
  requireSameOrigin,
} from "../lib/auth.mjs";

const MAX_IMPORT_ROWS = 2_000;

function entity(value) {
  if (!["account", "category", "transaction"].includes(value)) {
    const error = new Error("Unknown data type.");
    error.status = 400;
    throw error;
  }
  return value;
}

function accountJson(rows) {
  return JSON.stringify(
    rows.map((record) => ({
      id: record.id,
      name: record.name,
      type: record.type,
      opening: record.opening,
      created_at: record.createdAt,
      updated_at: record.updatedAt,
    })),
  );
}

function categoryJson(rows) {
  return JSON.stringify(
    rows.map((record) => ({
      id: record.id,
      name: record.name,
      created_at: record.createdAt,
    })),
  );
}

function transactionJson(rows) {
  return JSON.stringify(
    rows.map((record) => ({
      id: record.id,
      type: record.type,
      amount: record.amount,
      date: record.date,
      category: record.category,
      account_id: record.accountId,
      payment_type: record.paymentType,
      description: record.description,
      import_source: record.importSource,
      import_fingerprint: record.importFingerprint,
      created_at: record.createdAt,
      updated_at: record.updatedAt,
    })),
  );
}

const insertAccounts = (sql, userId, records) =>
  sql.query(
    `INSERT INTO paisa_accounts
      (user_id, id, name, type, opening, created_at, updated_at)
     SELECT $1::uuid, id, name, type, opening, created_at, updated_at
       FROM jsonb_to_recordset($2::jsonb)
         AS x(id text, name text, type text, opening bigint,
              created_at bigint, updated_at bigint)
     RETURNING id`,
    [userId, accountJson(records)],
  );

const insertCategories = (sql, userId, records, ignoreDuplicates = false) =>
  sql.query(
    `INSERT INTO paisa_categories (user_id, id, name, created_at)
     SELECT $1::uuid, id, name, created_at
       FROM jsonb_to_recordset($2::jsonb)
         AS x(id text, name text, created_at bigint)
     ${ignoreDuplicates ? "ON CONFLICT DO NOTHING" : ""}
     RETURNING id`,
    [userId, categoryJson(records)],
  );

const insertTransactions = (
  sql,
  userId,
  records,
  { ignoreDuplicates = false } = {},
) =>
  sql.query(
    `INSERT INTO paisa_transactions
      (user_id, id, type, amount, date, category, account_id, payment_type,
       description, import_source, import_fingerprint, created_at, updated_at)
     SELECT $1::uuid, id, type, amount, date, category, account_id, payment_type,
            description, import_source, import_fingerprint, created_at, updated_at
       FROM jsonb_to_recordset($2::jsonb)
         AS x(id text, type text, amount bigint, date date, category text,
              account_id text, payment_type text, description text,
              import_source text, import_fingerprint text,
              created_at bigint, updated_at bigint)
     ${ignoreDuplicates ? "ON CONFLICT DO NOTHING" : ""}
     RETURNING id`,
    [userId, transactionJson(records)],
  );

async function snapshot(sql, user) {
  const [accountRows, categoryRows, transactionRows] = await Promise.all([
    sql.query(
      `SELECT a.*,
              a.opening + COALESCE(SUM(
                CASE WHEN t.type='income' THEN t.amount ELSE -t.amount END
              ), 0) AS balance
         FROM paisa_accounts a
         LEFT JOIN paisa_transactions t
           ON t.user_id=a.user_id AND t.account_id=a.id
        WHERE a.user_id=$1
        GROUP BY a.user_id, a.id
        ORDER BY a.created_at, a.name`,
      [user.id],
    ),
    sql.query(
      `SELECT * FROM paisa_categories
        WHERE user_id=$1 ORDER BY lower(name), created_at`,
      [user.id],
    ),
    sql.query(
      `SELECT * FROM paisa_transactions
        WHERE user_id=$1 ORDER BY date DESC, created_at DESC`,
      [user.id],
    ),
  ]);
  return {
    user,
    accounts: accountRows.map(accountRow),
    categories: categoryRows.map(categoryRow),
    transactions: transactionRows.map(transactionRow),
  };
}

async function create(sql, userId, requestedEntity, body) {
  if (requestedEntity === "account") {
    const record = validateAccount(body.record ?? body);
    await insertAccounts(sql, userId, [record]);
    return record;
  }
  if (requestedEntity === "category") {
    const record = validateCategory(body.record ?? body);
    await insertCategories(sql, userId, [record]);
    return record;
  }
  const record = validateTransaction(body.record ?? body);
  await insertTransactions(sql, userId, [record]);
  return record;
}

async function update(sql, userId, requestedEntity, body) {
  if (requestedEntity === "account") {
    const record = validateAccount(body.record ?? body);
    const rows = await sql.query(
      `UPDATE paisa_accounts
          SET name=$3, type=$4, opening=$5, updated_at=$6
        WHERE user_id=$1 AND id=$2
        RETURNING id`,
      [
        userId,
        record.id,
        record.name,
        record.type,
        record.opening,
        record.updatedAt,
      ],
    );
    if (!rows.length) notFound("Account");
    return record;
  }
  if (requestedEntity === "category") {
    const record = validateCategory(body.record ?? body);
    const oldName = String(body.oldName || "").trim();
    if (!oldName) {
      const error = new Error("Original category name is required.");
      error.status = 400;
      throw error;
    }
    const results = await sql.transaction([
      sql.query(
        `UPDATE paisa_categories SET name=$3
          WHERE user_id=$1 AND id=$2 RETURNING id`,
        [userId, record.id, record.name],
      ),
      sql.query(
        `UPDATE paisa_transactions
            SET category=$3, updated_at=$4
          WHERE user_id=$1 AND category=$2`,
        [userId, oldName, record.name, Date.now()],
      ),
    ]);
    if (!results[0].length) notFound("Category");
    return record;
  }
  const record = validateTransaction(body.record ?? body);
  const rows = await sql.query(
    `UPDATE paisa_transactions
        SET type=$3, amount=$4, date=$5, category=$6, account_id=$7,
            payment_type=$8, description=$9, updated_at=$10, version=version+1
      WHERE user_id=$1 AND id=$2
      RETURNING id`,
    [
      userId,
      record.id,
      record.type,
      record.amount,
      record.date,
      record.category,
      record.accountId,
      record.paymentType,
      record.description,
      record.updatedAt,
    ],
  );
  if (!rows.length) notFound("Transaction");
  return record;
}

function notFound(label) {
  const error = new Error(`${label} not found.`);
  error.status = 404;
  throw error;
}

async function remove(sql, userId, requestedEntity, req) {
  if (req.query?.clear === "1") {
    const table = {
      account: "paisa_accounts",
      category: "paisa_categories",
      transaction: "paisa_transactions",
    }[requestedEntity];
    await sql.query(`DELETE FROM ${table} WHERE user_id=$1`, [userId]);
    return { cleared: true };
  }
  const id = String(req.query?.id || "");
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) {
    const error = new Error("A valid ID is required.");
    error.status = 400;
    throw error;
  }
  if (requestedEntity === "category") {
    const rows = await sql.query(
      "SELECT name FROM paisa_categories WHERE user_id=$1 AND id=$2",
      [userId, id],
    );
    if (rows.length) {
      const used = await sql.query(
        `SELECT 1 FROM paisa_transactions
          WHERE user_id=$1 AND category=$2 LIMIT 1`,
        [userId, rows[0].name],
      );
      if (used.length) {
        const error = new Error(
          "This category is used by transactions and cannot be deleted.",
        );
        error.status = 409;
        throw error;
      }
    }
  }
  const table = {
    account: "paisa_accounts",
    category: "paisa_categories",
    transaction: "paisa_transactions",
  }[requestedEntity];
  const rows = await sql.query(
    `DELETE FROM ${table} WHERE user_id=$1 AND id=$2 RETURNING id`,
    [userId, id],
  );
  return { deleted: rows.length > 0 };
}

async function validateAccountOwnership(sql, userId, records) {
  const requested = new Set(records.map((record) => record.accountId));
  if (!requested.size) return;
  const rows = await sql.query(
    "SELECT id FROM paisa_accounts WHERE user_id=$1 AND id=ANY($2::text[])",
    [userId, [...requested]],
  );
  if (rows.length !== requested.size) {
    const error = new Error(
      "One or more transactions refers to an account you cannot access.",
    );
    error.status = 400;
    throw error;
  }
}

async function importBatch(sql, userId, body) {
  if (!Array.isArray(body.records) || body.records.length > MAX_IMPORT_ROWS) {
    const error = new Error(
      `Import must contain 0 to ${MAX_IMPORT_ROWS.toLocaleString("en-IN")} rows.`,
    );
    error.status = 400;
    throw error;
  }
  const records = body.records.map((row) =>
    validateTransaction(row, { imported: true }),
  );
  const categories = (
    Array.isArray(body.categories) ? body.categories : []
  ).map(validateCategory);
  await validateAccountOwnership(sql, userId, records);
  const existingRows = await sql.query(
    "SELECT * FROM paisa_transactions WHERE user_id=$1",
    [userId],
  );
  const known = new Set(
    existingRows.map((row) => transactionFingerprint(transactionRow(row))),
  );
  const uniqueRecords = [];
  for (const record of records) {
    if (known.has(record.importFingerprint)) continue;
    known.add(record.importFingerprint);
    uniqueRecords.push(record);
  }
  const queries = [];
  if (categories.length) {
    queries.push(insertCategories(sql, userId, categories, true));
  }
  queries.push(
    insertTransactions(sql, userId, uniqueRecords, {
      ignoreDuplicates: true,
    }),
  );
  const results = await sql.transaction(queries);
  const inserted = results.at(-1)?.length || 0;
  return { imported: inserted, duplicates: records.length - inserted };
}

async function replaceAll(sql, userId, body) {
  const data = body.data || {};
  if (
    ![data.accounts, data.categories, data.transactions].every(Array.isArray)
  ) {
    const error = new Error(
      "Backup is missing accounts, categories, or transactions.",
    );
    error.status = 400;
    throw error;
  }
  if (data.transactions.length > MAX_IMPORT_ROWS) {
    const error = new Error("Backup contains too many transactions.");
    error.status = 400;
    throw error;
  }
  const accounts = data.accounts.map(validateAccount);
  const categories = data.categories.map(validateCategory);
  const transactions = data.transactions.map((row) => validateTransaction(row));
  const accountIds = new Set(accounts.map((account) => account.id));
  if (transactions.some((record) => !accountIds.has(record.accountId))) {
    const error = new Error(
      "The backup contains a transaction with an invalid account.",
    );
    error.status = 400;
    throw error;
  }
  await sql.transaction([
    sql.query("DELETE FROM paisa_transactions WHERE user_id=$1", [userId]),
    sql.query("DELETE FROM paisa_categories WHERE user_id=$1", [userId]),
    sql.query("DELETE FROM paisa_accounts WHERE user_id=$1", [userId]),
    insertAccounts(sql, userId, accounts),
    insertCategories(sql, userId, categories),
    insertTransactions(sql, userId, transactions),
  ]);
  return { restored: true };
}

export default async function handler(req, res) {
  try {
    if (!process.env.DATABASE_URL) {
      return reply(res, 503, {
        error: "Server setup is incomplete. Add DATABASE_URL in Vercel.",
      });
    }
    const sql = neon(process.env.DATABASE_URL);
    const user = await currentUser(sql, req);
    if (req.method === "GET") {
      return reply(res, 200, await snapshot(sql, user));
    }
    requireSameOrigin(req);
    const body = bodyOf(req);
    if (req.method === "POST" && body.action === "import") {
      return reply(res, 200, await importBatch(sql, user.id, body));
    }
    if (req.method === "POST" && body.action === "replace_all") {
      return reply(res, 200, await replaceAll(sql, user.id, body));
    }
    const requestedEntity = entity(
      String(req.query?.entity || body.entity || ""),
    );
    if (req.method === "POST") {
      return reply(res, 201, await create(sql, user.id, requestedEntity, body));
    }
    if (req.method === "PUT") {
      return reply(res, 200, await update(sql, user.id, requestedEntity, body));
    }
    if (req.method === "DELETE") {
      return reply(res, 200, await remove(sql, user.id, requestedEntity, req));
    }
    res.setHeader("Allow", "GET, POST, PUT, DELETE");
    return reply(res, 405, { error: "Method not allowed." });
  } catch (error) {
    const status =
      Number(error.status) ||
      (error.code === "23505" ? 409 : error.code === "23503" ? 400 : 500);
    const message =
      status === 500
        ? "The database request failed. Please try again."
        : error.message;
    console.error(error);
    return reply(
      res,
      status,
      { error: message },
      status === 401 ? { "Set-Cookie": clearSessionCookie() } : {},
    );
  }
}

export {
  MAX_IMPORT_ROWS,
  create,
  importBatch,
  remove,
  replaceAll,
  snapshot,
  update,
  validateAccountOwnership,
};
