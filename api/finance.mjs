import { neon } from "@neondatabase/serverless";
import { createHash } from "node:crypto";
import {
  transactionFingerprint,
  validateAccount,
  validateBudget,
  validateCategory,
  validateGoal,
  validateLoan,
  validateRecurring,
  validateTransaction,
} from "../lib/model.mjs";
import { decryptJson, encryptJson } from "../lib/crypto.mjs";
import {
  bodyOf,
  clearSessionCookie,
  currentUser,
  reply,
  requireSameOrigin,
} from "../lib/auth.mjs";

const MAX_IMPORT_ROWS = 2_000;
const ENTITY_TYPES = [
  "account",
  "category",
  "transaction",
  "budget",
  "recurring",
  "goal",
  "loan",
];

function entity(value) {
  if (!ENTITY_TYPES.includes(value)) {
    const error = new Error("Unknown data type.");
    error.status = 400;
    throw error;
  }
  return value;
}

const recordContext = (userId, entityType, id) =>
  `${userId}:${entityType}:${id}`;

function validatorFor(entityType) {
  return {
    account: validateAccount,
    category: validateCategory,
    transaction: validateTransaction,
    budget: validateBudget,
    recurring: validateRecurring,
    goal: validateGoal,
    loan: validateLoan,
  }[entityType];
}

function accountMetadata(entityType, record) {
  return ["transaction", "recurring", "goal", "loan"].includes(entityType)
    ? record.accountId || null
    : null;
}

function decryptRow(row) {
  return decryptJson(
    row.encrypted_payload,
    recordContext(row.user_id, row.entity_type, row.id),
  );
}

function insertRecord(
  sql,
  userId,
  entityType,
  record,
  { ignoreDuplicates = false } = {},
) {
  return sql.query(
    `INSERT INTO paisa_vault
      (user_id, entity_type, id, account_id, fingerprint, encrypted_payload,
       created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ${ignoreDuplicates ? "ON CONFLICT DO NOTHING" : ""}
     RETURNING id`,
    [
      userId,
      entityType,
      record.id,
      accountMetadata(entityType, record),
      entityType === "transaction" ? record.importFingerprint : null,
      encryptJson(record, recordContext(userId, entityType, record.id)),
      record.createdAt,
      record.updatedAt ?? record.createdAt,
    ],
  );
}

function updateRecord(sql, userId, entityType, record) {
  return sql.query(
    `UPDATE paisa_vault
        SET account_id=$4, fingerprint=$5, encrypted_payload=$6, updated_at=$7
      WHERE user_id=$1 AND entity_type=$2 AND id=$3
      RETURNING id`,
    [
      userId,
      entityType,
      record.id,
      accountMetadata(entityType, record),
      entityType === "transaction" ? record.importFingerprint : null,
      encryptJson(record, recordContext(userId, entityType, record.id)),
      record.updatedAt ?? Date.now(),
    ],
  );
}

async function recordsOf(sql, userId, entityType) {
  const rows = await sql.query(
    `SELECT user_id, entity_type, id, encrypted_payload
       FROM paisa_vault
      WHERE user_id=$1 AND entity_type=$2
      ORDER BY created_at, id`,
    [userId, entityType],
  );
  return rows.map(decryptRow);
}

async function ensureUniqueName(sql, userId, entityType, record) {
  const rows = await recordsOf(sql, userId, entityType);
  const duplicate = rows.some(
    (row) =>
      row.id !== record.id &&
      row.name.toLocaleLowerCase("en-IN") ===
        record.name.toLocaleLowerCase("en-IN"),
  );
  if (duplicate) {
    const error = new Error(
      entityType === "account"
        ? "An account with this name already exists."
        : "This category already exists.",
    );
    error.status = 409;
    throw error;
  }
}

function indiaToday() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

function addMonths(date, count) {
  const [year, month, day] = date.split("-").map(Number);
  const first = new Date(Date.UTC(year, month - 1 + count, 1));
  const lastDay = new Date(
    Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + 1, 0),
  ).getUTCDate();
  first.setUTCDate(Math.min(day, lastDay));
  return first.toISOString().slice(0, 10);
}

export function nextRecurringDate(date, frequency) {
  if (frequency === "weekly") {
    const next = new Date(`${date}T00:00:00Z`);
    next.setUTCDate(next.getUTCDate() + 7);
    return next.toISOString().slice(0, 10);
  }
  if (frequency === "monthly") return addMonths(date, 1);
  if (frequency === "quarterly") return addMonths(date, 3);
  return addMonths(date, 12);
}

function recurringTransactionId(recurringId, date) {
  const value = createHash("sha256")
    .update(`${recurringId}:${date}`)
    .digest("hex");
  return `rec_${value}`;
}

async function materializeRecurring(sql, userId) {
  const templates = await recordsOf(sql, userId, "recurring");
  const today = indiaToday();
  const queries = [];
  let sequence = 0;
  for (const template of templates) {
    if (!template.active || template.nextDate > today) continue;
    let nextDate = template.nextDate;
    let generated = 0;
    while (nextDate <= today && generated < 120) {
      const now = Date.now() + sequence++;
      const transaction = validateTransaction({
        id: recurringTransactionId(template.id, nextDate),
        type: template.type,
        amount: template.amount,
        date: nextDate,
        category: template.category,
        accountId: template.accountId,
        paymentType: template.paymentType,
        description: template.description || template.name,
        createdAt: now,
      });
      queries.push(
        insertRecord(sql, userId, "transaction", transaction, {
          ignoreDuplicates: true,
        }),
      );
      nextDate = nextRecurringDate(nextDate, template.frequency);
      generated += 1;
    }
    queries.push(
      updateRecord(sql, userId, "recurring", {
        ...template,
        nextDate,
        updatedAt: Date.now(),
      }),
    );
  }
  if (queries.length) await sql.transaction(queries);
}

async function snapshot(sql, user) {
  await materializeRecurring(sql, user.id);
  const rows = await sql.query(
    `SELECT user_id, entity_type, id, encrypted_payload
       FROM paisa_vault
      WHERE user_id=$1
      ORDER BY created_at, id`,
    [user.id],
  );
  const grouped = {
    account: [],
    category: [],
    transaction: [],
    budget: [],
    recurring: [],
    goal: [],
    loan: [],
  };
  for (const row of rows) {
    if (grouped[row.entity_type]) grouped[row.entity_type].push(decryptRow(row));
  }
  grouped.transaction.sort(
    (left, right) =>
      right.date.localeCompare(left.date) || right.createdAt - left.createdAt,
  );
  const accounts = grouped.account.map((account) => ({
    ...account,
    balance:
      account.opening +
      grouped.transaction
        .filter((transaction) => transaction.accountId === account.id)
        .reduce(
          (sum, transaction) =>
            sum +
            (transaction.type === "income"
              ? transaction.amount
              : -transaction.amount),
          0,
        ),
  }));
  return {
    user,
    accounts,
    categories: grouped.category,
    transactions: grouped.transaction,
    budgets: grouped.budget,
    recurring: grouped.recurring,
    goals: grouped.goal,
    loans: grouped.loan,
  };
}

async function validateAccountOwnership(sql, userId, records) {
  const requested = new Set(
    records.map((record) => record.accountId).filter(Boolean),
  );
  if (!requested.size) return;
  const rows = await sql.query(
    `SELECT id FROM paisa_vault
      WHERE user_id=$1 AND entity_type='account' AND id=ANY($2::text[])`,
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

async function create(sql, userId, entityType, body) {
  let record;
  if (entityType === "account") {
    record = validateAccount(body.record ?? body);
    await ensureUniqueName(sql, userId, entityType, record);
  } else if (entityType === "category") {
    record = validateCategory(body.record ?? body);
    await ensureUniqueName(sql, userId, entityType, record);
  } else {
    record = validatorFor(entityType)(body.record ?? body);
    if (["transaction", "recurring", "goal", "loan"].includes(entityType)) {
      await validateAccountOwnership(sql, userId, [record]);
    }
  }
  await insertRecord(sql, userId, entityType, record);
  return record;
}

function notFound(label) {
  const error = new Error(`${label} not found.`);
  error.status = 404;
  throw error;
}

async function update(sql, userId, entityType, body) {
  if (entityType === "account") {
    const record = validateAccount(body.record ?? body);
    await ensureUniqueName(sql, userId, entityType, record);
    const rows = await updateRecord(sql, userId, entityType, record);
    if (!rows.length) notFound("Account");
    return record;
  }
  if (entityType === "category") {
    const record = validateCategory(body.record ?? body);
    const oldName = String(body.oldName || "").trim();
    if (!oldName) {
      const error = new Error("Original category name is required.");
      error.status = 400;
      throw error;
    }
    await ensureUniqueName(sql, userId, entityType, record);
    const categories = await recordsOf(sql, userId, "category");
    if (!categories.some((category) => category.id === record.id)) {
      notFound("Category");
    }
    const transactions = await recordsOf(sql, userId, "transaction");
    const recurring = await recordsOf(sql, userId, "recurring");
    const budgets = await recordsOf(sql, userId, "budget");
    const queries = [updateRecord(sql, userId, entityType, record)];
    for (const transaction of transactions) {
      if (transaction.category !== oldName) continue;
      transaction.category = record.name;
      transaction.updatedAt = Date.now();
      queries.push(updateRecord(sql, userId, "transaction", transaction));
    }
    for (const template of recurring) {
      if (template.category !== oldName) continue;
      template.category = record.name;
      template.updatedAt = Date.now();
      queries.push(updateRecord(sql, userId, "recurring", template));
    }
    for (const budget of budgets) {
      if (budget.category !== oldName) continue;
      budget.category = record.name;
      budget.updatedAt = Date.now();
      queries.push(updateRecord(sql, userId, "budget", budget));
    }
    await sql.transaction(queries);
    return record;
  }
  const record = validatorFor(entityType)(body.record ?? body);
  if (["transaction", "recurring", "goal", "loan"].includes(entityType)) {
    await validateAccountOwnership(sql, userId, [record]);
  }
  const rows = await updateRecord(sql, userId, entityType, record);
  if (!rows.length) {
    notFound(entityType.charAt(0).toUpperCase() + entityType.slice(1));
  }
  return record;
}

async function remove(sql, userId, entityType, req) {
  if (req.query?.clear === "1") {
    if (entityType === "account") {
      const goals = await recordsOf(sql, userId, "goal");
      const loans = await recordsOf(sql, userId, "loan");
      await sql.transaction([
        sql.query(
          "DELETE FROM paisa_vault WHERE user_id=$1 AND entity_type='transaction'",
          [userId],
        ),
        sql.query(
          "DELETE FROM paisa_vault WHERE user_id=$1 AND entity_type='recurring'",
          [userId],
        ),
        ...goals
          .filter((record) => record.accountId)
          .map((record) =>
            updateRecord(sql, userId, "goal", {
              ...record,
              accountId: "",
              updatedAt: Date.now(),
            }),
          ),
        ...loans
          .filter((record) => record.accountId)
          .map((record) =>
            updateRecord(sql, userId, "loan", {
              ...record,
              accountId: "",
              updatedAt: Date.now(),
            }),
          ),
        sql.query(
          "DELETE FROM paisa_vault WHERE user_id=$1 AND entity_type='account'",
          [userId],
        ),
      ]);
    } else {
      await sql.query(
        "DELETE FROM paisa_vault WHERE user_id=$1 AND entity_type=$2",
        [userId, entityType],
      );
    }
    return { cleared: true };
  }
  const id = String(req.query?.id || "");
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) {
    const error = new Error("A valid ID is required.");
    error.status = 400;
    throw error;
  }
  if (entityType === "category") {
    const categories = await recordsOf(sql, userId, "category");
    const selected = categories.find((category) => category.id === id);
    if (selected) {
      const transactions = await recordsOf(sql, userId, "transaction");
      const recurring = await recordsOf(sql, userId, "recurring");
      const budgets = await recordsOf(sql, userId, "budget");
      if (
        transactions.some((record) => record.category === selected.name) ||
        recurring.some((record) => record.category === selected.name) ||
        budgets.some((record) => record.category === selected.name)
      ) {
        const error = new Error(
          "This category is in use and cannot be deleted.",
        );
        error.status = 409;
        throw error;
      }
    }
  }
  if (entityType === "account") {
    const goals = await recordsOf(sql, userId, "goal");
    const loans = await recordsOf(sql, userId, "loan");
    const results = await sql.transaction([
      sql.query(
        `DELETE FROM paisa_vault
          WHERE user_id=$1 AND entity_type='transaction' AND account_id=$2`,
        [userId, id],
      ),
      sql.query(
        `DELETE FROM paisa_vault
          WHERE user_id=$1 AND entity_type='recurring' AND account_id=$2`,
        [userId, id],
      ),
      ...goals
        .filter((record) => record.accountId === id)
        .map((record) =>
          updateRecord(sql, userId, "goal", {
            ...record,
            accountId: "",
            updatedAt: Date.now(),
          }),
        ),
      ...loans
        .filter((record) => record.accountId === id)
        .map((record) =>
          updateRecord(sql, userId, "loan", {
            ...record,
            accountId: "",
            updatedAt: Date.now(),
          }),
        ),
      sql.query(
        `DELETE FROM paisa_vault
          WHERE user_id=$1 AND entity_type='account' AND id=$2 RETURNING id`,
        [userId, id],
      ),
    ]);
    return { deleted: results.at(-1).length > 0 };
  }
  const rows = await sql.query(
    `DELETE FROM paisa_vault
      WHERE user_id=$1 AND entity_type=$2 AND id=$3 RETURNING id`,
    [userId, entityType, id],
  );
  return { deleted: rows.length > 0 };
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
  const existing = await recordsOf(sql, userId, "transaction");
  const known = new Set(existing.map(transactionFingerprint));
  const uniqueRecords = [];
  for (const record of records) {
    if (known.has(record.importFingerprint)) continue;
    known.add(record.importFingerprint);
    uniqueRecords.push(record);
  }
  const existingCategories = await recordsOf(sql, userId, "category");
  const categoryNames = new Set(
    existingCategories.map((category) =>
      category.name.toLocaleLowerCase("en-IN"),
    ),
  );
  const uniqueCategories = categories.filter((category) => {
    const name = category.name.toLocaleLowerCase("en-IN");
    if (categoryNames.has(name)) return false;
    categoryNames.add(name);
    return true;
  });
  const queries = [
    ...uniqueCategories.map((record) =>
      insertRecord(sql, userId, "category", record, {
        ignoreDuplicates: true,
      }),
    ),
    ...uniqueRecords.map((record) =>
      insertRecord(sql, userId, "transaction", record, {
        ignoreDuplicates: true,
      }),
    ),
  ];
  const results = queries.length ? await sql.transaction(queries) : [];
  const inserted = results
    .slice(uniqueCategories.length)
    .reduce((sum, rows) => sum + rows.length, 0);
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
  const budgets = (data.budgets || []).map(validateBudget);
  const recurring = (data.recurring || []).map(validateRecurring);
  const goals = (data.goals || []).map(validateGoal);
  const loans = (data.loans || []).map(validateLoan);
  if ([budgets, recurring, goals, loans].some((rows) => rows.length > MAX_IMPORT_ROWS)) {
    const error = new Error("Backup contains too many planning records.");
    error.status = 400;
    throw error;
  }
  const accountIds = new Set(accounts.map((account) => account.id));
  if (
    [...transactions, ...recurring].some(
      (record) => !accountIds.has(record.accountId),
    ) ||
    [...goals, ...loans].some(
      (record) => record.accountId && !accountIds.has(record.accountId),
    )
  ) {
    const error = new Error(
      "The backup contains a transaction with an invalid account.",
    );
    error.status = 400;
    throw error;
  }
  await sql.transaction([
    sql.query("DELETE FROM paisa_vault WHERE user_id=$1", [userId]),
    ...accounts.map((record) => insertRecord(sql, userId, "account", record)),
    ...categories.map((record) =>
      insertRecord(sql, userId, "category", record),
    ),
    ...transactions.map((record) =>
      insertRecord(sql, userId, "transaction", record),
    ),
    ...budgets.map((record) => insertRecord(sql, userId, "budget", record)),
    ...recurring.map((record) =>
      insertRecord(sql, userId, "recurring", record),
    ),
    ...goals.map((record) => insertRecord(sql, userId, "goal", record)),
    ...loans.map((record) => insertRecord(sql, userId, "loan", record)),
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
    if (!process.env.DATA_ENCRYPTION_KEY) {
      return reply(res, 503, {
        error:
          "Server setup is incomplete. Add DATA_ENCRYPTION_KEY in Vercel.",
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
    const entityType = entity(String(req.query?.entity || body.entity || ""));
    if (req.method === "POST") {
      return reply(res, 201, await create(sql, user.id, entityType, body));
    }
    if (req.method === "PUT") {
      return reply(res, 200, await update(sql, user.id, entityType, body));
    }
    if (req.method === "DELETE") {
      return reply(res, 200, await remove(sql, user.id, entityType, req));
    }
    res.setHeader("Allow", "GET, POST, PUT, DELETE");
    return reply(res, 405, { error: "Method not allowed." });
  } catch (error) {
    const status =
      Number(error.status) ||
      (error.code === "23505" ? 409 : error.code === "23503" ? 400 : 500);
    console.error(error);
    return reply(
      res,
      status,
      {
        error:
          status === 500
            ? "The database request failed. Please try again."
            : error.message,
      },
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
