import { createHash, timingSafeEqual } from "node:crypto";
import { blindIndex } from "./crypto.mjs";

export const ACCOUNT_TYPES = ["Bank account", "Cash", "Credit card", "Wallet"];
export const PAYMENT_TYPES = [
  "Bank/Cheque",
  "Credit Card",
  "Debit Card",
  "UPI/Cash",
];
export const TRANSACTION_TYPES = ["income", "expense"];
export const RECURRING_FREQUENCIES = [
  "weekly",
  "monthly",
  "quarterly",
  "yearly",
];
export const LOAN_DIRECTIONS = ["borrowed", "lent"];

const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;

function fail(message) {
  const error = new Error(message);
  error.status = 400;
  throw error;
}

function text(value, label, max, required = true) {
  const result = String(value ?? "").trim();
  if (required && !result) fail(`${label} is required.`);
  if (result.length > max) fail(`${label} must be ${max} characters or fewer.`);
  return result;
}

function id(value, label = "ID") {
  const result = text(value, label, 100);
  if (!ID_RE.test(result)) fail(`${label} is invalid.`);
  return result;
}

function integer(value, label, { positive = false } = {}) {
  const result = Number(value);
  if (!Number.isSafeInteger(result))
    fail(`${label} must be a valid amount in paise.`);
  if (positive && result <= 0) fail(`${label} must be greater than zero.`);
  return result;
}

function nonnegativeInteger(value, label) {
  const result = integer(value, label);
  if (result < 0) fail(`${label} cannot be negative.`);
  return result;
}

function enumValue(value, allowed, label) {
  const result = String(value ?? "");
  if (!allowed.includes(result)) fail(`${label} is invalid.`);
  return result;
}

function dateValue(value) {
  const result = String(value ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(result))
    fail("Date must use YYYY-MM-DD format.");
  const [year, month, day] = result.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  )
    fail("Date is invalid.");
  return result;
}

function optionalDate(value, label = "Date") {
  if (value === undefined || value === null || value === "") return "";
  try {
    return dateValue(value);
  } catch {
    fail(`${label} is invalid.`);
  }
}

function optionalId(value, label) {
  if (value === undefined || value === null || value === "") return "";
  return id(value, label);
}

function monthValue(value) {
  const result = String(value ?? "");
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(result)) {
    fail("Budget month must use YYYY-MM format.");
  }
  return result;
}

function booleanValue(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be true or false.`);
  return value;
}

export function validateAccount(input) {
  const now = Date.now();
  return {
    id: id(input?.id, "Account ID"),
    name: text(input?.name, "Account name", 60),
    type: enumValue(input?.type, ACCOUNT_TYPES, "Account type"),
    opening: integer(input?.opening ?? 0, "Opening balance"),
    createdAt: integer(input?.createdAt ?? now, "Created time"),
    updatedAt: now,
  };
}

export function validateCategory(input) {
  return {
    id: id(input?.id, "Category ID"),
    name: text(input?.name, "Category name", 40),
    createdAt: integer(input?.createdAt ?? Date.now(), "Created time"),
  };
}

export function validateTransaction(input, { imported = false } = {}) {
  const now = Date.now();
  const record = {
    id: id(input?.id, "Transaction ID"),
    type: enumValue(input?.type, TRANSACTION_TYPES, "Transaction type"),
    amount: integer(input?.amount, "Amount", { positive: true }),
    date: dateValue(input?.date),
    category: text(input?.category, "Category", 40),
    accountId: id(input?.accountId, "Account ID"),
    paymentType: enumValue(
      input?.paymentType || "UPI/Cash",
      PAYMENT_TYPES,
      "Payment type",
    ),
    description: text(input?.description, "Description", 500, false),
    importSource: imported
      ? text(input?.importSource, "Import source", 255, false) || null
      : null,
    importFingerprint: null,
    createdAt: integer(input?.createdAt ?? now, "Created time"),
    updatedAt: now,
  };
  if (imported) record.importFingerprint = transactionFingerprint(record);
  return record;
}

export function validateBudget(input) {
  const now = Date.now();
  return {
    id: id(input?.id, "Budget ID"),
    name: text(input?.name, "Budget name", 60),
    category: text(input?.category || "All categories", "Category", 40),
    amount: integer(input?.amount, "Budget amount", { positive: true }),
    month: monthValue(input?.month),
    createdAt: integer(input?.createdAt ?? now, "Created time"),
    updatedAt: now,
  };
}

export function validateRecurring(input) {
  const now = Date.now();
  return {
    id: id(input?.id, "Recurring transaction ID"),
    name: text(input?.name, "Recurring transaction name", 60),
    type: enumValue(input?.type, TRANSACTION_TYPES, "Transaction type"),
    amount: integer(input?.amount, "Amount", { positive: true }),
    category: text(input?.category, "Category", 40),
    accountId: id(input?.accountId, "Account ID"),
    paymentType: enumValue(
      input?.paymentType || "UPI/Cash",
      PAYMENT_TYPES,
      "Payment type",
    ),
    description: text(input?.description, "Description", 500, false),
    frequency: enumValue(
      input?.frequency,
      RECURRING_FREQUENCIES,
      "Frequency",
    ),
    nextDate: dateValue(input?.nextDate),
    active: booleanValue(input?.active ?? true, "Active status"),
    createdAt: integer(input?.createdAt ?? now, "Created time"),
    updatedAt: now,
  };
}

export function validateGoal(input) {
  const now = Date.now();
  return {
    id: id(input?.id, "Goal ID"),
    name: text(input?.name, "Goal name", 60),
    targetAmount: integer(input?.targetAmount, "Target amount", {
      positive: true,
    }),
    savedAmount: nonnegativeInteger(input?.savedAmount ?? 0, "Saved amount"),
    targetDate: optionalDate(input?.targetDate, "Target date"),
    accountId: optionalId(input?.accountId, "Account ID"),
    notes: text(input?.notes, "Notes", 500, false),
    createdAt: integer(input?.createdAt ?? now, "Created time"),
    updatedAt: now,
  };
}

export function validateLoan(input) {
  const now = Date.now();
  const interestRate = nonnegativeInteger(
    input?.interestRate ?? 0,
    "Interest rate",
  );
  if (interestRate > 100_000) fail("Interest rate cannot exceed 1,000%.");
  return {
    id: id(input?.id, "Loan ID"),
    name: text(input?.name, "Loan name", 60),
    direction: enumValue(input?.direction, LOAN_DIRECTIONS, "Loan direction"),
    principal: integer(input?.principal, "Principal", { positive: true }),
    outstanding: nonnegativeInteger(input?.outstanding, "Outstanding amount"),
    interestRate,
    dueDate: optionalDate(input?.dueDate, "Due date"),
    accountId: optionalId(input?.accountId, "Account ID"),
    notes: text(input?.notes, "Notes", 500, false),
    createdAt: integer(input?.createdAt ?? now, "Created time"),
    updatedAt: now,
  };
}

export function transactionFingerprint(record) {
  const normalized = [
    record.date,
    record.type,
    record.amount,
    record.accountId,
    record.paymentType,
    String(record.description || "")
      .trim()
      .replace(/\s+/g, " ")
      .toLocaleLowerCase("en-IN"),
  ].join("|");
  return process.env.DATA_ENCRYPTION_KEY
    ? blindIndex(normalized, "transaction-fingerprint")
    : createHash("sha256").update(normalized).digest("hex");
}

export function secureKeyEqual(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function accountRow(row) {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    opening: Number(row.opening),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    balance: Number(row.balance),
  };
}

export function categoryRow(row) {
  return { id: row.id, name: row.name, createdAt: Number(row.created_at) };
}

export function transactionRow(row) {
  return {
    id: row.id,
    type: row.type,
    amount: Number(row.amount),
    date: String(row.date).slice(0, 10),
    category: row.category,
    accountId: row.account_id,
    paymentType: row.payment_type,
    description: row.description || "",
    importSource: row.import_source || undefined,
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
  };
}
