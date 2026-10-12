import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  validateBudget,
  validateGoal,
  validateLoan,
  validateRecurring,
  transactionFingerprint,
  validateAccount,
  validateTransaction,
} from "../lib/model.mjs";

const transaction = {
  id: "tx_1",
  type: "expense",
  amount: 125050,
  date: "2026-10-01",
  category: "Shopping",
  accountId: "account_1",
  paymentType: "Debit Card",
  description: "Laptop stand",
  createdAt: 1,
};

test("payment type is validated on transactions", () => {
  const saved = validateTransaction(transaction);
  assert.equal(saved.paymentType, "Debit Card");
  assert.throws(
    () => validateTransaction({ ...transaction, paymentType: "Wallet" }),
    /Payment type is invalid/,
  );
});

test("accounts keep existing fields without a payment type", () => {
  const account = validateAccount({
    id: "account_1",
    name: "Primary Bank",
    type: "Bank account",
    opening: 250000,
    createdAt: 1,
    paymentType: "Credit Card",
  });
  assert.deepEqual(Object.keys(account).sort(), [
    "createdAt",
    "id",
    "name",
    "opening",
    "type",
    "updatedAt",
  ]);
});

test("duplicate fingerprints normalize description whitespace and case", () => {
  const first = transactionFingerprint(transaction);
  const second = transactionFingerprint({
    ...transaction,
    description: "  LAPTOP   stand ",
  });
  assert.equal(first, second);
  assert.notEqual(
    first,
    transactionFingerprint({ ...transaction, paymentType: "UPI/Cash" }),
  );
});

test("transaction form owns Payment Type and account form does not", async () => {
  const html = await readFile(
    new URL("../public/index.html", import.meta.url),
    "utf8",
  );
  const txForm = html.match(
    /<form class="modal-form" id="tx-form">([\s\S]*?)<\/form>/,
  )?.[1];
  const accountForm = html.match(
    /<form class="modal-form" id="account-form">([\s\S]*?)<\/form>/,
  )?.[1];
  assert.match(txForm, /Payment Type/);
  assert.doesNotMatch(accountForm, /Payment Type/);
});

test("client provides registration, login and logout without an access key", async () => {
  const html = await readFile(
    new URL("../public/index.html", import.meta.url),
    "utf8",
  );
  assert.match(html, /Create account/);
  assert.match(html, /name="email" type="email"/);
  assert.match(html, /verify_registration/);
  assert.match(html, /totp_begin/);
  assert.match(html, /autocomplete="username"/);
  assert.match(html, /current-password/);
  assert.match(html, /data-action="logout"/);
  assert.doesNotMatch(
    html,
    /Workspace access key|X-Paisa-Key|paisa_access_key/,
  );
});

test("new accounts use POST while existing accounts use PUT", async () => {
  const html = await readFile(
    new URL("../public/index.html", import.meta.url),
    "utf8",
  );
  assert.match(html, /if \(id\) await db\.put\("accounts", record\)/);
  assert.match(html, /else await db\.add\("accounts", record\)/);
});

test("dashboard selects the latest populated month and removed cloud slogans", async () => {
  const html = await readFile(
    new URL("../public/index.html", import.meta.url),
    "utf8",
  );
  assert.match(html, /selectedMonthHasData/);
  assert.match(html, /state\.month = latestMonth/);
  for (const phrase of [
    "Private workspace · Cloud-synced data",
    "Online · cloud database",
    "Stored securely online",
    "Available across your devices",
  ]) {
    assert.equal(html.includes(phrase), false);
  }
});

test("planning records validate money, dates, account links and schedules", () => {
  assert.equal(
    validateBudget({
      id: "budget_1",
      name: "Food cap",
      category: "Food",
      amount: 200000,
      month: "2026-10",
      createdAt: 1,
    }).amount,
    200000,
  );
  assert.equal(
    validateRecurring({
      id: "recurring_1",
      name: "Rent",
      type: "expense",
      amount: 1800000,
      category: "Rent",
      accountId: "account_1",
      paymentType: "Bank/Cheque",
      description: "Monthly rent",
      frequency: "monthly",
      nextDate: "2026-10-05",
      active: true,
      createdAt: 1,
    }).frequency,
    "monthly",
  );
  assert.equal(
    validateGoal({
      id: "goal_1",
      name: "Emergency fund",
      targetAmount: 5000000,
      savedAmount: 1000000,
      targetDate: "2027-12-31",
      accountId: "",
      createdAt: 1,
    }).savedAmount,
    1000000,
  );
  assert.equal(
    validateLoan({
      id: "loan_1",
      name: "Vehicle loan",
      direction: "borrowed",
      principal: 10000000,
      outstanding: 7000000,
      interestRate: 850,
      dueDate: "2029-01-01",
      accountId: "account_1",
      createdAt: 1,
    }).interestRate,
    850,
  );
  assert.throws(
    () =>
      validateRecurring({
        id: "recurring_1",
        name: "Bad schedule",
        type: "expense",
        amount: 100,
        category: "Other",
        accountId: "account_1",
        frequency: "daily",
        nextDate: "2026-10-01",
      }),
    /Frequency is invalid/,
  );
});

test("client includes password recovery, QR-based 2FA management and planning", async () => {
  const html = await readFile(
    new URL("../public/index.html", import.meta.url),
    "utf8",
  );
  for (const value of [
    "password_reset_begin",
    "password_reset_confirm",
    "password_change",
    "totp_disable",
    "qrDataUrl",
    '["planning", "Planning"]',
    "Add recurring entry",
    "Add savings goal",
  ]) {
    assert.match(html, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});
