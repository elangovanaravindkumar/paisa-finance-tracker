import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
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
  assert.match(html, /autocomplete="username"/);
  assert.match(html, /current-password/);
  assert.match(html, /data-action="logout"/);
  assert.doesNotMatch(
    html,
    /Workspace access key|X-Paisa-Key|paisa_access_key/,
  );
});
