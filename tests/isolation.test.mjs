import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { nextRecurringDate, remove, snapshot } from "../api/finance.mjs";

test("every snapshot query is scoped to the authenticated user", async () => {
  const calls = [];
  const sql = {
    query: async (statement, params) => {
      calls.push({ statement, params });
      return [];
    },
  };
  const data = await snapshot(sql, { id: "user-a", username: "anita" });
  assert.ok(calls.length >= 1);
  for (const call of calls) {
    assert.match(call.statement, /user_id=\$1|user_id = \$1/);
    assert.equal(call.params[0], "user-a");
  }
  assert.deepEqual(data.accounts, []);
  assert.deepEqual(data.transactions, []);
});

test("delete includes authenticated user ownership and cannot target by ID alone", async () => {
  let call;
  const sql = {
    query: async (statement, params) => {
      call = { statement, params };
      return [];
    },
  };
  const result = await remove(sql, "user-b", "transaction", {
    query: { id: "user_a_transaction" },
  });
  assert.match(call.statement, /user_id=\$1 AND entity_type=\$2 AND id=\$3/);
  assert.deepEqual(call.params, [
    "user-b",
    "transaction",
    "user_a_transaction",
  ]);
  assert.deepEqual(result, { deleted: false });
});

test("database schema enforces composite user ownership", async () => {
  const schema = await readFile(
    new URL("../db/schema.sql", import.meta.url),
    "utf8",
  );
  assert.match(schema, /PRIMARY KEY \(user_id, id\)/);
  assert.match(
    schema,
    /FOREIGN KEY \(user_id, account_id\)[\s\S]*REFERENCES paisa_accounts\(user_id, id\)/,
  );
  assert.match(schema, /UNIQUE INDEX[\s\S]*\(user_id, import_fingerprint\)/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS paisa_vault/);
  assert.match(schema, /encrypted_payload text NOT NULL/);
  for (const entity of ["budget", "recurring", "goal", "loan"]) {
    assert.match(schema, new RegExp(`entity_type IN \\([^)]*'${entity}'`));
  }
});

test("recurring schedules advance without invalid end-of-month dates", () => {
  assert.equal(nextRecurringDate("2026-01-31", "monthly"), "2026-02-28");
  assert.equal(nextRecurringDate("2028-02-29", "yearly"), "2029-02-28");
  assert.equal(nextRecurringDate("2026-10-01", "weekly"), "2026-10-08");
});
