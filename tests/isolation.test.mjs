import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { remove, snapshot } from "../api/finance.mjs";

test("every snapshot query is scoped to the authenticated user", async () => {
  const calls = [];
  const sql = {
    query: async (statement, params) => {
      calls.push({ statement, params });
      return [];
    },
  };
  const data = await snapshot(sql, { id: "user-a", username: "anita" });
  assert.equal(calls.length, 3);
  for (const call of calls) {
    assert.match(call.statement, /user_id=\$1|user_id = \$1/);
    assert.deepEqual(call.params, ["user-a"]);
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
  assert.match(call.statement, /user_id=\$1 AND id=\$2/);
  assert.deepEqual(call.params, ["user-b", "user_a_transaction"]);
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
});
