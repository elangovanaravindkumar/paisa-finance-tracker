import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createSession,
  currentUser,
  hashPassword,
  normalizeUsername,
  validatePassword,
  verifyPassword,
} from "../lib/auth.mjs";

test("passwords use salted scrypt hashes and verify safely", async () => {
  const first = await hashPassword("a strong password");
  const second = await hashPassword("a strong password");
  assert.match(first, /^scrypt\$16384\$8\$1\$/);
  assert.notEqual(first, second);
  assert.equal(first.includes("a strong password"), false);
  assert.equal(await verifyPassword("a strong password", first), true);
  assert.equal(await verifyPassword("incorrect password", first), false);
});

test("username and password policy rejects unsafe credentials", () => {
  assert.equal(normalizeUsername(" Anita_Rao "), "anita_rao");
  assert.throws(() => normalizeUsername("a"), /3–30/);
  assert.throws(() => normalizeUsername("anita@example.com"), /letters/);
  assert.throws(() => validatePassword("short"), /10 and 128/);
});

test("session token is hashed in storage and returned only as an HttpOnly cookie", async () => {
  let stored;
  const sql = {
    query: async (statement, params) => {
      stored = { statement, params };
      return [];
    },
  };
  const cookie = await createSession(
    sql,
    "a00f5d67-d18e-4ad2-b351-f4bd3690806f",
    {
      headers: {},
    },
  );
  const token = decodeURIComponent(cookie.match(/^[^=]+=([^;]+)/)[1]);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.equal(stored.params[0].length, 64);
  assert.notEqual(stored.params[0], token);
  assert.equal(stored.params.includes(token), false);
});

test("authenticated user comes only from the server-side session lookup", async () => {
  const sql = {
    query: async (statement, params) => {
      assert.match(statement, /paisa_sessions/);
      assert.equal(params[0].length, 64);
      return [{ id: "user-a", username: "anita" }];
    },
  };
  const user = await currentUser(sql, {
    headers: { cookie: "paisa_session=raw-browser-token" },
  });
  assert.deepEqual(user, { id: "user-a", username: "anita" });
});
