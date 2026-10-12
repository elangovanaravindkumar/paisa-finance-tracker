import assert from "node:assert/strict";
import { test } from "node:test";
import { decryptJson, encryptJson } from "../lib/crypto.mjs";
import { createTotpSecret, otpHash, verifyTotp } from "../lib/mfa.mjs";

process.env.DATA_ENCRYPTION_KEY ||= "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

test("financial payload encryption hides plaintext and authenticates context", () => {
  const record = { amount: 125000, account: "Primary Bank" };
  const encrypted = encryptJson(record, "user-a:transaction:tx-1");
  assert.equal(encrypted.includes("Primary Bank"), false);
  assert.deepEqual(
    decryptJson(encrypted, "user-a:transaction:tx-1"),
    record,
  );
  assert.throws(
    () => decryptJson(encrypted, "user-b:transaction:tx-1"),
    /authenticate|Unsupported state/i,
  );
});

test("email OTP hashes are bound to their challenge token", () => {
  assert.equal(otpHash("challenge-a", "123456").length, 64);
  assert.notEqual(
    otpHash("challenge-a", "123456"),
    otpHash("challenge-b", "123456"),
  );
});

test("authenticator secrets and invalid codes are handled safely", () => {
  const secret = createTotpSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.equal(verifyTotp(secret, "not-a-code"), false);
});
