import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SESSION_AGE_SECONDS = 60 * 60 * 24 * 30;
const USERNAME_RE = /^[a-z0-9_]{3,30}$/;

export function reply(res, status, payload, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [name, value] of Object.entries(extraHeaders)) {
    res.setHeader(name, value);
  }
  res.end(JSON.stringify(payload));
}

export function bodyOf(req) {
  if (!req.body) return {};
  if (typeof req.body === "object") return req.body;
  try {
    return JSON.parse(req.body);
  } catch {
    const error = new Error("Request body is not valid JSON.");
    error.status = 400;
    throw error;
  }
}

export function requireSameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  let originHost = "";
  try {
    originHost = new URL(origin).host;
  } catch {
    originHost = "";
  }
  if (!host || originHost !== host) {
    const error = new Error("Cross-origin writes are not allowed.");
    error.status = 403;
    throw error;
  }
}

export function normalizeUsername(value) {
  const username = String(value || "")
    .trim()
    .toLowerCase();
  if (!USERNAME_RE.test(username)) {
    const error = new Error(
      "Username must be 3–30 characters using letters, numbers, or underscores.",
    );
    error.status = 400;
    throw error;
  }
  return username;
}

export function validatePassword(value) {
  const password = String(value || "");
  if (password.length < 10 || password.length > 128) {
    const error = new Error("Password must be between 10 and 128 characters.");
    error.status = 400;
    throw error;
  }
  return password;
}

export async function hashPassword(password, salt = randomBytes(16)) {
  const derived = await scrypt(password, salt, 64, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("base64url")}$${Buffer.from(derived).toString("base64url")}`;
}

export async function verifyPassword(password, encoded) {
  const [algorithm, n, r, p, saltValue, hashValue] = String(encoded).split("$");
  if (algorithm !== "scrypt" || !saltValue || !hashValue) return false;
  const expected = Buffer.from(hashValue, "base64url");
  const actual = await scrypt(
    password,
    Buffer.from(saltValue, "base64url"),
    expected.length,
    {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: 64 * 1024 * 1024,
    },
  );
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function cookieName() {
  return process.env.VERCEL || process.env.NODE_ENV === "production"
    ? "__Host-paisa_session"
    : "paisa_session";
}

function cookieValue(req) {
  const cookies = String(req.headers.cookie || "")
    .split(";")
    .map((part) => part.trim().split("="));
  for (const accepted of [
    cookieName(),
    "__Host-paisa_session",
    "paisa_session",
  ]) {
    const pair = cookies.find(([name]) => name === accepted);
    if (pair) {
      try {
        return decodeURIComponent(pair.slice(1).join("="));
      } catch {
        return "";
      }
    }
  }
  return "";
}

function tokenHash(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function clearSessionCookie() {
  return `${cookieName()}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${
    cookieName().startsWith("__Host-") ? "; Secure" : ""
  }`;
}

export async function createSession(sql, userId, req) {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  const expiresAt = now + SESSION_AGE_SECONDS * 1000;
  await sql.query(
    `INSERT INTO paisa_sessions (token_hash, user_id, expires_at, created_at)
     VALUES ($1, $2, $3, $4)`,
    [tokenHash(token), userId, expiresAt, now],
  );
  const secure = cookieName().startsWith("__Host-") ? "; Secure" : "";
  return `${cookieName()}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_AGE_SECONDS}${secure}`;
}

export async function destroySession(sql, req) {
  const token = cookieValue(req);
  if (token) {
    await sql.query("DELETE FROM paisa_sessions WHERE token_hash=$1", [
      tokenHash(token),
    ]);
  }
}

export async function currentUser(sql, req, { required = true } = {}) {
  const token = cookieValue(req);
  if (!token) {
    if (!required) return null;
    const error = new Error("Sign in to access Paisa.");
    error.status = 401;
    throw error;
  }
  const rows = await sql.query(
    `SELECT u.id, u.username
       FROM paisa_sessions s
       JOIN paisa_users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at>$2
      LIMIT 1`,
    [tokenHash(token), Date.now()],
  );
  if (!rows.length) {
    if (!required) return null;
    const error = new Error("Your session has expired. Please sign in again.");
    error.status = 401;
    throw error;
  }
  return { id: rows[0].id, username: rows[0].username };
}

export function newUserId() {
  return randomUUID();
}
