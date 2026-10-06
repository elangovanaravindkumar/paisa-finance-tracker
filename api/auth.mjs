import { neon } from "@neondatabase/serverless";
import {
  bodyOf,
  clearSessionCookie,
  createSession,
  currentUser,
  destroySession,
  hashPassword,
  newUserId,
  normalizeUsername,
  reply,
  requireSameOrigin,
  validatePassword,
  verifyPassword,
} from "../lib/auth.mjs";

const GENERIC_LOGIN_ERROR = "Username or password is incorrect.";

async function register(sql, req, body) {
  const username = normalizeUsername(body.username);
  const password = validatePassword(body.password);
  const passwordHash = await hashPassword(password);
  const id = newUserId();
  const now = Date.now();
  try {
    await sql.query(
      `INSERT INTO paisa_users
        (id, username, password_hash, failed_login_attempts, locked_until, created_at)
       VALUES ($1, $2, $3, 0, 0, $4)`,
      [id, username, passwordHash, now],
    );
  } catch (error) {
    if (error.code === "23505") {
      const conflict = new Error("That username is already in use.");
      conflict.status = 409;
      throw conflict;
    }
    throw error;
  }
  const cookie = await createSession(sql, id, req);
  return { user: { id, username }, cookie };
}

async function login(sql, req, body) {
  const username = normalizeUsername(body.username);
  const password = validatePassword(body.password);
  const rows = await sql.query(
    `SELECT id, username, password_hash, failed_login_attempts, locked_until
       FROM paisa_users WHERE username=$1 LIMIT 1`,
    [username],
  );
  const user = rows[0];
  if (!user) {
    await hashPassword(password, Buffer.alloc(16));
    const error = new Error(GENERIC_LOGIN_ERROR);
    error.status = 401;
    throw error;
  }
  const now = Date.now();
  if (Number(user.locked_until) > now) {
    const error = new Error("Too many attempts. Try again in 15 minutes.");
    error.status = 429;
    throw error;
  }
  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    const attempts = Number(user.failed_login_attempts || 0) + 1;
    const lockedUntil = attempts >= 5 ? now + 15 * 60 * 1000 : 0;
    await sql.query(
      `UPDATE paisa_users
          SET failed_login_attempts=$2, locked_until=$3
        WHERE id=$1`,
      [user.id, lockedUntil ? 0 : attempts, lockedUntil],
    );
    const error = new Error(GENERIC_LOGIN_ERROR);
    error.status = 401;
    throw error;
  }
  await sql.query(
    "UPDATE paisa_users SET failed_login_attempts=0, locked_until=0 WHERE id=$1",
    [user.id],
  );
  const cookie = await createSession(sql, user.id, req);
  return { user: { id: user.id, username: user.username }, cookie };
}

export default async function handler(req, res) {
  try {
    if (!process.env.DATABASE_URL) {
      return reply(res, 503, {
        error: "Server setup is incomplete. Add DATABASE_URL in Vercel.",
      });
    }
    const sql = neon(process.env.DATABASE_URL);
    if (req.method === "GET") {
      const user = await currentUser(sql, req);
      return reply(res, 200, { user });
    }
    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return reply(res, 405, { error: "Method not allowed." });
    }
    requireSameOrigin(req);
    const body = bodyOf(req);
    if (body.action === "register") {
      const result = await register(sql, req, body);
      return reply(
        res,
        201,
        { user: result.user },
        { "Set-Cookie": result.cookie },
      );
    }
    if (body.action === "login") {
      const result = await login(sql, req, body);
      return reply(
        res,
        200,
        { user: result.user },
        { "Set-Cookie": result.cookie },
      );
    }
    if (body.action === "logout") {
      await destroySession(sql, req);
      return reply(
        res,
        200,
        { signedOut: true },
        { "Set-Cookie": clearSessionCookie() },
      );
    }
    return reply(res, 400, { error: "Unknown authentication action." });
  } catch (error) {
    const status = Number(error.status) || 500;
    console.error(error);
    return reply(res, status, {
      error:
        status === 500
          ? "The authentication request failed. Please try again."
          : error.message,
    });
  }
}

export { login, register };
