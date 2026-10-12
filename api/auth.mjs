import { neon } from "@neondatabase/serverless";
import QRCode from "qrcode";
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
import { decryptJson, encryptJson } from "../lib/crypto.mjs";
import {
  backupCodeHash,
  challengeToken,
  createBackupCodes,
  createTotpSecret,
  normalizeEmail,
  otpCode,
  otpHash,
  safeEqual,
  sendOtpEmail,
  tokenHash,
  totpUri,
  verifyTotp,
} from "../lib/mfa.mjs";

const GENERIC_LOGIN_ERROR = "Username or password is incorrect.";
const CHALLENGE_AGE = 10 * 60 * 1000;

function challengeContext(hash) {
  return `auth-challenge:${hash}`;
}

async function assertSendAllowed(sql, email) {
  const rows = await sql.query(
    `SELECT 1 FROM paisa_auth_challenges
      WHERE lower(email)=lower($1) AND created_at>$2 LIMIT 1`,
    [email, Date.now() - 30_000],
  );
  if (rows.length) {
    const error = new Error("Please wait 30 seconds before requesting another code.");
    error.status = 429;
    throw error;
  }
}

async function emailChallenge(sql, { purpose, email, userId = null, payload }) {
  await assertSendAllowed(sql, email);
  const token = challengeToken();
  const hash = tokenHash(token);
  const code = otpCode();
  const now = Date.now();
  await sql.query(
    `INSERT INTO paisa_auth_challenges
      (token_hash, purpose, user_id, email, encrypted_payload, code_hash,
       attempts, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8)`,
    [
      hash,
      purpose,
      userId,
      email,
      payload ? encryptJson(payload, challengeContext(hash)) : null,
      otpHash(token, code),
      now + CHALLENGE_AGE,
      now,
    ],
  );
  try {
    await sendOtpEmail(email, code, purpose);
  } catch (error) {
    await sql.query("DELETE FROM paisa_auth_challenges WHERE token_hash=$1", [
      hash,
    ]);
    throw error;
  }
  return token;
}

async function totpChallenge(sql, userId) {
  const token = challengeToken();
  const hash = tokenHash(token);
  const now = Date.now();
  await sql.query(
    `INSERT INTO paisa_auth_challenges
      (token_hash, purpose, user_id, attempts, expires_at, created_at)
     VALUES ($1, 'login_totp', $2, 0, $3, $4)`,
    [hash, userId, now + CHALLENGE_AGE, now],
  );
  return token;
}

async function challengeRow(sql, token, purpose) {
  const hash = tokenHash(token);
  const rows = await sql.query(
    `SELECT * FROM paisa_auth_challenges
      WHERE token_hash=$1 AND purpose=$2 AND expires_at>$3 AND attempts<5
      LIMIT 1`,
    [hash, purpose, Date.now()],
  );
  if (!rows.length) {
    const error = new Error("This verification request has expired. Start again.");
    error.status = 401;
    throw error;
  }
  return { row: rows[0], hash };
}

async function rejectCode(sql, hash) {
  await sql.query(
    "UPDATE paisa_auth_challenges SET attempts=attempts+1 WHERE token_hash=$1",
    [hash],
  );
  const error = new Error("The verification code is incorrect.");
  error.status = 401;
  throw error;
}

async function register(sql, req, body) {
  const username = normalizeUsername(body.username);
  const email = normalizeEmail(body.email);
  const password = validatePassword(body.password);
  const duplicate = await sql.query(
    `SELECT 1 FROM paisa_users
      WHERE username=$1 OR lower(email)=lower($2) LIMIT 1`,
    [username, email],
  );
  if (duplicate.length) {
    const error = new Error("That username or email is already in use.");
    error.status = 409;
    throw error;
  }
  const token = await emailChallenge(sql, {
    purpose: "register_email",
    email,
    payload: {
      id: newUserId(),
      username,
      email,
      passwordHash: await hashPassword(password),
      createdAt: Date.now(),
    },
  });
  return { challenge: token, factor: "email", email };
}

async function login(sql, req, body) {
  const username = normalizeUsername(body.username);
  const password = validatePassword(body.password);
  const rows = await sql.query(
    `SELECT id, username, email, email_verified, password_hash,
            failed_login_attempts, locked_until, totp_enabled
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
  if (user.totp_enabled) {
    return {
      challenge: await totpChallenge(sql, user.id),
      factor: "totp",
    };
  }
  if (user.email && user.email_verified) {
    return {
      challenge: await emailChallenge(sql, {
        purpose: "login_email",
        email: user.email,
        userId: user.id,
      }),
      factor: "email",
      email: user.email,
    };
  }
  const cookie = await createSession(sql, user.id, req);
  return { user: { id: user.id, username: user.username }, cookie };
}

async function verifyRegistration(sql, req, body) {
  const token = String(body.challenge || "");
  const { row, hash } = await challengeRow(sql, token, "register_email");
  if (!safeEqual(row.code_hash, otpHash(token, body.code))) {
    await rejectCode(sql, hash);
  }
  const payload = decryptJson(row.encrypted_payload, challengeContext(hash));
  try {
    await sql.transaction([
      sql.query(
        `INSERT INTO paisa_users
          (id, username, email, email_verified, password_hash,
           failed_login_attempts, locked_until, created_at)
         VALUES ($1, $2, $3, true, $4, 0, 0, $5)`,
        [
          payload.id,
          payload.username,
          payload.email,
          payload.passwordHash,
          payload.createdAt,
        ],
      ),
      sql.query("DELETE FROM paisa_auth_challenges WHERE token_hash=$1", [hash]),
    ]);
  } catch (error) {
    if (error.code === "23505") {
      const conflict = new Error("That username or email is already in use.");
      conflict.status = 409;
      throw conflict;
    }
    throw error;
  }
  const cookie = await createSession(sql, payload.id, req);
  return {
    user: {
      id: payload.id,
      username: payload.username,
      email: payload.email,
      emailVerified: true,
      totpEnabled: false,
    },
    cookie,
  };
}

async function verifyLogin(sql, req, body) {
  const token = String(body.challenge || "");
  const factor = body.factor === "totp" ? "totp" : "email";
  const purpose = factor === "totp" ? "login_totp" : "login_email";
  const { row, hash } = await challengeRow(sql, token, purpose);
  const users = await sql.query(
    `SELECT id, username, email, email_verified, totp_enabled, totp_secret,
            backup_code_hashes
       FROM paisa_users WHERE id=$1 LIMIT 1`,
    [row.user_id],
  );
  const user = users[0];
  if (!user) await rejectCode(sql, hash);
  let valid = false;
  let remainingBackupCodes = user.backup_code_hashes || [];
  if (factor === "email") {
    valid = safeEqual(row.code_hash, otpHash(token, body.code));
  } else if (user.totp_enabled && user.totp_secret) {
    const { secret } = decryptJson(user.totp_secret, `totp:${user.id}`);
    valid = verifyTotp(secret, body.code);
    if (!valid) {
      const candidate = backupCodeHash(user.id, body.code);
      const index = remainingBackupCodes.findIndex((value) =>
        safeEqual(value, candidate),
      );
      if (index >= 0) {
        valid = true;
        remainingBackupCodes = remainingBackupCodes.filter(
          (_, codeIndex) => codeIndex !== index,
        );
        await sql.query(
          "UPDATE paisa_users SET backup_code_hashes=$2::jsonb WHERE id=$1",
          [user.id, JSON.stringify(remainingBackupCodes)],
        );
      }
    }
  }
  if (!valid) await rejectCode(sql, hash);
  await sql.query("DELETE FROM paisa_auth_challenges WHERE token_hash=$1", [hash]);
  const cookie = await createSession(sql, user.id, req);
  return {
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      emailVerified: Boolean(user.email_verified),
      totpEnabled: Boolean(user.totp_enabled),
    },
    cookie,
  };
}

async function beginTotp(sql, req, body) {
  const user = await currentUser(sql, req);
  const rows = await sql.query(
    "SELECT password_hash FROM paisa_users WHERE id=$1 LIMIT 1",
    [user.id],
  );
  if (!(await verifyPassword(String(body.currentPassword || ""), rows[0]?.password_hash))) {
    const error = new Error("Your current password is incorrect.");
    error.status = 401;
    throw error;
  }
  const secret = createTotpSecret();
  const uri = totpUri(secret, user.username);
  await sql.query(
    "UPDATE paisa_users SET totp_pending_secret=$2 WHERE id=$1",
    [user.id, encryptJson({ secret }, `totp:${user.id}`)],
  );
  const qrDataUrl = await QRCode.toDataURL(uri, {
    width: 240,
    margin: 1,
    errorCorrectionLevel: "M",
  });
  return { secret, uri, qrDataUrl };
}

async function confirmTotp(sql, req, body) {
  const user = await currentUser(sql, req);
  const rows = await sql.query(
    "SELECT totp_pending_secret FROM paisa_users WHERE id=$1 LIMIT 1",
    [user.id],
  );
  if (!rows[0]?.totp_pending_secret) {
    const error = new Error("Start authenticator setup again.");
    error.status = 400;
    throw error;
  }
  const { secret } = decryptJson(
    rows[0].totp_pending_secret,
    `totp:${user.id}`,
  );
  if (!verifyTotp(secret, body.code)) {
    const error = new Error("The authenticator code is incorrect.");
    error.status = 400;
    throw error;
  }
  const backupCodes = createBackupCodes();
  const hashes = backupCodes.map((code) => backupCodeHash(user.id, code));
  await sql.query(
    `UPDATE paisa_users
        SET totp_secret=totp_pending_secret, totp_pending_secret=NULL,
            totp_enabled=true, backup_code_hashes=$2::jsonb
      WHERE id=$1`,
    [user.id, JSON.stringify(hashes)],
  );
  return { enabled: true, backupCodes };
}

async function beginAddEmail(sql, req, body) {
  const user = await currentUser(sql, req);
  const email = normalizeEmail(body.email);
  const duplicate = await sql.query(
    "SELECT 1 FROM paisa_users WHERE lower(email)=lower($1) AND id<>$2 LIMIT 1",
    [email, user.id],
  );
  if (duplicate.length) {
    const error = new Error("That email is already in use.");
    error.status = 409;
    throw error;
  }
  return {
    challenge: await emailChallenge(sql, {
      purpose: "add_email",
      email,
      userId: user.id,
    }),
    factor: "email",
    email,
  };
}

async function confirmAddEmail(sql, req, body) {
  const user = await currentUser(sql, req);
  const token = String(body.challenge || "");
  const { row, hash } = await challengeRow(sql, token, "add_email");
  if (row.user_id !== user.id) {
    const error = new Error("This verification request is not valid.");
    error.status = 403;
    throw error;
  }
  if (!safeEqual(row.code_hash, otpHash(token, body.code))) {
    await rejectCode(sql, hash);
  }
  await sql.transaction([
    sql.query(
      "UPDATE paisa_users SET email=$2, email_verified=true WHERE id=$1",
      [user.id, row.email],
    ),
    sql.query("DELETE FROM paisa_auth_challenges WHERE token_hash=$1", [hash]),
  ]);
  return { email: row.email, emailVerified: true };
}

async function passwordResetBegin(sql, body) {
  const email = normalizeEmail(body.email);
  const rows = await sql.query(
    `SELECT id FROM paisa_users
      WHERE lower(email)=lower($1) AND email_verified=true LIMIT 1`,
    [email],
  );
  if (!rows.length) {
    return { challenge: challengeToken(), factor: "email", email };
  }
  return {
    challenge: await emailChallenge(sql, {
      purpose: "password_reset",
      email,
      userId: rows[0].id,
    }),
    factor: "email",
    email,
  };
}

async function passwordResetConfirm(sql, req, body) {
  const password = validatePassword(body.newPassword);
  const token = String(body.challenge || "");
  const { row, hash } = await challengeRow(sql, token, "password_reset");
  if (!row.code_hash || !safeEqual(row.code_hash, otpHash(token, body.code))) {
    await rejectCode(sql, hash);
  }
  const users = await sql.query(
    `SELECT id, username, email, email_verified, totp_enabled
       FROM paisa_users WHERE id=$1 LIMIT 1`,
    [row.user_id],
  );
  const user = users[0];
  if (!user) await rejectCode(sql, hash);
  const passwordHash = await hashPassword(password);
  await sql.transaction([
    sql.query(
      `UPDATE paisa_users
          SET password_hash=$2, failed_login_attempts=0, locked_until=0
        WHERE id=$1`,
      [user.id, passwordHash],
    ),
    sql.query("DELETE FROM paisa_sessions WHERE user_id=$1", [user.id]),
    sql.query("DELETE FROM paisa_auth_challenges WHERE user_id=$1", [user.id]),
  ]);
  const cookie = await createSession(sql, user.id, req);
  return {
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      emailVerified: Boolean(user.email_verified),
      totpEnabled: Boolean(user.totp_enabled),
    },
    cookie,
  };
}

async function changePassword(sql, req, body) {
  const user = await currentUser(sql, req);
  const currentPassword = String(body.currentPassword || "");
  const newPassword = validatePassword(body.newPassword);
  const rows = await sql.query(
    "SELECT password_hash FROM paisa_users WHERE id=$1 LIMIT 1",
    [user.id],
  );
  if (!(await verifyPassword(currentPassword, rows[0]?.password_hash))) {
    const error = new Error("Your current password is incorrect.");
    error.status = 401;
    throw error;
  }
  if (await verifyPassword(newPassword, rows[0].password_hash)) {
    const error = new Error("Choose a password different from your current password.");
    error.status = 400;
    throw error;
  }
  await sql.transaction([
    sql.query("UPDATE paisa_users SET password_hash=$2 WHERE id=$1", [
      user.id,
      await hashPassword(newPassword),
    ]),
    sql.query("DELETE FROM paisa_sessions WHERE user_id=$1", [user.id]),
  ]);
  return { changed: true, cookie: await createSession(sql, user.id, req) };
}

async function disableTotp(sql, req, body) {
  const user = await currentUser(sql, req);
  const rows = await sql.query(
    `SELECT password_hash, totp_secret, totp_enabled, backup_code_hashes
       FROM paisa_users WHERE id=$1 LIMIT 1`,
    [user.id],
  );
  const record = rows[0];
  if (!(await verifyPassword(String(body.currentPassword || ""), record?.password_hash))) {
    const error = new Error("Your current password is incorrect.");
    error.status = 401;
    throw error;
  }
  if (!record?.totp_enabled || !record.totp_secret) {
    const error = new Error("Authenticator verification is not enabled.");
    error.status = 400;
    throw error;
  }
  const { secret } = decryptJson(record.totp_secret, `totp:${user.id}`);
  let valid = verifyTotp(secret, body.code);
  if (!valid) {
    const candidate = backupCodeHash(user.id, body.code);
    valid = (record.backup_code_hashes || []).some((value) =>
      safeEqual(value, candidate),
    );
  }
  if (!valid) {
    const error = new Error("The authenticator or recovery code is incorrect.");
    error.status = 401;
    throw error;
  }
  await sql.transaction([
    sql.query(
      `UPDATE paisa_users
          SET totp_secret=NULL, totp_pending_secret=NULL, totp_enabled=false,
              backup_code_hashes='[]'::jsonb
        WHERE id=$1`,
      [user.id],
    ),
    sql.query(
      "DELETE FROM paisa_auth_challenges WHERE user_id=$1 AND purpose='login_totp'",
      [user.id],
    ),
  ]);
  return { enabled: false };
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
        error: "Server setup is incomplete. Add DATA_ENCRYPTION_KEY in Vercel.",
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
    let result;
    let status = 200;
    if (body.action === "register") {
      result = await register(sql, req, body);
      status = 202;
    } else if (body.action === "login") {
      result = await login(sql, req, body);
    } else if (body.action === "verify_registration") {
      result = await verifyRegistration(sql, req, body);
      status = 201;
    } else if (body.action === "verify_login") {
      result = await verifyLogin(sql, req, body);
    } else if (body.action === "password_reset_begin") {
      result = await passwordResetBegin(sql, body);
      status = 202;
    } else if (body.action === "password_reset_confirm") {
      result = await passwordResetConfirm(sql, req, body);
    } else if (body.action === "password_change") {
      result = await changePassword(sql, req, body);
    } else if (body.action === "totp_begin") {
      result = await beginTotp(sql, req, body);
    } else if (body.action === "totp_confirm") {
      result = await confirmTotp(sql, req, body);
    } else if (body.action === "totp_disable") {
      result = await disableTotp(sql, req, body);
    } else if (body.action === "email_begin") {
      result = await beginAddEmail(sql, req, body);
    } else if (body.action === "email_confirm") {
      result = await confirmAddEmail(sql, req, body);
    } else if (body.action === "logout") {
      await destroySession(sql, req);
      return reply(
        res,
        200,
        { signedOut: true },
        { "Set-Cookie": clearSessionCookie() },
      );
    } else {
      return reply(res, 400, { error: "Unknown authentication action." });
    }
    const payload = { ...result };
    delete payload.cookie;
    return reply(
      res,
      status,
      payload,
      result.cookie ? { "Set-Cookie": result.cookie } : {},
    );
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

export {
  beginTotp,
  changePassword,
  disableTotp,
  login,
  passwordResetBegin,
  passwordResetConfirm,
  register,
  verifyLogin,
  verifyRegistration,
};
