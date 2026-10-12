import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { blindIndex } from "./crypto.mjs";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)
  ) {
    const error = new Error("Enter a valid email address.");
    error.status = 400;
    throw error;
  }
  return email;
}

export function challengeToken() {
  return randomBytes(32).toString("base64url");
}

export function tokenHash(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

export function otpCode() {
  return String(randomBytes(4).readUInt32BE() % 1_000_000).padStart(6, "0");
}

export function otpHash(token, code) {
  return blindIndex(`${token}:${String(code)}`, "email-otp");
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function sendOtpEmail(email, code, purpose) {
  const apiKey = String(process.env.BREVO_API_KEY || "");
  const senderEmail = String(process.env.OTP_FROM_EMAIL || "");
  if (!apiKey || !senderEmail) {
    const error = new Error(
      "Email verification is not configured. Add BREVO_API_KEY and OTP_FROM_EMAIL in Vercel.",
    );
    error.status = 503;
    throw error;
  }
  const label =
    purpose === "login_email"
      ? "sign in"
      : purpose === "password_reset"
        ? "reset your password"
        : "verify your email";
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": apiKey,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: {
        name: String(process.env.OTP_FROM_NAME || "Paisa"),
        email: senderEmail,
      },
      to: [{ email }],
      subject: `Your Paisa verification code: ${code}`,
      textContent: `Use ${code} to ${label}. It expires in 10 minutes. If you did not request this, ignore this email.`,
      htmlContent: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px"><h2>Paisa verification</h2><p>Use this code to ${label}:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in 10 minutes. If you did not request it, ignore this email.</p></div>`,
    }),
  });
  if (!response.ok) {
    const error = new Error("The verification email could not be sent.");
    error.status = 502;
    throw error;
  }
}

export function createTotpSecret() {
  const bytes = randomBytes(20);
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let index = 0; index < bits.length; index += 5) {
    output += BASE32[Number.parseInt(bits.slice(index, index + 5).padEnd(5, "0"), 2)];
  }
  return output;
}

function decodeBase32(value) {
  const cleaned = String(value).replace(/=+$/g, "").toUpperCase();
  let bits = "";
  for (const character of cleaned) {
    const index = BASE32.indexOf(character);
    if (index < 0) throw new Error("Authenticator secret is invalid.");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function totpAt(secret, counter) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret))
    .update(message)
    .digest();
  const offset = digest[digest.length - 1] & 15;
  const number =
    (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(number).padStart(6, "0");
}

export function verifyTotp(secret, code, now = Date.now()) {
  if (!/^\d{6}$/.test(String(code))) return false;
  const counter = Math.floor(now / 30_000);
  return [-1, 0, 1].some((offset) =>
    safeEqual(totpAt(secret, counter + offset), code),
  );
}

export function totpUri(secret, username) {
  const issuer = "Paisa";
  const label = encodeURIComponent(`${issuer}:${username}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function createBackupCodes() {
  return Array.from({ length: 8 }, () => {
    const value = randomBytes(5).toString("hex").toUpperCase();
    return `${value.slice(0, 5)}-${value.slice(5)}`;
  });
}

export function backupCodeHash(userId, code) {
  return blindIndex(
    `${userId}:${String(code).replace(/[^a-z0-9]/gi, "").toUpperCase()}`,
    "backup-code",
  );
}
