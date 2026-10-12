import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
} from "node:crypto";

function encryptionKey() {
  const value = String(process.env.DATA_ENCRYPTION_KEY || "").trim();
  if (!value) {
    const error = new Error(
      "Server setup is incomplete. Add DATA_ENCRYPTION_KEY in Vercel.",
    );
    error.status = 503;
    throw error;
  }
  let key;
  if (/^[a-f0-9]{64}$/i.test(value)) key = Buffer.from(value, "hex");
  else {
    try {
      key = Buffer.from(value, "base64url");
    } catch {
      key = Buffer.alloc(0);
    }
  }
  if (key.length !== 32) {
    const error = new Error("DATA_ENCRYPTION_KEY must contain exactly 32 bytes.");
    error.status = 503;
    throw error;
  }
  return key;
}

export function encryptJson(value, context) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  cipher.setAAD(Buffer.from(String(context)));
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return ["v1", iv, tag, encrypted]
    .map((part) =>
      Buffer.isBuffer(part) ? part.toString("base64url") : part,
    )
    .join(".");
}

export function decryptJson(value, context) {
  const [version, ivValue, tagValue, encryptedValue] = String(value).split(".");
  if (version !== "v1" || !ivValue || !tagValue || !encryptedValue) {
    throw new Error("Encrypted record format is invalid.");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(ivValue, "base64url"),
  );
  decipher.setAAD(Buffer.from(String(context)));
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encryptedValue, "base64url")),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(plaintext);
}

export function blindIndex(value, purpose = "index") {
  const derived = createHmac("sha256", encryptionKey())
    .update(`paisa:${purpose}`)
    .digest();
  return createHmac("sha256", derived).update(String(value)).digest("hex");
}

export function keyFingerprint() {
  return createHash("sha256")
    .update(encryptionKey())
    .digest("hex")
    .slice(0, 16);
}
