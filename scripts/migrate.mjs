import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { neon } from "@neondatabase/serverless";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required to apply the Paisa schema.");
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
const source = await readFile(resolve(here, "../db/schema.sql"), "utf8");
const statements = source
  .split("-- statement-breakpoint")
  .map((part) => part.trim())
  .filter(Boolean);
const sql = neon(process.env.DATABASE_URL);
for (const statement of statements) await sql.query(statement);
console.log(
  `Paisa database schema is ready (${statements.length} statements).`,
);
