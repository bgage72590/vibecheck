import { db } from "./client.js";
import { sql } from "drizzle-orm";

export async function runMigrations() {
  await db.run(sql`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      created_at INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    )
  `);

  await db.run(sql`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id),
      directory TEXT NOT NULL,
      files_scanned INTEGER NOT NULL,
      findings_count INTEGER NOT NULL,
      critical_count INTEGER NOT NULL DEFAULT 0,
      high_count INTEGER NOT NULL DEFAULT 0,
      medium_count INTEGER NOT NULL DEFAULT 0,
      low_count INTEGER NOT NULL DEFAULT 0,
      duration INTEGER NOT NULL,
      findings TEXT,
      created_at INTEGER NOT NULL DEFAULT (unixepoch())
    )
  `);

  await db.run(sql`
    CREATE TABLE IF NOT EXISTS daily_usage (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      date TEXT NOT NULL,
      scan_count INTEGER NOT NULL DEFAULT 0
    )
  `);

  await db.run(sql`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_daily_usage_user_date
    ON daily_usage(user_id, date)
  `);

  console.log("Migrations complete");
}
