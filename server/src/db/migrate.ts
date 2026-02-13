import fs from "node:fs";
import path from "node:path";
import { closeDb, withTransaction } from "./connection";

const MIGRATIONS_TABLE = "schema_migrations";

function getMigrationsDir(): string {
  const candidates = [
    path.resolve(process.cwd(), "src/db/migrations"),
    path.resolve(process.cwd(), "dist/db/migrations")
  ];

  for (const dir of candidates) {
    if (fs.existsSync(dir)) {
      return dir;
    }
  }

  throw new Error("Migration directory not found.");
}

export async function runMigrations(): Promise<void> {
  await withTransaction(async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE} (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
  });

  const migrationsDir = getMigrationsDir();
  const files = fs
    .readdirSync(migrationsDir)
    .filter((name) => name.endsWith(".sql"))
    .sort((a, b) => a.localeCompare(b));

  for (const file of files) {
    // Each migration is applied in its own transaction for atomicity.
    await withTransaction(async (client) => {
      const existing = await client.query<{ id: number }>(
        `SELECT id FROM ${MIGRATIONS_TABLE} WHERE name = $1 LIMIT 1`,
        [file]
      );
      if (existing.rowCount && existing.rowCount > 0) {
        return;
      }

      const sql = fs.readFileSync(path.join(migrationsDir, file), "utf8");
      await client.query(sql);
      await client.query(
        `INSERT INTO ${MIGRATIONS_TABLE} (name) VALUES ($1)`,
        [file]
      );
    });
  }
}

if (require.main === module) {
  runMigrations()
    .then(() => {
      // eslint-disable-next-line no-console
      console.log("Migrations completed.");
    })
    .finally(async () => {
      await closeDb();
    });
}
