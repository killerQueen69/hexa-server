import { closeDb, query } from "../src/db/connection";
import { runMigrations } from "../src/db/migrate";

async function main(): Promise<void> {
  await runMigrations();

  await query("DROP SCHEMA IF EXISTS public CASCADE");
  await query("CREATE SCHEMA public");
  await query("GRANT ALL ON SCHEMA public TO public");

  await runMigrations();
  // eslint-disable-next-line no-console
  console.log("Migration smoke (down/up) completed.");
}

main()
  .catch((error) => {
    // eslint-disable-next-line no-console
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDb();
  });
