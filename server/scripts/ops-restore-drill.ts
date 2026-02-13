import { closeDb } from "../src/db/connection";
import { runMigrations } from "../src/db/migrate";
import { opsBackupService } from "../src/services/ops-backup-service";

async function main(): Promise<void> {
  await runMigrations();
  const backupPath = process.argv[2];
  const result = await opsBackupService.runRestoreDrill({
    backupPath
  });
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(result, null, 2));
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
