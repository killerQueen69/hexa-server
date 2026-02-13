import { env } from "./config/env";
import { closeDb } from "./db/connection";
import { runMigrations } from "./db/migrate";
import { buildApp } from "./app";

async function start() {
  await runMigrations();

  const app = buildApp();
  app.addHook("onClose", async () => {
    await closeDb();
  });

  await app.listen({
    host: "0.0.0.0",
    port: env.PORT
  });
}

start().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  closeDb()
    .catch(() => undefined)
    .finally(() => {
      process.exit(1);
    });
});
