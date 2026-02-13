import assert from "node:assert/strict";
import test from "node:test";
import { buildApp } from "../../src/app";
import { closeDb } from "../../src/db/connection";
import { runMigrations } from "../../src/db/migrate";

test("production HTTPS enforcement rejects insecure requests and allows secure proxy requests", async () => {
  await runMigrations();
  const app = buildApp();

  try {
    const insecure = await app.inject({
      method: "GET",
      url: "/health",
      headers: {
        host: "api.example.com"
      }
    });
    assert.equal(insecure.statusCode, 426);
    assert.equal(insecure.json().code, "https_required");

    const secureForwarded = await app.inject({
      method: "GET",
      url: "/health",
      headers: {
        host: "api.example.com",
        "x-forwarded-proto": "https"
      }
    });
    assert.equal(secureForwarded.statusCode, 200);
    assert.equal(secureForwarded.json().status, "ok");

    const localhostBypass = await app.inject({
      method: "GET",
      url: "/health",
      headers: {
        host: "localhost:3000"
      }
    });
    assert.equal(localhostBypass.statusCode, 200);
    assert.equal(localhostBypass.json().status, "ok");
  } finally {
    await app.close();
    await closeDb();
  }
});
