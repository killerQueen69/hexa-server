import assert from "node:assert/strict";
import test from "node:test";
import { AddressInfo } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import bcrypt from "bcrypt";
import { buildApp } from "../../src/app";
import { env } from "../../src/config/env";
import { closeDb, query } from "../../src/db/connection";
import { runMigrations } from "../../src/db/migrate";
import { newId, sha256 } from "../../src/utils/crypto";
import { nowIso } from "../../src/utils/time";

type JsonObject = Record<string, unknown>;

async function requestJson(
  url: string,
  init?: RequestInit
): Promise<{ status: number; body: JsonObject }> {
  const response = await fetch(url, init);
  const text = await response.text();
  return {
    status: response.status,
    body: text.length > 0 ? (JSON.parse(text) as JsonObject) : {}
  };
}

test("e2e smoke: admin ops + ota signing", async () => {
  await runMigrations();
  const app = buildApp();
  await app.listen({ host: "127.0.0.1", port: 0 });

  const address = app.server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const adminEmail = `smoke-admin-${newId()}@example.com`;
    const adminPassword = "SmokePass!234";
    const passwordHash = await bcrypt.hash(adminPassword, env.BCRYPT_ROUNDS);
    await query(
      `INSERT INTO users (
         id, email, password_hash, name, role, is_active, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, 'admin', TRUE, $5, $6)`,
      [newId(), adminEmail, passwordHash, "Smoke Admin", nowIso(), nowIso()]
    );

    const login = await requestJson(`${baseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: adminEmail,
        password: adminPassword
      })
    });
    assert.equal(login.status, 200);
    const accessToken = String(login.body.access_token);
    assert.ok(accessToken.length > 10);

    const authHeaders = {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`
    };

    const dashboardPage = await fetch(`${baseUrl}/dashboard`);
    const dashboardHtml = await dashboardPage.text();
    assert.equal(dashboardPage.status, 200);
    assert.equal(dashboardHtml.includes("Hexa Admin"), true);

    const overview = await requestJson(`${baseUrl}/api/v1/admin/overview`, {
      method: "GET",
      headers: authHeaders
    });
    assert.equal(overview.status, 200);

    const alerts = await requestJson(`${baseUrl}/api/v1/admin/ops/alerts/simulate`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({})
    });
    assert.equal(alerts.status, 200);
    assert.ok(Array.isArray(alerts.body.alerts));

    const backupRun = await requestJson(`${baseUrl}/api/v1/admin/ops/backup/run`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({})
    });
    assert.equal(backupRun.status, 201);
    assert.equal(typeof backupRun.body.backup_path, "string");

    const restoreDrill = await requestJson(`${baseUrl}/api/v1/admin/ops/restore-drill/run`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({})
    });
    assert.equal(restoreDrill.status, 201);
    assert.equal(restoreDrill.body.rto_target_met, true);

    await query(
      `UPDATE ota_signing_keys
       SET status = 'retired',
           rotated_at = $1,
           updated_at = $1
       WHERE status IN ('active', 'next')`,
      [nowIso()]
    );

    const activeKeyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const activePublicPem = activeKeyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const activePrivatePem = activeKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    process.env.SMOKE_OTA_ACTIVE_PRIVATE_KEY = activePrivatePem;

    const nextKeyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const nextPublicPem = nextKeyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const nextPrivatePem = nextKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    process.env.SMOKE_OTA_NEXT_PRIVATE_KEY = nextPrivatePem;

    const activeKeyId = `smoke-active-${Date.now()}`;
    const activeKey = await requestJson(`${baseUrl}/api/v1/ota/signing-keys`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        key_id: activeKeyId,
        public_key_pem: activePublicPem,
        private_key_secret_ref: "env:SMOKE_OTA_ACTIVE_PRIVATE_KEY",
        status: "active"
      })
    });
    assert.equal(activeKey.status, 201);

    const nextKeyId = `smoke-next-${Date.now()}`;
    const nextKey = await requestJson(`${baseUrl}/api/v1/ota/signing-keys`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        key_id: nextKeyId,
        public_key_pem: nextPublicPem,
        private_key_secret_ref: "env:SMOKE_OTA_NEXT_PRIVATE_KEY",
        status: "next"
      })
    });
    assert.equal(nextKey.status, 201);

    const version = `9.${Math.floor(Date.now() / 1000)}.0`;
    const release = await requestJson(`${baseUrl}/api/v1/ota/releases`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        model: "hexa-mini-switch-v1",
        version,
        security_version: 1,
        channel: "stable",
        url: `https://updates.smoke.local/${version}.bin`,
        size_bytes: 234567,
        sha256: sha256(`smoke-${version}`),
        expires_at: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
        is_active: true,
        metadata: {
          smoke: true
        },
        auto_sign: true
      })
    });
    assert.equal(release.status, 201);
    assert.equal(release.body.verification_key_id, activeKeyId);
    assert.equal(release.body.next_verification_key_id, nextKeyId);

    const uploadVersion = `9.${Math.floor(Date.now() / 1000)}.9`;
    const uploadPayload = `smoke-upload-${uploadVersion}`;
    const uploadForm = new FormData();
    uploadForm.set(
      "firmware",
      new Blob([uploadPayload], { type: "application/octet-stream" }),
      `hexa-mini-switch-v1-${uploadVersion}-stable.bin`
    );
    uploadForm.set("model", "hexa-mini-switch-v1");
    uploadForm.set("version", uploadVersion);
    uploadForm.set("channel", "stable");
    uploadForm.set("security_version", "1");
    uploadForm.set("auto_sign", "true");

    const uploadResponse = await fetch(`${baseUrl}/api/v1/ota/releases/upload`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`
      },
      body: uploadForm
    });
    const uploadText = await uploadResponse.text();
    const uploadBody = uploadText.length > 0 ? (JSON.parse(uploadText) as JsonObject) : {};

    assert.equal(uploadResponse.status, 201);
    assert.equal(uploadBody.model, "hexa-mini-switch-v1");
    assert.equal(uploadBody.version, uploadVersion);
    assert.equal(uploadBody.sha256, sha256(uploadPayload));

    const artifactUrl = String(uploadBody.url || "");
    const artifactResponse = await fetch(artifactUrl);
    assert.equal(artifactResponse.status, 200);
    const artifactBytes = await artifactResponse.arrayBuffer();
    assert.equal(Buffer.from(artifactBytes).toString("utf8"), uploadPayload);

    const rollbackCandidate = await requestJson(`${baseUrl}/api/v1/ota/releases`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        model: "hexa-mini-switch-v1",
        version: `9.${Math.floor(Date.now() / 1000)}.1`,
        security_version: 0,
        channel: "stable",
        url: `https://updates.smoke.local/${version}-rollback.bin`,
        size_bytes: 234567,
        sha256: sha256(`smoke-rollback-${version}`),
        expires_at: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
        is_active: true,
        metadata: {
          rollback: true
        },
        auto_sign: true
      })
    });
    assert.equal(rollbackCandidate.status, 409);

    const verify = await requestJson(`${baseUrl}/api/v1/ota/releases/${release.body.id as string}/verify`, {
      method: "GET",
      headers: authHeaders
    });
    assert.equal(verify.status, 200);
    assert.equal(verify.body.ok, true);

    const rotate = await requestJson(`${baseUrl}/api/v1/ota/signing-keys/rotate`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({})
    });
    assert.equal(rotate.status, 200);
    assert.equal((rotate.body.active_key as JsonObject).key_id, nextKeyId);
  } finally {
    await app.close();
    await closeDb();
  }
});
