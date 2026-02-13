import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import bcrypt from "bcrypt";
import { buildApp } from "../../src/app";
import { env } from "../../src/config/env";
import { closeDb, query } from "../../src/db/connection";
import { runMigrations } from "../../src/db/migrate";
import {
  canonicalManifestPayload,
  canonicalManifestString,
  signManifestPayload,
  verifyManifestSignature
} from "../../src/services/ota-manifest-signer";
import { newId } from "../../src/utils/crypto";
import { nowIso } from "../../src/utils/time";

test("ota manifest signer: canonical payload and verify", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  const payload = canonicalManifestPayload({
    version: "1.2.3",
    security_version: 7,
    channel: "stable",
    url: "https://updates.example.com/fw.bin",
    size_bytes: 123456,
    sha256: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
    signature_alg: "ecdsa-p256-sha256",
    expires_at: "2026-12-31T00:00:00.000Z"
  });

  const canonical = canonicalManifestString(payload);
  assert.ok(canonical.includes("\"channel\":\"stable\""));
  assert.ok(canonical.includes("\"security_version\":7"));

  const signature = signManifestPayload(payload, privatePem);
  assert.ok(signature.length > 20);
  assert.equal(verifyManifestSignature(payload, signature, publicPem), true);
  assert.equal(
    verifyManifestSignature(
      {
        ...payload,
        security_version: payload.security_version + 1
      },
      signature,
      publicPem
    ),
    false
  );
});

test("auth + RBAC device CRUD and default device shape", async () => {
  await runMigrations();
  const app = buildApp();

  try {
    const userEmail = `unit-user-${newId()}@example.com`;
    const userPassword = "UnitUserPass!234";
    const register = await app.inject({
      method: "POST",
      url: "/api/v1/auth/register",
      payload: {
        email: userEmail,
        password: userPassword,
        name: "Unit User"
      }
    });
    assert.equal(register.statusCode, 201);
    const registerBody = register.json();
    assert.equal(typeof registerBody.access_token, "string");
    assert.equal(typeof registerBody.refresh_token, "string");

    const login = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        email: userEmail,
        password: userPassword
      }
    });
    assert.equal(login.statusCode, 200);
    const userLoginBody = login.json();
    const userAccessToken = String(userLoginBody.access_token);
    const userRefreshToken = String(userLoginBody.refresh_token);

    const refresh = await app.inject({
      method: "POST",
      url: "/api/v1/auth/refresh",
      payload: {
        refresh_token: userRefreshToken
      }
    });
    assert.equal(refresh.statusCode, 200);
    assert.equal(typeof refresh.json().access_token, "string");

    const logout = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      payload: {
        refresh_token: userRefreshToken
      }
    });
    assert.equal(logout.statusCode, 200);

    const adminEmail = `unit-admin-${newId()}@example.com`;
    const adminPassword = "UnitAdminPass!234";
    const adminHash = await bcrypt.hash(adminPassword, env.BCRYPT_ROUNDS);
    await query(
      `INSERT INTO users (
         id, email, password_hash, name, role, is_active, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, 'admin', TRUE, $5, $6)`,
      [newId(), adminEmail, adminHash, "Unit Admin", nowIso(), nowIso()]
    );

    const adminLogin = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        email: adminEmail,
        password: adminPassword
      }
    });
    assert.equal(adminLogin.statusCode, 200);
    const adminAccessToken = String(adminLogin.json().access_token);

    const adminCreateDevice = await app.inject({
      method: "POST",
      url: "/api/v1/devices",
      headers: {
        authorization: `Bearer ${adminAccessToken}`
      },
      payload: {
        device_uid: `unit-dev-${newId()}`,
        name: "Unit Device",
        model: "hexa-mini-switch-v1"
      }
    });
    assert.equal(adminCreateDevice.statusCode, 201);
    const adminCreateBody = adminCreateDevice.json();
    assert.equal(adminCreateBody.device.relay_count, 3);
    assert.equal(adminCreateBody.device.button_count, 3);
    assert.deepEqual(adminCreateBody.device.input_config, []);
    const createdDeviceId = String(adminCreateBody.device.id);

    const userCreateDevice = await app.inject({
      method: "POST",
      url: "/api/v1/devices",
      headers: {
        authorization: `Bearer ${userAccessToken}`
      },
      payload: {
        device_uid: `unit-dev-user-${newId()}`,
        name: "User Device",
        model: "hexa-mini-switch-v1"
      }
    });
    assert.equal(userCreateDevice.statusCode, 403);

    const userDeleteDevice = await app.inject({
      method: "DELETE",
      url: `/api/v1/devices/${createdDeviceId}`,
      headers: {
        authorization: `Bearer ${userAccessToken}`
      }
    });
    assert.equal(userDeleteDevice.statusCode, 403);

    const adminDeleteDevice = await app.inject({
      method: "DELETE",
      url: `/api/v1/devices/${createdDeviceId}`,
      headers: {
        authorization: `Bearer ${adminAccessToken}`
      }
    });
    assert.equal(adminDeleteDevice.statusCode, 200);
  } finally {
    await app.close();
    await closeDb();
  }
});
