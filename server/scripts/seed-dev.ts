import bcrypt from "bcrypt";
import { generateKeyPairSync } from "node:crypto";
import { env } from "../src/config/env";
import { closeDb, query, withTransaction } from "../src/db/connection";
import { runMigrations } from "../src/db/migrate";
import { canonicalManifestPayload, signManifestPayload } from "../src/services/ota-manifest-signer";
import { newId, randomClaimCode, randomToken, sha256 } from "../src/utils/crypto";
import { nowIso } from "../src/utils/time";

async function ensureAdminUser(email: string, password: string, name: string): Promise<string> {
  const existing = await query<{ id: string }>(
    `SELECT id
     FROM users
     WHERE email = $1
     LIMIT 1`,
    [email]
  );

  const now = nowIso();
  const passwordHash = await bcrypt.hash(password, env.BCRYPT_ROUNDS);
  if (existing.rowCount && existing.rowCount > 0) {
    const userId = existing.rows[0].id;
    await query(
      `UPDATE users
       SET password_hash = $1,
           role = 'admin',
           is_active = TRUE,
           name = $2,
           updated_at = $3
       WHERE id = $4`,
      [passwordHash, name, now, userId]
    );
    return userId;
  }

  const userId = newId();
  await query(
    `INSERT INTO users (
       id, email, password_hash, name, role, is_active, created_at, updated_at
     ) VALUES ($1, $2, $3, $4, 'admin', TRUE, $5, $6)`,
    [userId, email, passwordHash, name, now, now]
  );
  return userId;
}

async function ensureSampleDevice(params: {
  deviceUid: string;
  hardwareUid: string;
  model: string;
  relayCount: number;
  buttonCount: number;
}): Promise<{ deviceId: string; deviceToken: string; claimCode: string | null }> {
  const now = nowIso();
  const deviceToken = randomToken(32);
  const tokenHash = sha256(deviceToken);

  const existing = await query<{
    id: string;
    owner_user_id: string | null;
    claim_code: string | null;
  }>(
    `SELECT id, owner_user_id, claim_code
     FROM devices
     WHERE device_uid = $1
     LIMIT 1`,
    [params.deviceUid]
  );

  if (existing.rowCount && existing.rowCount > 0) {
    const row = existing.rows[0];
    const nextClaimCode = row.owner_user_id ? null : row.claim_code ?? randomClaimCode(8);
    await query(
      `UPDATE devices
       SET hardware_uid = $1,
           model = $2,
           relay_count = $3,
           button_count = $4,
           device_token_hash = $5,
           claim_code = $6,
           claim_code_created_at = $7,
           updated_at = $8
       WHERE id = $9`,
      [
        params.hardwareUid,
        params.model,
        params.relayCount,
        params.buttonCount,
        tokenHash,
        nextClaimCode,
        nextClaimCode ? now : null,
        now,
        row.id
      ]
    );

    return {
      deviceId: row.id,
      deviceToken,
      claimCode: nextClaimCode
    };
  }

  const deviceId = newId();
  const claimCode = randomClaimCode(8);
  const relayNames = Array.from({ length: params.relayCount }, (_, idx) => `Relay ${idx + 1}`);

  await withTransaction(async (client) => {
    await client.query(
      `INSERT INTO devices (
         id, device_uid, hardware_uid, name, device_token_hash, model,
         relay_count, button_count, relay_names, input_config, power_restore_mode,
         firmware_version, is_active, owner_user_id, claim_code, claim_code_created_at,
         config, ota_channel, ota_security_version, created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6,
         $7, $8, $9::jsonb, '[]'::jsonb, 'last_state',
         $10, TRUE, NULL, $11, $12,
         '{}'::jsonb, 'stable', 0, $13, $14
       )`,
      [
        deviceId,
        params.deviceUid,
        params.hardwareUid,
        "Seed Device",
        tokenHash,
        params.model,
        params.relayCount,
        params.buttonCount,
        JSON.stringify(relayNames),
        "0.0.1",
        claimCode,
        now,
        now,
        now
      ]
    );

    for (let idx = 0; idx < params.relayCount; idx += 1) {
      await client.query(
        `INSERT INTO relay_states (
           id, device_id, relay_index, relay_name, is_on, last_changed_at
         ) VALUES ($1, $2, $3, $4, FALSE, $5)`,
        [newId(), deviceId, idx, relayNames[idx], now]
      );
    }
  });

  return {
    deviceId,
    deviceToken,
    claimCode
  };
}

async function ensureSeedSigningKey(): Promise<{ keyId: string; privateKeyPem: string }> {
  const keyId = "seed-active-key";
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateKeyPem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  process.env.SEED_OTA_PRIVATE_KEY = privateKeyPem;

  await withTransaction(async (client) => {
    await client.query(
      `UPDATE ota_signing_keys
       SET status = 'retired',
           rotated_at = $1,
           updated_at = $1
       WHERE status = 'active'
         AND key_id <> $2`,
      [nowIso(), keyId]
    );

    const existing = await client.query<{ id: string }>(
      `SELECT id
       FROM ota_signing_keys
       WHERE key_id = $1
       LIMIT 1
       FOR UPDATE`,
      [keyId]
    );
    if (existing.rowCount && existing.rowCount > 0) {
      await client.query(
        `UPDATE ota_signing_keys
         SET public_key_pem = $1,
             private_key_secret_ref = $2,
             status = 'active',
             updated_at = $3
         WHERE key_id = $4`,
        [publicKeyPem, "env:SEED_OTA_PRIVATE_KEY", nowIso(), keyId]
      );
      return;
    }

    await client.query(
      `INSERT INTO ota_signing_keys (
         id, key_id, public_key_pem, private_key_secret_ref,
         status, created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4,
         'active', $5, $6
       )`,
      [newId(), keyId, publicKeyPem, "env:SEED_OTA_PRIVATE_KEY", nowIso(), nowIso()]
    );
  });

  return { keyId, privateKeyPem };
}

async function ensureSeedRelease(model: string, allowedHosts: string[], signingKeyId: string, signingPrivateKeyPem: string): Promise<void> {
  const host = allowedHosts[0] ?? "updates.seed.local";
  const version = "1.0.0";
  const url = `https://${host}/firmware/${model}-${version}.bin`;
  const manifestPayload = canonicalManifestPayload({
    version,
    security_version: 1,
    channel: "stable",
    url,
    size_bytes: 150_000,
    sha256: sha256(`${model}-${version}`),
    signature_alg: "ecdsa-p256-sha256",
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  });
  const signature = signManifestPayload(manifestPayload, signingPrivateKeyPem);

  const exists = await query<{ id: string }>(
    `SELECT id
     FROM ota_releases
     WHERE model = $1
       AND version = $2
       AND channel = 'stable'
     LIMIT 1`,
    [model, version]
  );

  if (exists.rowCount && exists.rowCount > 0) {
    await query(
      `UPDATE ota_releases
       SET is_active = TRUE,
           url = $1,
           security_version = $2,
           size_bytes = $3,
           sha256 = $4,
           signature_alg = 'ecdsa-p256-sha256',
           signature = $5,
           verification_key_id = $6,
           next_verification_key_id = NULL,
           manifest_payload = $7::jsonb,
           expires_at = $8,
           updated_at = $9
       WHERE id = $10`,
      [
        url,
        manifestPayload.security_version,
        manifestPayload.size_bytes,
        manifestPayload.sha256,
        signature,
        signingKeyId,
        JSON.stringify(manifestPayload),
        manifestPayload.expires_at,
        nowIso(),
        exists.rows[0].id
      ]
    );
    return;
  }

  await query(
      `INSERT INTO ota_releases (
       id, model, version, security_version, channel, url, size_bytes, sha256,
       signature_alg, signature, verification_key_id, next_verification_key_id,
       manifest_payload, expires_at, is_active, metadata, created_at, updated_at
     ) VALUES (
       $1, $2, $3, $4, 'stable', $5, $6, $7,
       $8, $9, $10, NULL, $11::jsonb, $12, TRUE, $13::jsonb, $14, $15
     )`,
    [
      newId(),
      model,
      version,
      manifestPayload.security_version,
      url,
      manifestPayload.size_bytes,
      manifestPayload.sha256,
      "ecdsa-p256-sha256",
      signature,
      signingKeyId,
      JSON.stringify(manifestPayload),
      manifestPayload.expires_at,
      JSON.stringify({ seed: true }),
      nowIso(),
      nowIso()
    ]
  );
}

async function main(): Promise<void> {
  const adminEmail = (process.env.SEED_ADMIN_EMAIL ?? "admin@hexa.local").trim().toLowerCase();
  const adminPassword = process.env.SEED_ADMIN_PASSWORD ?? "AdminPass!234";
  const adminName = process.env.SEED_ADMIN_NAME ?? "Hexa Admin";
  const deviceUid = process.env.SEED_DEVICE_UID ?? "hexa-seed-001";
  const hardwareUid = process.env.SEED_HARDWARE_UID ?? "seed-hw-001";
  const model = process.env.SEED_DEVICE_MODEL ?? "hexa-mini-switch-v1";

  await runMigrations();

  const adminUserId = await ensureAdminUser(adminEmail, adminPassword, adminName);
  const seededDevice = await ensureSampleDevice({
    deviceUid,
    hardwareUid,
    model,
    relayCount: 3,
    buttonCount: 3
  });
  const signingKey = await ensureSeedSigningKey();
  await ensureSeedRelease(model, env.OTA_ALLOWED_HOSTS, signingKey.keyId, signingKey.privateKeyPem);

  // eslint-disable-next-line no-console
  console.log("Seed complete.");
  // eslint-disable-next-line no-console
  console.log(`Admin email: ${adminEmail}`);
  // eslint-disable-next-line no-console
  console.log(`Admin password: ${adminPassword}`);
  // eslint-disable-next-line no-console
  console.log(`Admin user id: ${adminUserId}`);
  // eslint-disable-next-line no-console
  console.log(`Device UID: ${deviceUid}`);
  // eslint-disable-next-line no-console
  console.log(`Device token: ${seededDevice.deviceToken}`);
  // eslint-disable-next-line no-console
  console.log(`Claim code (if unclaimed): ${seededDevice.claimCode ?? "already claimed"}`);
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
