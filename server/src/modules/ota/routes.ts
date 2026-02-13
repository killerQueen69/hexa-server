import { FastifyInstance } from "fastify";
import semver from "semver";
import { z } from "zod";
import { env } from "../../config/env";
import { query, withTransaction } from "../../db/connection";
import { authenticate, requireRole } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import { realtimeHub } from "../../realtime/hub";
import {
  OtaManifestPayload,
  canonicalManifestPayload,
  signManifestPayload,
  verifyManifestSignature
} from "../../services/ota-manifest-signer";
import { secretManager } from "../../services/secret-manager";
import { newId, sha256 } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type OtaChannel = "dev" | "beta" | "stable";

type DeviceOtaRow = {
  id: string;
  device_uid: string;
  model: string;
  firmware_version: string | null;
  ota_channel: OtaChannel;
  ota_security_version: number;
  owner_user_id: string | null;
  device_token_hash: string;
};

type OtaReleaseRow = {
  id: string;
  model: string;
  version: string;
  security_version: number;
  channel: OtaChannel;
  url: string;
  size_bytes: string | number;
  sha256: string;
  signature_alg: "ecdsa-p256-sha256";
  signature: string;
  verification_key_id: string | null;
  next_verification_key_id: string | null;
  manifest_payload: unknown;
  expires_at: Date | string;
  is_active: boolean;
  metadata: unknown;
  created_at: Date | string;
  updated_at: Date | string;
};

type OtaSigningKeyRow = {
  id: string;
  key_id: string;
  public_key_pem: string;
  private_key_secret_ref: string;
  status: "active" | "next" | "retired";
  created_at: Date | string;
  updated_at: Date | string;
  rotated_at: Date | string | null;
};

type ReleaseIntegrityResult = {
  ok: boolean;
  reason?: string;
  manifest?: OtaManifestPayload;
};

const otaChannelSchema = z.enum(["dev", "beta", "stable"]);
const signatureAlgSchema = z.literal("ecdsa-p256-sha256");

const createReleaseSchema = z.object({
  model: z.string().min(1).max(100),
  version: z.string().min(1).max(50),
  security_version: z.number().int().min(0),
  channel: otaChannelSchema,
  url: z.string().url(),
  size_bytes: z.number().int().positive(),
  sha256: z.string().regex(/^[a-fA-F0-9]{64}$/),
  expires_at: z.string().datetime(),
  is_active: z.boolean().default(true),
  metadata: z.record(z.unknown()).default({}),
  auto_sign: z.boolean().default(true),
  signature: z.string().min(16).optional(),
  verification_key_id: z.string().min(1).optional(),
  next_verification_key_id: z.string().min(1).nullable().optional(),
  signature_alg: signatureAlgSchema.default("ecdsa-p256-sha256")
});

const updateReleaseSchema = z.object({
  security_version: z.number().int().min(0).optional(),
  channel: otaChannelSchema.optional(),
  url: z.string().url().optional(),
  size_bytes: z.number().int().positive().optional(),
  sha256: z.string().regex(/^[a-fA-F0-9]{64}$/).optional(),
  expires_at: z.string().datetime().optional(),
  is_active: z.boolean().optional(),
  metadata: z.record(z.unknown()).optional(),
  auto_sign: z.boolean().optional(),
  re_sign: z.boolean().optional(),
  signature: z.string().min(16).optional(),
  verification_key_id: z.string().min(1).optional(),
  next_verification_key_id: z.string().min(1).nullable().optional(),
  signature_alg: signatureAlgSchema.optional()
});

const createSigningKeySchema = z.object({
  key_id: z.string().min(3).max(120).regex(/^[a-zA-Z0-9._-]+$/),
  public_key_pem: z.string().min(40),
  private_key_secret_ref: z.string().min(1).max(500),
  status: z.enum(["active", "next", "retired"]).default("retired")
});

const updateSigningKeySchema = z.object({
  public_key_pem: z.string().min(40).optional(),
  private_key_secret_ref: z.string().min(1).max(500).optional(),
  status: z.enum(["active", "next", "retired"]).optional()
});

const otaCheckQuerySchema = z.object({
  device_uid: z.string().min(1),
  current: z.string().min(1),
  channel: otaChannelSchema.optional(),
  token: z.string().min(16).optional()
});

const otaManifestQuerySchema = z.object({
  channel: otaChannelSchema.optional(),
  token: z.string().min(16).optional(),
  current: z.string().min(1).optional()
});

const otaReportSchema = z.object({
  device_uid: z.string().min(1),
  device_token: z.string().min(16),
  event_type: z.enum(["check", "download", "verify", "install", "rollback", "success", "failure", "boot_ok"]),
  status: z.enum(["ok", "error", "in_progress", "rejected"]),
  from_version: z.string().max(100).optional(),
  to_version: z.string().max(100).optional(),
  security_version: z.number().int().min(0).optional(),
  reason: z.string().max(500).optional(),
  details: z.record(z.unknown()).default({})
});

const manifestPayloadSchema = z.object({
  version: z.string().min(1),
  security_version: z.number().int().min(0),
  channel: otaChannelSchema,
  url: z.string().url(),
  size_bytes: z.number().int().positive(),
  sha256: z.string().regex(/^[a-fA-F0-9]{64}$/),
  signature_alg: signatureAlgSchema,
  expires_at: z.string().datetime()
});

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function ensureValidSemver(version: string): void {
  if (!semver.valid(version)) {
    throw new Error("invalid_version");
  }
}

function isAllowedArtifactHost(urlString: string): boolean {
  const allowedHosts = env.OTA_ALLOWED_HOSTS;
  if (allowedHosts.length === 0) {
    return true;
  }

  try {
    const url = new URL(urlString);
    if (url.protocol !== "https:") {
      return false;
    }
    return allowedHosts.includes(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function serializeSigningKey(row: OtaSigningKeyRow) {
  return {
    id: row.id,
    key_id: row.key_id,
    public_key_pem: row.public_key_pem,
    status: row.status,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    rotated_at: row.rotated_at ? toIso(row.rotated_at) : null
  };
}

function serializeRelease(row: OtaReleaseRow) {
  return {
    id: row.id,
    model: row.model,
    version: row.version,
    security_version: row.security_version,
    channel: row.channel,
    url: row.url,
    size_bytes: typeof row.size_bytes === "string" ? Number(row.size_bytes) : row.size_bytes,
    sha256: row.sha256,
    signature_alg: row.signature_alg,
    signature: row.signature,
    verification_key_id: row.verification_key_id,
    next_verification_key_id: row.next_verification_key_id,
    manifest_payload: asObject(row.manifest_payload),
    expires_at: toIso(row.expires_at),
    is_active: row.is_active,
    metadata: asObject(row.metadata),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function buildManifestPayload(input: {
  version: string;
  security_version: number;
  channel: OtaChannel;
  url: string;
  size_bytes: number;
  sha256: string;
  expires_at: string;
}): OtaManifestPayload {
  return canonicalManifestPayload({
    version: input.version,
    security_version: input.security_version,
    channel: input.channel,
    url: input.url,
    size_bytes: input.size_bytes,
    sha256: input.sha256.toLowerCase(),
    signature_alg: "ecdsa-p256-sha256",
    expires_at: input.expires_at
  });
}

function manifestFromReleaseRow(row: OtaReleaseRow): OtaManifestPayload {
  const candidate = manifestPayloadSchema.safeParse(row.manifest_payload);
  if (candidate.success) {
    return canonicalManifestPayload(candidate.data);
  }

  return buildManifestPayload({
    version: row.version,
    security_version: row.security_version,
    channel: row.channel,
    url: row.url,
    size_bytes: typeof row.size_bytes === "string" ? Number(row.size_bytes) : row.size_bytes,
    sha256: row.sha256,
    expires_at: toIso(row.expires_at)
  });
}

function releaseMatchesManifest(row: OtaReleaseRow, manifest: OtaManifestPayload): boolean {
  const size = typeof row.size_bytes === "string" ? Number(row.size_bytes) : row.size_bytes;
  return (
    row.version === manifest.version &&
    row.security_version === manifest.security_version &&
    row.channel === manifest.channel &&
    row.url === manifest.url &&
    size === manifest.size_bytes &&
    row.sha256.toLowerCase() === manifest.sha256.toLowerCase() &&
    row.signature_alg === manifest.signature_alg &&
    toIso(row.expires_at) === manifest.expires_at
  );
}

async function findDevice(deviceUid: string): Promise<DeviceOtaRow | null> {
  const result = await query<DeviceOtaRow>(
    `SELECT
       id, device_uid, model, firmware_version, ota_channel, ota_security_version,
       owner_user_id, device_token_hash
     FROM devices
     WHERE device_uid = $1
       AND is_active = TRUE
     LIMIT 1`,
    [deviceUid]
  );
  return result.rows[0] ?? null;
}

async function loadSigningKeys(): Promise<Map<string, OtaSigningKeyRow>> {
  const result = await query<OtaSigningKeyRow>(
    `SELECT
       id, key_id, public_key_pem, private_key_secret_ref,
       status, created_at, updated_at, rotated_at
     FROM ota_signing_keys`
  );
  const map = new Map<string, OtaSigningKeyRow>();
  for (const row of result.rows) {
    map.set(row.key_id, row);
  }
  return map;
}

async function getSigningKeyByStatus(status: "active" | "next" | "retired"): Promise<OtaSigningKeyRow | null> {
  const result = await query<OtaSigningKeyRow>(
    `SELECT
       id, key_id, public_key_pem, private_key_secret_ref,
       status, created_at, updated_at, rotated_at
     FROM ota_signing_keys
     WHERE status = $1
     LIMIT 1`,
    [status]
  );
  return result.rows[0] ?? null;
}

async function getSigningKeyByKeyId(keyId: string): Promise<OtaSigningKeyRow | null> {
  const result = await query<OtaSigningKeyRow>(
    `SELECT
       id, key_id, public_key_pem, private_key_secret_ref,
       status, created_at, updated_at, rotated_at
     FROM ota_signing_keys
     WHERE key_id = $1
     LIMIT 1`,
    [keyId]
  );
  return result.rows[0] ?? null;
}

async function verifyReleaseIntegrity(
  row: OtaReleaseRow,
  signingKeyMap?: Map<string, OtaSigningKeyRow>
): Promise<ReleaseIntegrityResult> {
  if (!isAllowedArtifactHost(row.url)) {
    return {
      ok: false,
      reason: "ota_host_blocked"
    };
  }
  if (row.signature_alg !== "ecdsa-p256-sha256") {
    return {
      ok: false,
      reason: "signature_algorithm_invalid"
    };
  }
  if (!row.verification_key_id) {
    return {
      ok: false,
      reason: "verification_key_missing"
    };
  }

  const manifest = manifestFromReleaseRow(row);
  if (!releaseMatchesManifest(row, manifest)) {
    return {
      ok: false,
      reason: "manifest_mismatch"
    };
  }

  const keyMap = signingKeyMap ?? (await loadSigningKeys());
  const verificationKey = keyMap.get(row.verification_key_id);
  if (!verificationKey) {
    return {
      ok: false,
      reason: "verification_key_not_found"
    };
  }
  if (row.next_verification_key_id && !keyMap.has(row.next_verification_key_id)) {
    return {
      ok: false,
      reason: "next_verification_key_not_found"
    };
  }

  const signatureOk = verifyManifestSignature(manifest, row.signature, verificationKey.public_key_pem);
  if (!signatureOk) {
    return {
      ok: false,
      reason: "signature_invalid"
    };
  }

  return {
    ok: true,
    manifest
  };
}

async function resolveBestRelease(params: {
  model: string;
  channel: OtaChannel;
  currentVersion?: string | null;
  minimumSecurityVersion: number;
}): Promise<{ release: OtaReleaseRow; manifest: OtaManifestPayload } | null> {
  const result = await query<OtaReleaseRow>(
    `SELECT
       id, model, version, security_version, channel, url, size_bytes,
       sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
       manifest_payload, expires_at, is_active, metadata,
       created_at, updated_at
     FROM ota_releases
     WHERE model = $1
       AND channel = $2
       AND is_active = TRUE
       AND expires_at > now()
       AND security_version >= $3`,
    [params.model, params.channel, params.minimumSecurityVersion]
  );

  const candidates = result.rows
    .filter((row) => semver.valid(row.version))
    .sort((a, b) => semver.rcompare(a.version, b.version));
  const keys = await loadSigningKeys();

  for (const release of candidates) {
    const integrity = await verifyReleaseIntegrity(release, keys);
    if (!integrity.ok || !integrity.manifest) {
      continue;
    }

    if (!params.currentVersion || !semver.valid(params.currentVersion)) {
      return {
        release,
        manifest: integrity.manifest
      };
    }
    if (semver.gt(release.version, params.currentVersion)) {
      return {
        release,
        manifest: integrity.manifest
      };
    }
  }

  return null;
}

async function currentSecurityFloor(params: {
  model: string;
  channel: OtaChannel;
  excludeReleaseId?: string;
}): Promise<number> {
  const values: unknown[] = [params.model, params.channel];
  let excludeClause = "";
  if (params.excludeReleaseId) {
    values.push(params.excludeReleaseId);
    excludeClause = `AND id <> $${values.length}`;
  }

  const result = await query<{ floor: string }>(
    `SELECT COALESCE(MAX(security_version), 0)::text AS floor
     FROM ota_releases
     WHERE model = $1
       AND channel = $2
       AND is_active = TRUE
       ${excludeClause}`,
    values
  );
  return Number(result.rows[0]?.floor ?? "0");
}

async function prepareManifestSignature(params: {
  manifest: OtaManifestPayload;
  autoSign: boolean;
  providedSignature?: string;
  providedVerificationKeyId?: string;
  providedNextVerificationKeyId?: string | null;
}): Promise<{
  signature: string;
  verificationKeyId: string;
  nextVerificationKeyId: string | null;
}> {
  if (params.autoSign) {
    const activeKey = await getSigningKeyByStatus("active");
    if (activeKey) {
      const privateKeyPem = secretManager.resolveSigningPrivateKey(activeKey.private_key_secret_ref);
      if (!privateKeyPem) {
        throw new Error("active_signing_private_key_unavailable");
      }
      const signature = signManifestPayload(params.manifest, privateKeyPem);
      const nextKey = await getSigningKeyByStatus("next");
      return {
        signature,
        verificationKeyId: activeKey.key_id,
        nextVerificationKeyId: nextKey?.key_id ?? null
      };
    }
  }

  if (!params.providedSignature || !params.providedVerificationKeyId) {
    throw new Error("signing_key_unavailable");
  }
  const key = await getSigningKeyByKeyId(params.providedVerificationKeyId);
  if (!key) {
    throw new Error("verification_key_not_found");
  }

  const verified = verifyManifestSignature(params.manifest, params.providedSignature, key.public_key_pem);
  if (!verified) {
    throw new Error("signature_invalid");
  }

  let nextVerificationKeyId: string | null = null;
  if (typeof params.providedNextVerificationKeyId !== "undefined") {
    if (params.providedNextVerificationKeyId === null) {
      nextVerificationKeyId = null;
    } else {
      const next = await getSigningKeyByKeyId(params.providedNextVerificationKeyId);
      if (!next) {
        throw new Error("next_verification_key_not_found");
      }
      nextVerificationKeyId = next.key_id;
    }
  }

  return {
    signature: params.providedSignature,
    verificationKeyId: key.key_id,
    nextVerificationKeyId
  };
}

async function getReleaseById(id: string): Promise<OtaReleaseRow | null> {
  const result = await query<OtaReleaseRow>(
    `SELECT
       id, model, version, security_version, channel, url, size_bytes,
       sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
       manifest_payload, expires_at, is_active, metadata,
       created_at, updated_at
     FROM ota_releases
     WHERE id = $1
     LIMIT 1`,
    [id]
  );
  return result.rows[0] ?? null;
}

function normalizeReleaseSize(size: string | number): number {
  return typeof size === "string" ? Number(size) : size;
}

export async function otaRoutes(server: FastifyInstance): Promise<void> {
  server.get("/check", async (request, reply) => {
    const parsedQuery = otaCheckQuerySchema.safeParse(request.query);
    if (!parsedQuery.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid query parameters.", parsedQuery.error.flatten());
    }

    const queryParams = parsedQuery.data;
    if (!semver.valid(queryParams.current)) {
      return sendApiError(reply, 400, "validation_error", "current must be a valid semantic version.");
    }

    const device = await findDevice(queryParams.device_uid);
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    if (queryParams.token) {
      const tokenHash = sha256(queryParams.token);
      if (tokenHash !== device.device_token_hash) {
        return sendApiError(reply, 401, "unauthorized", "Device token is invalid.");
      }
    }

    const channel = queryParams.channel ?? device.ota_channel;
    const resolved = await resolveBestRelease({
      model: device.model,
      channel,
      currentVersion: queryParams.current,
      minimumSecurityVersion: device.ota_security_version
    });

    const now = nowIso();
    await query(
      `UPDATE devices
       SET last_ota_check_at = $1,
           last_ota_status = $2,
           updated_at = $1
       WHERE id = $3`,
      [now, resolved ? "update_available" : "up_to_date", device.id]
    );

    if (!resolved) {
      return reply.send({
        update_available: false,
        device_uid: device.device_uid,
        current: queryParams.current,
        channel
      });
    }

    return reply.send({
      update_available: true,
      device_uid: device.device_uid,
      current: queryParams.current,
      channel,
      manifest: {
        ...resolved.manifest,
        verification_key_id: resolved.release.verification_key_id,
        next_verification_key_id: resolved.release.next_verification_key_id
      }
    });
  });

  server.get("/manifest/:device_uid", async (request, reply) => {
    const params = request.params as { device_uid: string };
    const parsedQuery = otaManifestQuerySchema.safeParse(request.query);
    if (!parsedQuery.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid query parameters.", parsedQuery.error.flatten());
    }
    const queryParams = parsedQuery.data;

    const device = await findDevice(params.device_uid);
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    if (queryParams.token) {
      const tokenHash = sha256(queryParams.token);
      if (tokenHash !== device.device_token_hash) {
        return sendApiError(reply, 401, "unauthorized", "Device token is invalid.");
      }
    }

    const channel = queryParams.channel ?? device.ota_channel;
    const currentVersion = queryParams.current ?? device.firmware_version ?? "0.0.0";
    const resolved = await resolveBestRelease({
      model: device.model,
      channel,
      currentVersion,
      minimumSecurityVersion: device.ota_security_version
    });

    if (!resolved) {
      return sendApiError(reply, 404, "manifest_not_found", "No active manifest for device.");
    }

    await query(
      `UPDATE devices
       SET last_ota_check_at = $1,
           last_ota_status = $2,
           updated_at = $1
       WHERE id = $3`,
      [nowIso(), "manifest_served", device.id]
    );

    return reply.send({
      device_uid: device.device_uid,
      model: device.model,
      ...resolved.manifest,
      verification_key_id: resolved.release.verification_key_id,
      next_verification_key_id: resolved.release.next_verification_key_id
    });
  });

  server.post("/report", async (request, reply) => {
    const parsed = otaReportSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const payload = parsed.data;
    const tokenHash = sha256(payload.device_token);
    const deviceLookup = await query<DeviceOtaRow>(
      `SELECT
         id, device_uid, model, firmware_version, ota_channel, ota_security_version,
         owner_user_id, device_token_hash
       FROM devices
       WHERE device_uid = $1
         AND device_token_hash = $2
         AND is_active = TRUE
       LIMIT 1`,
      [payload.device_uid, tokenHash]
    );
    const device = deviceLookup.rows[0];
    if (!device) {
      return sendApiError(reply, 401, "unauthorized", "Device credentials are invalid.");
    }

    if (
      payload.status === "ok" &&
      (payload.event_type === "success" || payload.event_type === "boot_ok") &&
      typeof payload.security_version === "number" &&
      payload.security_version < device.ota_security_version
    ) {
      const nowRejected = nowIso();
      await query(
        `INSERT INTO ota_reports (
           id, device_id, event_type, status, from_version, to_version,
           security_version, details, created_at
         ) VALUES (
           $1, $2, $3, 'rejected', $4, $5,
           $6, $7::jsonb, $8
         )`,
        [
          newId(),
          device.id,
          payload.event_type,
          payload.from_version ?? null,
          payload.to_version ?? null,
          payload.security_version,
          JSON.stringify({
            reason: "security_version_rollback_rejected",
            reported_security_version: payload.security_version,
            required_minimum: device.ota_security_version
          }),
          nowRejected
        ]
      );

      await query(
        `UPDATE devices
         SET last_ota_status = 'rejected',
             last_ota_reason = 'security_version_rollback_rejected',
             updated_at = $1
         WHERE id = $2`,
        [nowRejected, device.id]
      );

      return sendApiError(
        reply,
        409,
        "ota_security_rollback_rejected",
        "Reported security_version is lower than device minimum accepted version."
      );
    }

    const now = nowIso();
    const nextSecurityVersion = Math.max(
      device.ota_security_version,
      payload.security_version ?? device.ota_security_version
    );

    await query(
      `INSERT INTO ota_reports (
         id, device_id, event_type, status, from_version, to_version,
         security_version, details, created_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6,
         $7, $8::jsonb, $9
       )`,
      [
        newId(),
        device.id,
        payload.event_type,
        payload.status,
        payload.from_version ?? null,
        payload.to_version ?? null,
        payload.security_version ?? null,
        JSON.stringify({
          reason: payload.reason ?? null,
          ...payload.details
        }),
        now
      ]
    );

    const finalFirmwareVersion =
      payload.status === "ok" && (payload.event_type === "success" || payload.event_type === "boot_ok")
        ? payload.to_version ?? device.firmware_version
        : device.firmware_version;

    await query(
      `UPDATE devices
       SET ota_security_version = $1,
           firmware_version = $2,
           last_ota_status = $3,
           last_ota_reason = $4,
           updated_at = $5
       WHERE id = $6`,
      [
        nextSecurityVersion,
        finalFirmwareVersion,
        payload.status,
        payload.reason ?? null,
        now,
        device.id
      ]
    );

    if (device.owner_user_id) {
      realtimeHub.broadcastToUser(device.owner_user_id, {
        type: "ota_status",
        device_uid: device.device_uid,
        event_type: payload.event_type,
        status: payload.status,
        from_version: payload.from_version ?? null,
        to_version: payload.to_version ?? null,
        security_version: payload.security_version ?? null,
        reason: payload.reason ?? null,
        details: payload.details,
        ts: now
      });
    }

    return reply.send({ ok: true });
  });

  server.get("/releases", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const queryParams = request.query as { model?: string; channel?: OtaChannel };
    const filters: string[] = [];
    const values: unknown[] = [];

    if (queryParams.model) {
      values.push(queryParams.model);
      filters.push(`model = $${values.length}`);
    }
    if (queryParams.channel) {
      values.push(queryParams.channel);
      filters.push(`channel = $${values.length}`);
    }

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
    const releases = await query<OtaReleaseRow>(
      `SELECT
         id, model, version, security_version, channel, url, size_bytes,
         sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
         manifest_payload, expires_at, is_active, metadata,
         created_at, updated_at
       FROM ota_releases
       ${whereClause}
       ORDER BY created_at DESC`,
      values
    );

    return reply.send(releases.rows.map((row) => serializeRelease(row)));
  });

  server.post("/releases", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const parsed = createReleaseSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const payload = parsed.data;
    try {
      ensureValidSemver(payload.version);
    } catch {
      return sendApiError(reply, 400, "validation_error", "version must be a valid semantic version.");
    }
    if (!isAllowedArtifactHost(payload.url)) {
      return sendApiError(reply, 400, "validation_error", "Release URL host is not allowlisted.");
    }

    const floor = await currentSecurityFloor({
      model: payload.model,
      channel: payload.channel
    });
    if (payload.security_version < floor) {
      return sendApiError(
        reply,
        409,
        "security_version_rollback",
        `security_version must be >= ${floor} for active ${payload.model}/${payload.channel} releases.`
      );
    }

    const manifest = buildManifestPayload({
      version: payload.version,
      security_version: payload.security_version,
      channel: payload.channel,
      url: payload.url,
      size_bytes: payload.size_bytes,
      sha256: payload.sha256,
      expires_at: payload.expires_at
    });

    let signatureInfo;
    try {
      signatureInfo = await prepareManifestSignature({
        manifest,
        autoSign: payload.auto_sign,
        providedSignature: payload.signature,
        providedVerificationKeyId: payload.verification_key_id,
        providedNextVerificationKeyId: payload.next_verification_key_id
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "release_signing_failed";
      return sendApiError(reply, 400, "release_signing_failed", message);
    }

    const now = nowIso();
    try {
      const inserted = await query<OtaReleaseRow>(
        `INSERT INTO ota_releases (
           id, model, version, security_version, channel, url, size_bytes,
           sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
           manifest_payload, expires_at, is_active, metadata,
           created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7,
           $8, 'ecdsa-p256-sha256', $9, $10, $11,
           $12::jsonb, $13, $14, $15::jsonb,
           $16, $17
         )
         RETURNING
           id, model, version, security_version, channel, url, size_bytes,
           sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
           manifest_payload, expires_at, is_active, metadata,
           created_at, updated_at`,
        [
          newId(),
          payload.model,
          payload.version,
          payload.security_version,
          payload.channel,
          payload.url,
          payload.size_bytes,
          payload.sha256.toLowerCase(),
          signatureInfo.signature,
          signatureInfo.verificationKeyId,
          signatureInfo.nextVerificationKeyId,
          JSON.stringify(manifest),
          payload.expires_at,
          payload.is_active,
          JSON.stringify(payload.metadata),
          now,
          now
        ]
      );

      return reply.code(201).send(serializeRelease(inserted.rows[0]));
    } catch (error) {
      const pgError = error as { code?: string; constraint?: string } | undefined;
      if (pgError?.code === "23505") {
        return sendApiError(reply, 409, "release_exists", "Release already exists for model/version/channel.");
      }
      throw error;
    }
  });

  server.patch("/releases/:id", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateReleaseSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }
    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    const existing = await getReleaseById(params.id);
    if (!existing) {
      return sendApiError(reply, 404, "not_found", "Release not found.");
    }

    const merged = {
      security_version: typeof changes.security_version === "number" ? changes.security_version : existing.security_version,
      channel: changes.channel ?? existing.channel,
      url: changes.url ?? existing.url,
      size_bytes: typeof changes.size_bytes === "number" ? changes.size_bytes : normalizeReleaseSize(existing.size_bytes),
      sha256: typeof changes.sha256 === "string" ? changes.sha256.toLowerCase() : existing.sha256.toLowerCase(),
      expires_at: changes.expires_at ?? toIso(existing.expires_at),
      is_active: typeof changes.is_active === "boolean" ? changes.is_active : existing.is_active,
      metadata: typeof changes.metadata !== "undefined" ? changes.metadata : asObject(existing.metadata)
    };

    if (!isAllowedArtifactHost(merged.url)) {
      return sendApiError(reply, 400, "validation_error", "Release URL host is not allowlisted.");
    }

    const floor = await currentSecurityFloor({
      model: existing.model,
      channel: merged.channel,
      excludeReleaseId: existing.id
    });
    if (merged.security_version < floor) {
      return sendApiError(
        reply,
        409,
        "security_version_rollback",
        `security_version must be >= ${floor} for active ${existing.model}/${merged.channel} releases.`
      );
    }

    const manifest = buildManifestPayload({
      version: existing.version,
      security_version: merged.security_version,
      channel: merged.channel,
      url: merged.url,
      size_bytes: merged.size_bytes,
      sha256: merged.sha256,
      expires_at: merged.expires_at
    });

    const signedFieldsChanged =
      typeof changes.security_version !== "undefined" ||
      typeof changes.channel !== "undefined" ||
      typeof changes.url !== "undefined" ||
      typeof changes.size_bytes !== "undefined" ||
      typeof changes.sha256 !== "undefined" ||
      typeof changes.expires_at !== "undefined";
    const explicitSigningInput =
      typeof changes.signature !== "undefined" ||
      typeof changes.verification_key_id !== "undefined" ||
      typeof changes.next_verification_key_id !== "undefined" ||
      typeof changes.auto_sign !== "undefined" ||
      changes.re_sign === true;

    let nextSignature = existing.signature;
    let nextVerificationKeyId = existing.verification_key_id;
    let nextVerificationKeyId2 = existing.next_verification_key_id;

    if (signedFieldsChanged || explicitSigningInput) {
      try {
        const signing = await prepareManifestSignature({
          manifest,
          autoSign: changes.auto_sign ?? true,
          providedSignature: changes.signature,
          providedVerificationKeyId: changes.verification_key_id,
          providedNextVerificationKeyId: changes.next_verification_key_id
        });
        nextSignature = signing.signature;
        nextVerificationKeyId = signing.verificationKeyId;
        nextVerificationKeyId2 = signing.nextVerificationKeyId;
      } catch (error) {
        const message = error instanceof Error ? error.message : "release_signing_failed";
        return sendApiError(reply, 400, "release_signing_failed", message);
      }
    }

    const updated = await query<OtaReleaseRow>(
      `UPDATE ota_releases
       SET security_version = $1,
           channel = $2,
           url = $3,
           size_bytes = $4,
           sha256 = $5,
           signature_alg = 'ecdsa-p256-sha256',
           signature = $6,
           verification_key_id = $7,
           next_verification_key_id = $8,
           manifest_payload = $9::jsonb,
           expires_at = $10,
           is_active = $11,
           metadata = $12::jsonb,
           updated_at = $13
       WHERE id = $14
       RETURNING
         id, model, version, security_version, channel, url, size_bytes,
         sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
         manifest_payload, expires_at, is_active, metadata,
         created_at, updated_at`,
      [
        merged.security_version,
        merged.channel,
        merged.url,
        merged.size_bytes,
        merged.sha256,
        nextSignature,
        nextVerificationKeyId,
        nextVerificationKeyId2,
        JSON.stringify(manifest),
        merged.expires_at,
        merged.is_active,
        JSON.stringify(merged.metadata),
        nowIso(),
        params.id
      ]
    );

    return reply.send(serializeRelease(updated.rows[0]));
  });

  server.get("/releases/:id/verify", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const params = request.params as { id: string };
    const release = await getReleaseById(params.id);
    if (!release) {
      return sendApiError(reply, 404, "not_found", "Release not found.");
    }

    const keys = await loadSigningKeys();
    const integrity = await verifyReleaseIntegrity(release, keys);
    return reply.send({
      release_id: release.id,
      ok: integrity.ok,
      reason: integrity.reason ?? null,
      verification_key_id: release.verification_key_id,
      next_verification_key_id: release.next_verification_key_id,
      manifest_payload: integrity.manifest ?? manifestFromReleaseRow(release)
    });
  });

  server.get("/signing-keys", { preHandler: [authenticate, requireRole(["admin"])] }, async (_request, reply) => {
    const keys = await query<OtaSigningKeyRow>(
      `SELECT
         id, key_id, public_key_pem, private_key_secret_ref,
         status, created_at, updated_at, rotated_at
       FROM ota_signing_keys
       ORDER BY created_at DESC`
    );
    return reply.send(keys.rows.map((row) => serializeSigningKey(row)));
  });

  server.post("/signing-keys", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const parsed = createSigningKeySchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const payload = parsed.data;
    const now = nowIso();
    try {
      const inserted = await query<OtaSigningKeyRow>(
        `INSERT INTO ota_signing_keys (
           id, key_id, public_key_pem, private_key_secret_ref,
           status, created_at, updated_at, rotated_at
         ) VALUES (
           $1, $2, $3, $4,
           $5, $6, $7, NULL
         )
         RETURNING
           id, key_id, public_key_pem, private_key_secret_ref,
           status, created_at, updated_at, rotated_at`,
        [newId(), payload.key_id, payload.public_key_pem, payload.private_key_secret_ref, payload.status, now, now]
      );
      return reply.code(201).send(serializeSigningKey(inserted.rows[0]));
    } catch (error) {
      const pgError = error as { code?: string } | undefined;
      if (pgError?.code === "23505") {
        return sendApiError(reply, 409, "signing_key_conflict", "Key id or key status already exists.");
      }
      throw error;
    }
  });

  server.patch("/signing-keys/:id", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateSigningKeySchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }
    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    const fields: string[] = [];
    const values: unknown[] = [];
    if (typeof changes.public_key_pem !== "undefined") {
      values.push(changes.public_key_pem);
      fields.push(`public_key_pem = $${values.length}`);
    }
    if (typeof changes.private_key_secret_ref !== "undefined") {
      values.push(changes.private_key_secret_ref);
      fields.push(`private_key_secret_ref = $${values.length}`);
    }
    if (typeof changes.status !== "undefined") {
      values.push(changes.status);
      fields.push(`status = $${values.length}`);
      if (changes.status === "retired") {
        values.push(nowIso());
        fields.push(`rotated_at = $${values.length}`);
      }
    }
    values.push(nowIso());
    fields.push(`updated_at = $${values.length}`);

    values.push(params.id);
    const idArg = values.length;
    try {
      const updated = await query<OtaSigningKeyRow>(
        `UPDATE ota_signing_keys
         SET ${fields.join(", ")}
         WHERE id = $${idArg}
         RETURNING
           id, key_id, public_key_pem, private_key_secret_ref,
           status, created_at, updated_at, rotated_at`,
        values
      );
      if (!updated.rowCount || updated.rowCount === 0) {
        return sendApiError(reply, 404, "not_found", "Signing key not found.");
      }
      return reply.send(serializeSigningKey(updated.rows[0]));
    } catch (error) {
      const pgError = error as { code?: string } | undefined;
      if (pgError?.code === "23505") {
        return sendApiError(reply, 409, "signing_key_conflict", "Only one active and one next key are allowed.");
      }
      throw error;
    }
  });

  server.post("/signing-keys/rotate", { preHandler: [authenticate, requireRole(["admin"])] }, async (_request, reply) => {
    try {
      const result = await withTransaction(async (client) => {
        const active = await client.query<OtaSigningKeyRow>(
          `SELECT
             id, key_id, public_key_pem, private_key_secret_ref,
             status, created_at, updated_at, rotated_at
           FROM ota_signing_keys
           WHERE status = 'active'
           LIMIT 1
           FOR UPDATE`
        );
        const next = await client.query<OtaSigningKeyRow>(
          `SELECT
             id, key_id, public_key_pem, private_key_secret_ref,
             status, created_at, updated_at, rotated_at
           FROM ota_signing_keys
           WHERE status = 'next'
           LIMIT 1
           FOR UPDATE`
        );
        const nextKey = next.rows[0];
        if (!nextKey) {
          throw new Error("next_signing_key_not_configured");
        }

        const now = nowIso();
        const previousActive = active.rows[0];
        if (previousActive) {
          await client.query(
            `UPDATE ota_signing_keys
             SET status = 'retired',
                 rotated_at = $1,
                 updated_at = $1
             WHERE id = $2`,
            [now, previousActive.id]
          );
        }
        await client.query(
          `UPDATE ota_signing_keys
           SET status = 'active',
               rotated_at = $1,
               updated_at = $1
           WHERE id = $2`,
          [now, nextKey.id]
        );

        const activeAfter = await client.query<OtaSigningKeyRow>(
          `SELECT
             id, key_id, public_key_pem, private_key_secret_ref,
             status, created_at, updated_at, rotated_at
           FROM ota_signing_keys
           WHERE id = $1
           LIMIT 1`,
          [nextKey.id]
        );
        return {
          retired: previousActive ? serializeSigningKey(previousActive) : null,
          active: serializeSigningKey(activeAfter.rows[0])
        };
      });

      return reply.send({
        ok: true,
        rotated_at: nowIso(),
        retired_key: result.retired,
        active_key: result.active
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "signing_key_rotation_failed";
      if (message === "next_signing_key_not_configured") {
        return sendApiError(reply, 409, "next_signing_key_not_configured", "No next signing key is configured.");
      }
      return sendApiError(reply, 500, "signing_key_rotation_failed", message);
    }
  });
}
