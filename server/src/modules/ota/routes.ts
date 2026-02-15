import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { access, mkdir, rename, rm, stat } from "node:fs/promises";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
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
type CreateReleaseInput = z.infer<typeof createReleaseSchema>;

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

const releaseSigningErrors = new Set([
  "signing_key_unavailable",
  "verification_key_not_found",
  "next_verification_key_not_found",
  "signature_invalid",
  "active_signing_private_key_unavailable"
]);

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseSecurityRollbackFloor(message: string): number | null {
  if (!message.startsWith("security_version_rollback:")) {
    return null;
  }
  const floor = Number(message.slice("security_version_rollback:".length));
  return Number.isFinite(floor) ? floor : null;
}

function sanitizeArtifactSegment(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
}

function inferReleaseMetadataFromFilename(filename: string): {
  model?: string;
  version?: string;
  channel?: OtaChannel;
} {
  const baseName = path.basename(filename).replace(/\.bin$/i, "");
  const patterns = [
    /^(?<model>.+?)[-_](?<version>v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)[-_](?<channel>dev|beta|stable)$/i,
    /^(?<model>.+?)[-_](?<channel>dev|beta|stable)[-_](?<version>v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$/i
  ];

  for (const pattern of patterns) {
    const match = baseName.match(pattern);
    if (!match?.groups) {
      continue;
    }
    const model = String(match.groups.model ?? "").trim();
    const version = String(match.groups.version ?? "").trim();
    const channelCandidate = String(match.groups.channel ?? "").trim().toLowerCase();
    const channelParsed = otaChannelSchema.safeParse(channelCandidate);
    if (!model || !version || !channelParsed.success) {
      continue;
    }
    return {
      model,
      version,
      channel: channelParsed.data
    };
  }

  return {};
}

function parseBooleanField(value: string | undefined, defaultValue: boolean): boolean {
  if (!value) {
    return defaultValue;
  }
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return defaultValue;
}

function readMultipartField(fields: Record<string, unknown> | undefined, name: string): string | undefined {
  const entry = fields?.[name];
  if (!entry) {
    return undefined;
  }
  const item = Array.isArray(entry) ? entry[0] : entry;
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    return undefined;
  }
  const value = (item as { value?: unknown }).value;
  if (typeof value === "undefined" || value === null) {
    return undefined;
  }
  return String(value).trim();
}

function normalizeArtifactKey(rawKey: string): string | null {
  const decoded = decodeURIComponentSafe(rawKey).replace(/\\/g, "/");
  const segments = decoded.split("/").filter((segment) => segment.length > 0 && segment !== ".");
  if (segments.length === 0 || segments.some((segment) => segment === "..")) {
    return null;
  }
  return segments.join("/");
}

function resolveArtifactAbsolutePath(rootDir: string, key: string): string | null {
  const normalized = normalizeArtifactKey(key);
  if (!normalized) {
    return null;
  }
  const absolute = path.resolve(rootDir, ...normalized.split("/"));
  const normalizedRoot = path.resolve(rootDir);
  if (absolute !== normalizedRoot && !absolute.startsWith(`${normalizedRoot}${path.sep}`)) {
    return null;
  }
  return absolute;
}

function artifactRootDir(): string {
  return path.resolve(process.cwd(), env.OTA_ARTIFACTS_DIR);
}

function buildArtifactPublicUrl(request: FastifyRequest, artifactKey: string): string {
  const encodedKey = artifactKey.split("/").map((segment) => encodeURIComponent(segment)).join("/");
  const configuredBase = env.OTA_PUBLIC_BASE_URL?.replace(/\/+$/, "");
  if (configuredBase) {
    return `${configuredBase}/api/v1/ota/artifacts/${encodedKey}`;
  }
  if (env.OTA_ALLOWED_HOSTS.length === 1) {
    return `https://${env.OTA_ALLOWED_HOSTS[0]}/api/v1/ota/artifacts/${encodedKey}`;
  }

  const hostHeader = request.headers.host;
  const host = (Array.isArray(hostHeader) ? hostHeader[0] : hostHeader) ?? `127.0.0.1:${env.PORT}`;
  const forwardedProtoHeader = request.headers["x-forwarded-proto"];
  const forwardedProto = (Array.isArray(forwardedProtoHeader) ? forwardedProtoHeader[0] : forwardedProtoHeader)
    ?.split(",")[0]
    ?.trim()
    ?.toLowerCase();
  const protocol = forwardedProto || request.protocol || (env.NODE_ENV === "production" ? "https" : "http");
  return `${protocol}://${host}/api/v1/ota/artifacts/${encodedKey}`;
}

function isUploadTooLargeError(error: unknown): boolean {
  const code = (error as { code?: string } | undefined)?.code;
  if (code === "FST_REQ_FILE_TOO_LARGE") {
    return true;
  }
  const message = (error as { message?: string } | undefined)?.message ?? "";
  return typeof message === "string" && message.toLowerCase().includes("too large");
}

function sendArtifactStoreError(reply: FastifyReply, error: unknown, rootDir: string) {
  const fsCode = (error as { code?: string } | undefined)?.code ?? null;
  const message = (error as { message?: string } | undefined)?.message ?? "unknown_error";

  if (isUploadTooLargeError(error)) {
    return sendApiError(reply, 413, "payload_too_large", "Firmware binary exceeds upload limit.", {
      upload_limit_bytes: env.OTA_UPLOAD_MAX_BYTES
    });
  }

  if (fsCode === "ENOSPC") {
    return sendApiError(reply, 507, "insufficient_storage", "Server disk is full while storing firmware.", {
      code: fsCode,
      root_dir: rootDir
    });
  }

  if (fsCode === "EACCES" || fsCode === "EPERM" || fsCode === "EROFS") {
    return sendApiError(reply, 500, "artifact_store_failed", "OTA artifact directory is not writable.", {
      code: fsCode,
      root_dir: rootDir
    });
  }

  return sendApiError(reply, 500, "artifact_store_failed", "Failed to store uploaded firmware.", {
    code: fsCode,
    reason: message,
    root_dir: rootDir
  });
}

async function writeUploadedArtifact(
  source: NodeJS.ReadableStream,
  destinationPath: string
): Promise<{ sha256Hex: string; sizeBytes: number }> {
  await mkdir(path.dirname(destinationPath), { recursive: true });

  const hash = createHash("sha256");
  let sizeBytes = 0;
  const hashTransform = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      hash.update(chunk);
      sizeBytes += chunk.length;
      callback(null, chunk);
    }
  });

  try {
    await pipeline(source, hashTransform, createWriteStream(destinationPath, { flags: "wx" }));
  } catch (error) {
    await rm(destinationPath, { force: true });
    throw error;
  }

  return {
    sha256Hex: hash.digest("hex"),
    sizeBytes
  };
}

function parseMetadataField(rawMetadata: string | undefined): Record<string, unknown> {
  if (!rawMetadata) {
    return {};
  }
  const parsed = JSON.parse(rawMetadata);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("metadata_invalid");
  }
  return parsed as Record<string, unknown>;
}

async function createSignedRelease(payload: CreateReleaseInput): Promise<OtaReleaseRow> {
  const normalizedVersion = semver.clean(payload.version) ?? payload.version;
  ensureValidSemver(normalizedVersion);

  if (!isAllowedArtifactHost(payload.url)) {
    throw new Error("ota_host_blocked");
  }

  const floor = await currentSecurityFloor({
    model: payload.model,
    channel: payload.channel
  });
  if (payload.security_version < floor) {
    throw new Error(`security_version_rollback:${floor}`);
  }

  const manifest = buildManifestPayload({
    version: normalizedVersion,
    security_version: payload.security_version,
    channel: payload.channel,
    url: payload.url,
    size_bytes: payload.size_bytes,
    sha256: payload.sha256,
    expires_at: payload.expires_at
  });

  const signatureInfo = await prepareManifestSignature({
    manifest,
    autoSign: payload.auto_sign,
    providedSignature: payload.signature,
    providedVerificationKeyId: payload.verification_key_id,
    providedNextVerificationKeyId: payload.next_verification_key_id
  });

  const now = nowIso();
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
      normalizedVersion,
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

  return inserted.rows[0];
}

function handleCreateReleaseError(
  reply: FastifyReply,
  error: unknown,
  context: { model: string; channel: OtaChannel }
): boolean {
  const message = error instanceof Error ? error.message : "release_create_failed";
  if (message === "invalid_version") {
    sendApiError(reply, 400, "validation_error", "version must be a valid semantic version.");
    return true;
  }
  if (message === "ota_host_blocked") {
    sendApiError(reply, 400, "validation_error", "Release URL host is not allowlisted.");
    return true;
  }

  const floor = parseSecurityRollbackFloor(message);
  if (floor !== null) {
    sendApiError(
      reply,
      409,
      "security_version_rollback",
      `security_version must be >= ${floor} for active ${context.model}/${context.channel} releases.`
    );
    return true;
  }

  if (releaseSigningErrors.has(message)) {
    sendApiError(reply, 400, "release_signing_failed", message);
    return true;
  }

  const pgError = error as { code?: string } | undefined;
  if (pgError?.code === "23505") {
    sendApiError(reply, 409, "release_exists", "Release already exists for model/version/channel.");
    return true;
  }

  return false;
}

export async function otaRoutes(server: FastifyInstance): Promise<void> {
  server.get("/artifacts/*", async (request, reply) => {
    const params = request.params as { "*": string };
    const key = normalizeArtifactKey(params["*"] ?? "");
    if (!key) {
      return sendApiError(reply, 400, "validation_error", "Invalid artifact path.");
    }

    const rootDir = artifactRootDir();
    const absolutePath = resolveArtifactAbsolutePath(rootDir, key);
    if (!absolutePath) {
      return sendApiError(reply, 400, "validation_error", "Invalid artifact path.");
    }

    try {
      const info = await stat(absolutePath);
      if (!info.isFile()) {
        return sendApiError(reply, 404, "not_found", "Artifact not found.");
      }

      reply.header("cache-control", "public, max-age=31536000, immutable");
      reply.header("content-length", String(info.size));
      reply.type("application/octet-stream");
      return reply.send(createReadStream(absolutePath));
    } catch (error) {
      const fsError = error as { code?: string } | undefined;
      if (fsError?.code === "ENOENT") {
        return sendApiError(reply, 404, "not_found", "Artifact not found.");
      }
      throw error;
    }
  });

  server.get("/check", async (_request, reply) => {
    return sendApiError(
      reply,
      410,
      "ota_ws_only",
      "OTA check over HTTP is deprecated. Use WebSocket ota_control (scope=ota, operation=check)."
    );
  });

  server.get("/manifest/:device_uid", async (_request, reply) => {
    return sendApiError(
      reply,
      410,
      "ota_ws_only",
      "OTA manifest over HTTP is deprecated. Use WebSocket ota_control with embedded signed manifest."
    );
  });

  server.post("/report", async (_request, reply) => {
    return sendApiError(
      reply,
      410,
      "ota_ws_only",
      "OTA report over HTTP is deprecated. OTA status is ingested from device WebSocket ota_status events."
    );
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

  server.post("/releases/upload", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    let upload:
      | {
          filename: string;
          mimetype: string;
          file: NodeJS.ReadableStream;
          fields?: Record<string, unknown>;
        }
      | undefined;

    try {
      upload = (await request.file({
        limits: {
          fileSize: env.OTA_UPLOAD_MAX_BYTES,
          files: 1
        }
      })) as
        | {
            filename: string;
            mimetype: string;
            file: NodeJS.ReadableStream;
            fields?: Record<string, unknown>;
          }
        | undefined;
    } catch (error) {
      const code = (error as { code?: string } | undefined)?.code;
      if (code === "FST_REQ_FILE_TOO_LARGE") {
        return sendApiError(reply, 413, "payload_too_large", "Firmware binary exceeds upload limit.");
      }
      throw error;
    }

    if (!upload) {
      return sendApiError(reply, 400, "validation_error", "Missing firmware file. Use multipart field 'firmware'.");
    }

    const originalFilename = upload.filename?.trim() || "firmware.bin";
    if (!originalFilename.toLowerCase().endsWith(".bin")) {
      upload.file.resume();
      return sendApiError(reply, 400, "validation_error", "Uploaded file must use .bin extension.");
    }

    const inferred = inferReleaseMetadataFromFilename(originalFilename);
    const model = readMultipartField(upload.fields, "model") ?? inferred.model;
    const versionRaw = readMultipartField(upload.fields, "version") ?? inferred.version;
    const channelRaw = readMultipartField(upload.fields, "channel") ?? inferred.channel;

    if (!model || !versionRaw || !channelRaw) {
      upload.file.resume();
      return sendApiError(
        reply,
        400,
        "validation_error",
        "model/version/channel are required. Provide fields or filename pattern model-version-channel.bin."
      );
    }

    const channelParsed = otaChannelSchema.safeParse(String(channelRaw).toLowerCase());
    if (!channelParsed.success) {
      upload.file.resume();
      return sendApiError(reply, 400, "validation_error", "channel must be one of: dev, beta, stable.");
    }
    const channel = channelParsed.data;
    const normalizedVersion = semver.clean(versionRaw) ?? versionRaw.trim();

    let metadata: Record<string, unknown>;
    try {
      metadata = parseMetadataField(readMultipartField(upload.fields, "metadata"));
    } catch {
      upload.file.resume();
      return sendApiError(reply, 400, "validation_error", "metadata must be a JSON object.");
    }

    const securityVersionRaw = readMultipartField(upload.fields, "security_version");
    const inferredFloor = await currentSecurityFloor({
      model: model.trim(),
      channel
    });
    const securityVersion = securityVersionRaw ? Number(securityVersionRaw) : inferredFloor;
    if (!Number.isInteger(securityVersion) || securityVersion < 0) {
      upload.file.resume();
      return sendApiError(reply, 400, "validation_error", "security_version must be a non-negative integer.");
    }

    const expiresAtRaw = readMultipartField(upload.fields, "expires_at");
    const expiresAt =
      expiresAtRaw && expiresAtRaw.length > 0
        ? expiresAtRaw
        : new Date(Date.now() + env.OTA_RELEASE_DEFAULT_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();
    if (!z.string().datetime().safeParse(expiresAt).success) {
      upload.file.resume();
      return sendApiError(reply, 400, "validation_error", "expires_at must be a valid ISO timestamp.");
    }

    const isActive = parseBooleanField(readMultipartField(upload.fields, "is_active"), true);
    const autoSign = parseBooleanField(readMultipartField(upload.fields, "auto_sign"), true);
    const signature = readMultipartField(upload.fields, "signature");
    const verificationKeyId = readMultipartField(upload.fields, "verification_key_id");
    const nextVerificationField = readMultipartField(upload.fields, "next_verification_key_id");
    const nextVerificationKeyId =
      typeof nextVerificationField === "undefined"
        ? undefined
        : nextVerificationField.length > 0
          ? nextVerificationField
          : null;

    const rootDir = artifactRootDir();
    const tempKey = `_tmp/${newId()}.bin`;
    const tempPath = resolveArtifactAbsolutePath(rootDir, tempKey);
    if (!tempPath) {
      upload.file.resume();
      return sendApiError(reply, 500, "artifact_path_error", "Failed to prepare artifact path.");
    }

    let artifactKey = "";
    let artifactPath = "";
    let createdArtifactFile = false;
    let artifactStats: { sha256Hex: string; sizeBytes: number };

    try {
      artifactStats = await writeUploadedArtifact(upload.file, tempPath);
    } catch (error) {
      return sendArtifactStoreError(reply, error, rootDir);
    }

    try {
      const modelSegment = sanitizeArtifactSegment(model) || "model";
      const versionSegment = sanitizeArtifactSegment(normalizedVersion) || "version";
      const baseSegment = sanitizeArtifactSegment(path.basename(originalFilename, ".bin")) || "firmware";
      const finalName = `${baseSegment}-${artifactStats.sha256Hex.slice(0, 16)}.bin`;
      artifactKey = `${modelSegment}/${channel}/${versionSegment}/${finalName}`;
      artifactPath = resolveArtifactAbsolutePath(rootDir, artifactKey) ?? "";
      if (!artifactPath) {
        throw new Error("artifact_path_error");
      }
      await mkdir(path.dirname(artifactPath), { recursive: true });
      try {
        await access(artifactPath);
        await rm(tempPath, { force: true });
      } catch {
        await rename(tempPath, artifactPath);
        createdArtifactFile = true;
      }
    } catch (error) {
      await rm(tempPath, { force: true });
      const message = error instanceof Error ? error.message : "artifact_store_failed";
      if (message === "artifact_path_error") {
        return sendApiError(reply, 500, "artifact_path_error", "Failed to prepare artifact path.");
      }
      return sendArtifactStoreError(reply, error, rootDir);
    }

    const releasePayloadParse = createReleaseSchema.safeParse({
      model: model.trim(),
      version: normalizedVersion,
      security_version: securityVersion,
      channel,
      url: buildArtifactPublicUrl(request, artifactKey),
      size_bytes: artifactStats.sizeBytes,
      sha256: artifactStats.sha256Hex,
      expires_at: expiresAt,
      is_active: isActive,
      metadata: {
        ...metadata,
        artifact: {
          key: artifactKey,
          original_filename: originalFilename,
          mime_type: upload.mimetype || "application/octet-stream",
          uploaded_at: nowIso()
        }
      },
      auto_sign: autoSign,
      signature,
      verification_key_id: verificationKeyId,
      next_verification_key_id: nextVerificationKeyId
    });

    if (!releasePayloadParse.success) {
      if (createdArtifactFile) {
        await rm(artifactPath, { force: true });
      }
      return sendApiError(
        reply,
        400,
        "validation_error",
        "Invalid OTA release payload generated from upload.",
        releasePayloadParse.error.flatten()
      );
    }

    try {
      const inserted = await createSignedRelease(releasePayloadParse.data);
      return reply.code(201).send({
        ...serializeRelease(inserted),
        artifact: {
          key: artifactKey,
          size_bytes: artifactStats.sizeBytes,
          sha256: artifactStats.sha256Hex
        }
      });
    } catch (error) {
      if (createdArtifactFile) {
        await rm(artifactPath, { force: true });
      }
      if (handleCreateReleaseError(reply, error, { model: model.trim(), channel })) {
        return;
      }
      throw error;
    }
  });

  server.post("/releases", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const parsed = createReleaseSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const payload = parsed.data;
    try {
      const inserted = await createSignedRelease(payload);
      return reply.code(201).send(serializeRelease(inserted));
    } catch (error) {
      if (handleCreateReleaseError(reply, error, { model: payload.model, channel: payload.channel })) {
        return;
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

  server.delete("/releases/:id", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const params = request.params as { id: string };
    const existing = await getReleaseById(params.id);
    if (!existing) {
      return sendApiError(reply, 404, "not_found", "Release not found.");
    }

    await query(
      `DELETE FROM ota_releases
       WHERE id = $1`,
      [params.id]
    );

    return reply.send({
      ok: true,
      id: existing.id,
      model: existing.model,
      version: existing.version,
      channel: existing.channel
    });
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
