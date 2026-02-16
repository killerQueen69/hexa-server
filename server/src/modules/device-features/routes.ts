import { FastifyInstance } from "fastify";
import { z } from "zod";
import { env } from "../../config/env";
import { query } from "../../db/connection";
import { authenticate } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import {
  normalizeIrPayload,
  rankIrMatches,
  type IrRankableRecord
} from "../../services/ir-code-utils";
import { newId, sha256 } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type DeviceAccessRow = {
  id: string;
  device_uid: string;
  owner_user_id: string | null;
  device_class: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid";
  capabilities: unknown;
};

type DeviceAuthRow = {
  id: string;
  device_uid: string;
  owner_user_id: string | null;
};

type DeviceCapabilityRow = {
  id: string;
  device_id: string;
  capability_key: string;
  capability_kind: string;
  config: unknown;
  metadata: unknown;
  is_enabled: boolean;
  created_at: Date | string;
  updated_at: Date | string;
};

type DeviceIrCodeRow = {
  id: string;
  device_id: string;
  owner_user_id: string | null;
  code_name: string;
  protocol: string;
  protocol_norm: string | null;
  frequency_hz: number | null;
  frequency_norm_hz: number | null;
  payload: string;
  payload_format: string | null;
  payload_fingerprint: string | null;
  source_type: string | null;
  source_ref: string | null;
  normalized_payload: unknown;
  metadata: unknown;
  learned_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

type IrLibrarySourceRow = {
  id: string;
  source_key: string;
  source_url: string;
  source_hash: string;
  source_version: string;
  license: string;
  metadata: unknown;
  is_active: boolean;
  created_at: Date | string;
  updated_at: Date | string;
};

type IrLibraryRecordRow = {
  id: string;
  source_id: string;
  source_record_id: string;
  brand: string | null;
  model: string | null;
  protocol: string;
  protocol_norm: string;
  frequency_hz: number | null;
  frequency_norm_hz: number | null;
  payload: string;
  payload_format: string;
  payload_fingerprint: string;
  normalized_payload: unknown;
  metadata: unknown;
  created_at: Date | string;
  updated_at: Date | string;
};

type DeviceSensorStateRow = {
  id: string;
  device_id: string;
  sensor_key: string;
  sensor_type: string;
  state: unknown;
  observed_at: Date | string;
  source: string;
  created_at: Date | string;
  updated_at: Date | string;
};

type DeviceSensorEventRow = {
  id: string;
  device_id: string;
  sensor_key: string;
  sensor_type: string;
  event_kind: string;
  value: unknown;
  observed_at: Date | string;
  source: string;
  created_at: Date | string;
};

const capabilityKeySchema = z
  .string()
  .min(2)
  .max(80)
  .regex(/^[a-zA-Z0-9._-]+$/);

const capabilityUpsertSchema = z.object({
  capability_kind: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
  config: z.record(z.unknown()).default({}),
  metadata: z.record(z.unknown()).default({}),
  is_enabled: z.boolean().default(true)
});

const irCodeCreateSchema = z.object({
  code_name: z.string().min(1).max(120),
  protocol: z.string().min(1).max(80),
  frequency_hz: z.number().int().min(1).max(1000000).optional(),
  payload_format: z.enum(["raw", "hex", "base64", "json"]).optional(),
  payload: z.string().min(1).max(20000),
  source_type: z.enum(["device", "migration", "library", "user"]).optional(),
  source_ref: z.string().min(1).max(120).optional(),
  normalized_payload: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).default({})
});

const irCodePatchSchema = z.object({
  code_name: z.string().min(1).max(120).optional(),
  protocol: z.string().min(1).max(80).optional(),
  frequency_hz: z.number().int().min(1).max(1000000).nullable().optional(),
  payload_format: z.enum(["raw", "hex", "base64", "json"]).optional(),
  payload: z.string().min(1).max(20000).optional(),
  source_type: z.enum(["device", "migration", "library", "user"]).optional(),
  source_ref: z.string().min(1).max(120).nullable().optional(),
  normalized_payload: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).optional()
});

const irCodeBatchItemSchema = z.object({
  code_name: z.string().min(1).max(120),
  protocol: z.string().min(1).max(80),
  frequency_hz: z.number().int().min(1).max(1000000).nullable().optional(),
  payload_format: z.enum(["raw", "hex", "base64", "json"]).optional(),
  payload: z.string().min(1).max(20000),
  source_ref: z.string().min(1).max(120).optional(),
  metadata: z.record(z.unknown()).default({})
});

const deviceIrUploadSchema = z.object({
  device_uid: z.string().min(3).max(120),
  device_token: z.string().min(16),
  migration_id: z.string().min(1).max(120).optional(),
  partial: z.boolean().default(false),
  records: z.array(irCodeBatchItemSchema).min(1).max(500)
});

const irRecognizeSchema = z.object({
  candidate: z.object({
    protocol: z.string().min(1).max(80),
    frequency_hz: z.number().int().min(1).max(1000000).nullable().optional(),
    payload_format: z.enum(["raw", "hex", "base64", "json"]).optional(),
    payload: z.string().min(1).max(20000),
    metadata: z.record(z.unknown()).default({})
  }),
  brand_hint: z.string().min(1).max(80).optional(),
  model_hint: z.string().min(1).max(80).optional(),
  top_n: z.number().int().min(1).max(20).default(5)
});

const irRecognizeFeedbackSchema = z.object({
  candidate_fingerprint: z.string().min(8).max(128),
  library_record_id: z.string().min(1).max(120).nullable().optional(),
  accepted: z.boolean(),
  confidence: z.number().min(0).max(1).optional(),
  context: z.record(z.unknown()).default({})
});

const irLibraryManifestSchema = z.object({
  source_url: z.string().url(),
  source_hash: z.string().min(8).max(128),
  source_version: z.string().min(1).max(80),
  license: z.string().min(1).max(120),
  metadata: z.record(z.unknown()).default({})
});

const irLibraryRecordIngestSchema = z.object({
  source_record_id: z.string().min(1).max(160),
  brand: z.string().min(1).max(120).optional(),
  model: z.string().min(1).max(120).optional(),
  protocol: z.string().min(1).max(80),
  frequency_hz: z.number().int().min(1).max(1000000).nullable().optional(),
  payload_format: z.enum(["raw", "hex", "base64", "json"]).optional(),
  payload: z.string().min(1).max(20000),
  metadata: z.record(z.unknown()).default({})
});

const irLibraryIngestSchema = z.object({
  source_key: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
  manifest: irLibraryManifestSchema,
  records: z.array(irLibraryRecordIngestSchema).min(1).max(5000)
});

const sensorStateUpsertSchema = z.object({
  sensor_key: z.string().min(1).max(120).regex(/^[a-zA-Z0-9._:-]+$/),
  sensor_type: z.string().min(1).max(80).regex(/^[a-zA-Z0-9._:-]+$/),
  state: z.record(z.unknown()),
  observed_at: z.string().datetime().optional(),
  source: z.string().min(1).max(80).default("api")
});

const sensorEventSchema = z.object({
  sensor_key: z.string().min(1).max(120).regex(/^[a-zA-Z0-9._:-]+$/),
  sensor_type: z.string().min(1).max(80).regex(/^[a-zA-Z0-9._:-]+$/),
  event_kind: z.string().min(1).max(80).regex(/^[a-zA-Z0-9._:-]+$/),
  value: z.record(z.unknown()),
  observed_at: z.string().datetime().optional(),
  source: z.string().min(1).max(80).default("api")
});

const sensorEventsIngestSchema = z.object({
  events: z.array(sensorEventSchema).min(1).max(500)
});

const deviceSensorReportSchema = z.object({
  device_uid: z.string().min(3).max(120),
  device_token: z.string().min(16),
  events: z.array(sensorEventSchema.extend({
    source: z.string().min(1).max(80).default("device")
  })).min(1).max(500)
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

function asCapabilitySummary(value: unknown): Array<{
  key: string;
  kind: string;
  enabled: boolean;
}> {
  if (!Array.isArray(value)) {
    return [];
  }
  const out: Array<{
    key: string;
    kind: string;
    enabled: boolean;
  }> = [];
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      continue;
    }
    const row = item as Record<string, unknown>;
    const key = typeof row.key === "string" ? row.key : "";
    const kind = typeof row.kind === "string" ? row.kind : "";
    if (!key || !kind) {
      continue;
    }
    out.push({
      key,
      kind,
      enabled: row.enabled !== false
    });
  }
  return out;
}

function serializeCapability(row: DeviceCapabilityRow) {
  return {
    id: row.id,
    device_id: row.device_id,
    capability_key: row.capability_key,
    capability_kind: row.capability_kind,
    config: asObject(row.config),
    metadata: asObject(row.metadata),
    is_enabled: row.is_enabled,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function serializeIrCode(row: DeviceIrCodeRow) {
  return {
    id: row.id,
    device_id: row.device_id,
    owner_user_id: row.owner_user_id,
    code_name: row.code_name,
    protocol: row.protocol,
    protocol_norm: row.protocol_norm,
    frequency_hz: row.frequency_hz,
    frequency_norm_hz: row.frequency_norm_hz,
    payload_format: row.payload_format ?? "raw",
    payload_fingerprint: row.payload_fingerprint,
    source_type: row.source_type,
    source_ref: row.source_ref,
    payload: row.payload,
    normalized_payload: asObject(row.normalized_payload),
    metadata: asObject(row.metadata),
    learned_at: row.learned_at ? toIso(row.learned_at) : null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function serializeIrLibrarySource(row: IrLibrarySourceRow) {
  return {
    id: row.id,
    source_key: row.source_key,
    source_url: row.source_url,
    source_hash: row.source_hash,
    source_version: row.source_version,
    license: row.license,
    metadata: asObject(row.metadata),
    is_active: row.is_active,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function hasIrCapability(device: DeviceAccessRow): boolean {
  if (device.device_class === "ir_hub" || device.device_class === "hybrid") {
    return true;
  }
  const summary = asCapabilitySummary(device.capabilities);
  return summary.some(
    (item) =>
      item.enabled &&
      (item.key === "ir_tx" || item.key === "ir_rx" || item.kind === "infrared")
  );
}

async function upsertDeviceIrCode(params: {
  deviceId: string;
  ownerUserId: string | null;
  codeName: string;
  protocol: string;
  frequencyHz: number | null;
  payload: string;
  payloadFormat?: string | null;
  sourceType: "device" | "migration" | "library" | "user";
  sourceRef?: string | null;
  metadata: Record<string, unknown>;
  normalizedPayloadOverride?: Record<string, unknown> | null;
}): Promise<DeviceIrCodeRow> {
  const normalized = normalizeIrPayload({
    protocol: params.protocol,
    frequencyHz: params.frequencyHz,
    payload: params.payload,
    payloadFormat: params.payloadFormat
  });

  const mergedNormalizedPayload =
    params.normalizedPayloadOverride && Object.keys(params.normalizedPayloadOverride).length > 0
      ? {
        ...normalized.normalizedPayload,
        ...params.normalizedPayloadOverride
      }
      : normalized.normalizedPayload;

  const saved = await query<DeviceIrCodeRow>(
    `INSERT INTO device_ir_codes (
       id, device_id, owner_user_id, code_name, protocol, protocol_norm,
       frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
       source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7, $8, $9, $10, $11,
       $12, $13, $14::jsonb, $15::jsonb, $16, $17, $18
     )
     ON CONFLICT (device_id, code_name)
     DO UPDATE SET
       owner_user_id = EXCLUDED.owner_user_id,
       protocol = EXCLUDED.protocol,
       protocol_norm = EXCLUDED.protocol_norm,
       frequency_hz = EXCLUDED.frequency_hz,
       frequency_norm_hz = EXCLUDED.frequency_norm_hz,
       payload = EXCLUDED.payload,
       payload_format = EXCLUDED.payload_format,
       payload_fingerprint = EXCLUDED.payload_fingerprint,
       source_type = EXCLUDED.source_type,
       source_ref = EXCLUDED.source_ref,
       normalized_payload = EXCLUDED.normalized_payload,
       metadata = EXCLUDED.metadata,
       learned_at = EXCLUDED.learned_at,
       updated_at = EXCLUDED.updated_at
     RETURNING
       id, device_id, owner_user_id, code_name, protocol, protocol_norm,
       frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
       source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at`,
    [
      newId(),
      params.deviceId,
      params.ownerUserId,
      params.codeName.trim(),
      params.protocol.trim(),
      normalized.protocolNorm,
      params.frequencyHz,
      normalized.frequencyNormHz,
      params.payload,
      normalized.payloadFormat,
      normalized.payloadFingerprint,
      params.sourceType,
      params.sourceRef ?? null,
      JSON.stringify(mergedNormalizedPayload),
      JSON.stringify(params.metadata),
      nowIso(),
      nowIso(),
      nowIso()
    ]
  );

  return saved.rows[0];
}

async function loadIrRankRecords(deviceId: string): Promise<IrRankableRecord[]> {
  const deviceRows = await query<{
    id: string;
    code_name: string;
    protocol_norm: string | null;
    frequency_norm_hz: number | null;
    payload_fingerprint: string | null;
    payload: string;
    brand: string | null;
    model: string | null;
    metadata: unknown;
  }>(
    `SELECT
       id,
       code_name,
       protocol_norm,
       frequency_norm_hz,
       payload_fingerprint,
       payload,
       metadata->>'brand' AS brand,
       metadata->>'model' AS model,
       metadata
     FROM device_ir_codes
     WHERE device_id = $1`,
    [deviceId]
  );

  const libraryRows = await query<{
    id: string;
    protocol_norm: string;
    frequency_norm_hz: number | null;
    payload_fingerprint: string;
    payload: string;
    brand: string | null;
    model: string | null;
    metadata: unknown;
  }>(
    `SELECT
       r.id,
       r.protocol_norm,
       r.frequency_norm_hz,
       r.payload_fingerprint,
       r.payload,
       r.brand,
       r.model,
       r.metadata
     FROM ir_library_records r
     INNER JOIN ir_library_sources s ON s.id = r.source_id
     WHERE s.is_active = TRUE`
  );

  const out: IrRankableRecord[] = [];
  for (const row of deviceRows.rows) {
    const protocolNorm = row.protocol_norm ?? "UNKNOWN";
    const fingerprint = row.payload_fingerprint ?? "";
    if (!fingerprint) {
      continue;
    }
    out.push({
      source: "device",
      codeId: row.id,
      codeName: row.code_name,
      libraryRecordId: null,
      protocolNorm,
      frequencyNormHz: row.frequency_norm_hz,
      payloadFingerprint: fingerprint,
      payloadCanonical: row.payload,
      brand: row.brand,
      model: row.model,
      metadata: asObject(row.metadata)
    });
  }

  for (const row of libraryRows.rows) {
    out.push({
      source: "library",
      codeId: row.id,
      codeName: null,
      libraryRecordId: row.id,
      protocolNorm: row.protocol_norm,
      frequencyNormHz: row.frequency_norm_hz,
      payloadFingerprint: row.payload_fingerprint,
      payloadCanonical: row.payload,
      brand: row.brand,
      model: row.model,
      metadata: asObject(row.metadata)
    });
  }

  return out;
}

function serializeSensorState(row: DeviceSensorStateRow) {
  return {
    id: row.id,
    device_id: row.device_id,
    sensor_key: row.sensor_key,
    sensor_type: row.sensor_type,
    state: asObject(row.state),
    observed_at: toIso(row.observed_at),
    source: row.source,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function serializeSensorEvent(row: DeviceSensorEventRow) {
  return {
    id: row.id,
    device_id: row.device_id,
    sensor_key: row.sensor_key,
    sensor_type: row.sensor_type,
    event_kind: row.event_kind,
    value: asObject(row.value),
    observed_at: toIso(row.observed_at),
    source: row.source,
    created_at: toIso(row.created_at)
  };
}

async function getAccessibleDevice(params: {
  deviceId: string;
  userId: string;
  role: string;
}): Promise<DeviceAccessRow | null> {
  const result = await query<DeviceAccessRow>(
    `SELECT
       id,
       device_uid,
       owner_user_id,
       device_class,
       capabilities
     FROM devices
     WHERE id = $1
       AND ($2 = 'admin' OR owner_user_id = $3)
     LIMIT 1`,
    [params.deviceId, params.role, params.userId]
  );
  return result.rows[0] ?? null;
}

async function writeAudit(params: {
  deviceId: string;
  userId?: string;
  action: string;
  source: string;
  details: Record<string, unknown>;
}): Promise<void> {
  await query(
    `INSERT INTO audit_log (
       id, device_id, user_id, action, details, source, created_at
     ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
    [
      newId(),
      params.deviceId,
      params.userId ?? null,
      params.action,
      JSON.stringify(params.details),
      params.source,
      nowIso()
    ]
  );
}

async function syncCapabilitiesSummary(deviceId: string): Promise<void> {
  const rows = await query<{
    capability_key: string;
    capability_kind: string;
    is_enabled: boolean;
  }>(
    `SELECT capability_key, capability_kind, is_enabled
     FROM device_capabilities
     WHERE device_id = $1
     ORDER BY capability_key ASC`,
    [deviceId]
  );

  const summary = rows.rows.map((row) => ({
    key: row.capability_key,
    kind: row.capability_kind,
    enabled: row.is_enabled
  }));

  await query(
    `UPDATE devices
     SET capabilities = $1::jsonb,
         updated_at = $2
     WHERE id = $3`,
    [JSON.stringify(summary), nowIso(), deviceId]
  );
}

async function upsertSensorState(params: {
  deviceId: string;
  sensorKey: string;
  sensorType: string;
  state: Record<string, unknown>;
  observedAt: string;
  source: string;
}): Promise<void> {
  await query(
    `INSERT INTO device_sensor_state (
       id, device_id, sensor_key, sensor_type, state, observed_at, source, created_at, updated_at
     ) VALUES (
       $1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9
     )
     ON CONFLICT (device_id, sensor_key)
     DO UPDATE SET
       sensor_type = EXCLUDED.sensor_type,
       state = EXCLUDED.state,
       observed_at = EXCLUDED.observed_at,
       source = EXCLUDED.source,
       updated_at = EXCLUDED.updated_at`,
    [
      newId(),
      params.deviceId,
      params.sensorKey,
      params.sensorType,
      JSON.stringify(params.state),
      params.observedAt,
      params.source,
      nowIso(),
      nowIso()
    ]
  );
}

async function insertSensorEvent(params: {
  deviceId: string;
  sensorKey: string;
  sensorType: string;
  eventKind: string;
  value: Record<string, unknown>;
  observedAt: string;
  source: string;
}): Promise<void> {
  await query(
    `INSERT INTO device_sensor_events (
       id, device_id, sensor_key, sensor_type, event_kind, value, observed_at, source, created_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9
     )`,
    [
      newId(),
      params.deviceId,
      params.sensorKey,
      params.sensorType,
      params.eventKind,
      JSON.stringify(params.value),
      params.observedAt,
      params.source,
      nowIso()
    ]
  );
}

export async function deviceFeatureRoutes(server: FastifyInstance): Promise<void> {
  server.get("/:id/capabilities", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const rows = await query<DeviceCapabilityRow>(
      `SELECT
         id, device_id, capability_key, capability_kind, config, metadata, is_enabled, created_at, updated_at
       FROM device_capabilities
       WHERE device_id = $1
       ORDER BY capability_key ASC`,
      [params.id]
    );

    if (rows.rowCount && rows.rowCount > 0) {
      return reply.send({
        device_id: device.id,
        device_uid: device.device_uid,
        device_class: device.device_class,
        capabilities: rows.rows.map((row) => serializeCapability(row))
      });
    }

    return reply.send({
      device_id: device.id,
      device_uid: device.device_uid,
      device_class: device.device_class,
      capabilities_summary: asCapabilitySummary(device.capabilities)
    });
  });

  server.put("/:id/capabilities/:capabilityKey", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string; capabilityKey: string };
    const keyParsed = capabilityKeySchema.safeParse(params.capabilityKey);
    if (!keyParsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid capability key.");
    }

    const bodyParsed = capabilityUpsertSchema.safeParse(request.body);
    if (!bodyParsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", bodyParsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const payload = bodyParsed.data;
    const updated = await query<DeviceCapabilityRow>(
      `INSERT INTO device_capabilities (
         id, device_id, capability_key, capability_kind, config, metadata, is_enabled, created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9
       )
       ON CONFLICT (device_id, capability_key)
       DO UPDATE SET
         capability_kind = EXCLUDED.capability_kind,
         config = EXCLUDED.config,
         metadata = EXCLUDED.metadata,
         is_enabled = EXCLUDED.is_enabled,
         updated_at = EXCLUDED.updated_at
       RETURNING
         id, device_id, capability_key, capability_kind, config, metadata, is_enabled, created_at, updated_at`,
      [
        newId(),
        params.id,
        keyParsed.data,
        payload.capability_kind,
        JSON.stringify(payload.config),
        JSON.stringify(payload.metadata),
        payload.is_enabled,
        nowIso(),
        nowIso()
      ]
    );

    await syncCapabilitiesSummary(params.id);
    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_capability_upsert",
      source: "api",
      details: {
        capability_key: keyParsed.data,
        capability_kind: payload.capability_kind,
        is_enabled: payload.is_enabled
      }
    });

    return reply.send(serializeCapability(updated.rows[0]));
  });

  server.delete("/:id/capabilities/:capabilityKey", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string; capabilityKey: string };
    const keyParsed = capabilityKeySchema.safeParse(params.capabilityKey);
    if (!keyParsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid capability key.");
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const removed = await query(
      `DELETE FROM device_capabilities
       WHERE device_id = $1
         AND capability_key = $2`,
      [params.id, keyParsed.data]
    );
    if (!removed.rowCount || removed.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Capability not found.");
    }

    await syncCapabilitiesSummary(params.id);
    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_capability_delete",
      source: "api",
      details: {
        capability_key: keyParsed.data
      }
    });

    return reply.send({
      ok: true
    });
  });

  server.get("/:id/ir-codes", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const rows = await query<DeviceIrCodeRow>(
      `SELECT
         id, device_id, owner_user_id, code_name, protocol, protocol_norm,
         frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
         source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
       FROM device_ir_codes
       WHERE device_id = $1
       ORDER BY code_name ASC`,
      [params.id]
    );
    return reply.send(rows.rows.map((row) => serializeIrCode(row)));
  });

  server.post("/:id/ir-codes", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = irCodeCreateSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    if (!hasIrCapability(device)) {
      return sendApiError(reply, 409, "device_not_ir_capable", "Device does not expose IR capability.");
    }

    try {
      const normalized = normalizeIrPayload({
        protocol: parsed.data.protocol,
        frequencyHz: parsed.data.frequency_hz ?? null,
        payload: parsed.data.payload,
        payloadFormat: parsed.data.payload_format
      });
      const normalizedPayloadMerged =
        parsed.data.normalized_payload && Object.keys(parsed.data.normalized_payload).length > 0
          ? {
            ...normalized.normalizedPayload,
            ...parsed.data.normalized_payload
          }
          : normalized.normalizedPayload;

      const created = await query<DeviceIrCodeRow>(
        `INSERT INTO device_ir_codes (
           id, device_id, owner_user_id, code_name, protocol, protocol_norm,
           frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
           source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, $8, $9, $10, $11,
           $12, $13, $14::jsonb, $15::jsonb, $16, $17, $18
         )
         RETURNING
           id, device_id, owner_user_id, code_name, protocol, protocol_norm,
           frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
           source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at`,
        [
          newId(),
          params.id,
          request.user.sub,
          parsed.data.code_name.trim(),
          parsed.data.protocol.trim(),
          normalized.protocolNorm,
          parsed.data.frequency_hz ?? null,
          normalized.frequencyNormHz,
          parsed.data.payload,
          normalized.payloadFormat,
          normalized.payloadFingerprint,
          parsed.data.source_type ?? "user",
          parsed.data.source_ref ?? null,
          JSON.stringify(normalizedPayloadMerged),
          JSON.stringify(parsed.data.metadata),
          nowIso(),
          nowIso(),
          nowIso()
        ]
      );

      await writeAudit({
        deviceId: params.id,
        userId: request.user.sub,
        action: "device_ir_code_create",
        source: "api",
        details: {
          code_name: parsed.data.code_name,
          protocol: parsed.data.protocol
        }
      });

      return reply.code(201).send(serializeIrCode(created.rows[0]));
    } catch (error) {
      const pgError = error as { code?: string; constraint?: string } | undefined;
      if (pgError?.code === "23505" && pgError.constraint?.includes("device_ir_codes_device_id_code_name_key")) {
        return sendApiError(reply, 409, "ir_code_name_exists", "An IR code with this name already exists for device.");
      }
      throw error;
    }
  });

  server.patch("/:id/ir-codes/:codeId", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string; codeId: string };
    const parsed = irCodePatchSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    if (!hasIrCapability(device)) {
      return sendApiError(reply, 409, "device_not_ir_capable", "Device does not expose IR capability.");
    }
    if (Object.keys(parsed.data).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    try {
      const existingResult = await query<DeviceIrCodeRow>(
        `SELECT
           id, device_id, owner_user_id, code_name, protocol, protocol_norm,
           frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
           source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
         FROM device_ir_codes
         WHERE device_id = $1
           AND id = $2
         LIMIT 1`,
        [params.id, params.codeId]
      );
      const existing = existingResult.rows[0];
      if (!existing) {
        return sendApiError(reply, 404, "not_found", "IR code not found.");
      }

      const nextCodeName = parsed.data.code_name ? parsed.data.code_name.trim() : existing.code_name;
      const nextProtocol = parsed.data.protocol ? parsed.data.protocol.trim() : existing.protocol;
      const nextFrequencyHz =
        typeof parsed.data.frequency_hz === "undefined"
          ? existing.frequency_hz
          : parsed.data.frequency_hz;
      const nextPayload = parsed.data.payload ?? existing.payload;
      const nextPayloadFormat = parsed.data.payload_format ?? existing.payload_format ?? "raw";
      const nextSourceType =
        parsed.data.source_type ??
        ((existing.source_type as "device" | "migration" | "library" | "user" | null) ?? "user");
      const nextSourceRef =
        typeof parsed.data.source_ref === "undefined"
          ? existing.source_ref
          : parsed.data.source_ref;
      const nextMetadata = parsed.data.metadata ?? asObject(existing.metadata);
      const normalized = normalizeIrPayload({
        protocol: nextProtocol,
        frequencyHz: nextFrequencyHz,
        payload: nextPayload,
        payloadFormat: nextPayloadFormat
      });
      const normalizedPayloadMerged =
        parsed.data.normalized_payload && Object.keys(parsed.data.normalized_payload).length > 0
          ? {
            ...normalized.normalizedPayload,
            ...parsed.data.normalized_payload
          }
          : normalized.normalizedPayload;

      const updated = await query<DeviceIrCodeRow>(
        `UPDATE device_ir_codes
         SET owner_user_id = $1,
             code_name = $2,
             protocol = $3,
             protocol_norm = $4,
             frequency_hz = $5,
             frequency_norm_hz = $6,
             payload = $7,
             payload_format = $8,
             payload_fingerprint = $9,
             source_type = $10,
             source_ref = $11,
             normalized_payload = $12::jsonb,
             metadata = $13::jsonb,
             learned_at = $14,
             updated_at = $15
         WHERE device_id = $16
           AND id = $17
         RETURNING
           id, device_id, owner_user_id, code_name, protocol, protocol_norm,
           frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
           source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at`,
        [
          request.user.sub,
          nextCodeName,
          nextProtocol,
          normalized.protocolNorm,
          nextFrequencyHz,
          normalized.frequencyNormHz,
          nextPayload,
          normalized.payloadFormat,
          normalized.payloadFingerprint,
          nextSourceType,
          nextSourceRef ?? null,
          JSON.stringify(normalizedPayloadMerged),
          JSON.stringify(nextMetadata),
          nowIso(),
          nowIso(),
          params.id,
          params.codeId
        ]
      );

      await writeAudit({
        deviceId: params.id,
        userId: request.user.sub,
        action: "device_ir_code_update",
        source: "api",
        details: {
          code_id: params.codeId
        }
      });

      return reply.send(serializeIrCode(updated.rows[0]));
    } catch (error) {
      const pgError = error as { code?: string; constraint?: string } | undefined;
      if (pgError?.code === "23505" && pgError.constraint?.includes("device_ir_codes_device_id_code_name_key")) {
        return sendApiError(reply, 409, "ir_code_name_exists", "An IR code with this name already exists for device.");
      }
      throw error;
    }
  });

  server.delete("/:id/ir-codes/:codeId", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string; codeId: string };
    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    if (!hasIrCapability(device)) {
      return sendApiError(reply, 409, "device_not_ir_capable", "Device does not expose IR capability.");
    }

    const deleted = await query(
      `DELETE FROM device_ir_codes
       WHERE device_id = $1
         AND id = $2`,
      [params.id, params.codeId]
    );
    if (!deleted.rowCount || deleted.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "IR code not found.");
    }

    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_ir_code_delete",
      source: "api",
      details: {
        code_id: params.codeId
      }
    });

    return reply.send({
      ok: true
    });
  });

  server.post("/:id/ir-recognize", { preHandler: [authenticate] }, async (request, reply) => {
    if (!env.IR_AUTOREC_ENABLED) {
      return sendApiError(reply, 503, "feature_disabled", "IR auto-recognition is disabled.");
    }

    const params = request.params as { id: string };
    const parsed = irRecognizeSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    if (!hasIrCapability(device)) {
      return sendApiError(reply, 409, "device_not_ir_capable", "Device does not expose IR capability.");
    }

    const candidate = normalizeIrPayload({
      protocol: parsed.data.candidate.protocol,
      frequencyHz: parsed.data.candidate.frequency_hz ?? null,
      payload: parsed.data.candidate.payload,
      payloadFormat: parsed.data.candidate.payload_format
    });
    const rankRecords = await loadIrRankRecords(params.id);
    const matches = rankIrMatches(candidate, rankRecords, {
      brandHint: parsed.data.brand_hint,
      modelHint: parsed.data.model_hint,
      topN: parsed.data.top_n
    });

    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_ir_recognize",
      source: "api",
      details: {
        candidate_fingerprint: candidate.payloadFingerprint,
        top_n: parsed.data.top_n,
        result_count: matches.length
      }
    });

    return reply.send({
      device_id: params.id,
      candidate: {
        protocol_norm: candidate.protocolNorm,
        frequency_norm_hz: candidate.frequencyNormHz,
        payload_format: candidate.payloadFormat,
        payload_fingerprint: candidate.payloadFingerprint
      },
      matches
    });
  });

  server.post("/:id/ir-recognize-feedback", { preHandler: [authenticate] }, async (request, reply) => {
    if (!env.IR_AUTOREC_ENABLED) {
      return sendApiError(reply, 503, "feature_disabled", "IR auto-recognition is disabled.");
    }

    const params = request.params as { id: string };
    const parsed = irRecognizeFeedbackSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    await query(
      `INSERT INTO ir_match_feedback (
         id, device_id, owner_user_id, library_record_id, candidate_fingerprint,
         accepted, confidence, context, created_at
       ) VALUES (
         $1, $2, $3, $4, $5,
         $6, $7, $8::jsonb, $9
       )`,
      [
        newId(),
        params.id,
        request.user.sub,
        parsed.data.library_record_id ?? null,
        parsed.data.candidate_fingerprint,
        parsed.data.accepted,
        parsed.data.confidence ?? null,
        JSON.stringify(parsed.data.context),
        nowIso()
      ]
    );

    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_ir_recognize_feedback",
      source: "api",
      details: {
        accepted: parsed.data.accepted,
        library_record_id: parsed.data.library_record_id ?? null
      }
    });

    return reply.code(201).send({
      ok: true
    });
  });

  server.post("/ir-upload", async (request, reply) => {
    if (!env.IR_CLOUD_FEATURE_ENABLED) {
      return sendApiError(reply, 503, "feature_disabled", "Cloud IR upload is disabled.");
    }

    const parsed = deviceIrUploadSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const auth = await query<DeviceAuthRow>(
      `SELECT id, device_uid, owner_user_id
       FROM devices
       WHERE device_uid = $1
         AND device_token_hash = $2
         AND is_active = TRUE
       LIMIT 1`,
      [parsed.data.device_uid, sha256(parsed.data.device_token)]
    );
    const device = auth.rows[0];
    if (!device) {
      return sendApiError(reply, 401, "unauthorized", "Device credentials are invalid.");
    }

    let ingested = 0;
    let failed = 0;
    const errors: Array<{ index: number; code_name: string; error: string }> = [];

    for (let i = 0; i < parsed.data.records.length; i += 1) {
      const item = parsed.data.records[i];
      try {
        await upsertDeviceIrCode({
          deviceId: device.id,
          ownerUserId: device.owner_user_id,
          codeName: item.code_name,
          protocol: item.protocol,
          frequencyHz: item.frequency_hz ?? null,
          payload: item.payload,
          payloadFormat: item.payload_format,
          sourceType: "migration",
          sourceRef: item.source_ref ?? parsed.data.migration_id ?? null,
          metadata: {
            ...item.metadata,
            migration_partial: parsed.data.partial
          }
        });
        ingested += 1;
      } catch (error) {
        failed += 1;
        errors.push({
          index: i,
          code_name: item.code_name,
          error: error instanceof Error ? error.message : "unknown_error"
        });
      }
    }

    await writeAudit({
      deviceId: device.id,
      action: "device_ir_upload",
      source: "device",
      details: {
        migration_id: parsed.data.migration_id ?? null,
        partial: parsed.data.partial,
        ingested,
        failed
      }
    });

    return reply.send({
      ok: failed === 0,
      device_uid: device.device_uid,
      ingested,
      failed,
      errors
    });
  });

  server.post("/ir-library/ingest", { preHandler: [authenticate] }, async (request, reply) => {
    if (!env.IR_LIBRARY_INGEST_ENABLED) {
      return sendApiError(reply, 503, "feature_disabled", "IR library ingest is disabled.");
    }
    if (request.user.role !== "admin") {
      return sendApiError(reply, 403, "forbidden", "Only admin can ingest IR library records.");
    }

    const parsed = irLibraryIngestSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const source = await query<IrLibrarySourceRow>(
      `INSERT INTO ir_library_sources (
         id, source_key, source_url, source_hash, source_version, license, metadata, is_active, created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7::jsonb, TRUE, $8, $9
       )
       ON CONFLICT (source_key)
       DO UPDATE SET
         source_url = EXCLUDED.source_url,
         source_hash = EXCLUDED.source_hash,
         source_version = EXCLUDED.source_version,
         license = EXCLUDED.license,
         metadata = EXCLUDED.metadata,
         is_active = TRUE,
         updated_at = EXCLUDED.updated_at
       RETURNING
         id, source_key, source_url, source_hash, source_version, license, metadata, is_active, created_at, updated_at`,
      [
        newId(),
        parsed.data.source_key,
        parsed.data.manifest.source_url,
        parsed.data.manifest.source_hash,
        parsed.data.manifest.source_version,
        parsed.data.manifest.license,
        JSON.stringify(parsed.data.manifest.metadata),
        nowIso(),
        nowIso()
      ]
    );
    const sourceRow = source.rows[0];

    let upserted = 0;
    for (const item of parsed.data.records) {
      const normalized = normalizeIrPayload({
        protocol: item.protocol,
        frequencyHz: item.frequency_hz ?? null,
        payload: item.payload,
        payloadFormat: item.payload_format
      });

      await query<IrLibraryRecordRow>(
        `INSERT INTO ir_library_records (
           id, source_id, source_record_id, brand, model, protocol, protocol_norm,
           frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
           normalized_payload, metadata, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7,
           $8, $9, $10, $11, $12,
           $13::jsonb, $14::jsonb, $15, $16
         )
         ON CONFLICT (source_id, source_record_id)
         DO UPDATE SET
           brand = EXCLUDED.brand,
           model = EXCLUDED.model,
           protocol = EXCLUDED.protocol,
           protocol_norm = EXCLUDED.protocol_norm,
           frequency_hz = EXCLUDED.frequency_hz,
           frequency_norm_hz = EXCLUDED.frequency_norm_hz,
           payload = EXCLUDED.payload,
           payload_format = EXCLUDED.payload_format,
           payload_fingerprint = EXCLUDED.payload_fingerprint,
           normalized_payload = EXCLUDED.normalized_payload,
           metadata = EXCLUDED.metadata,
           updated_at = EXCLUDED.updated_at`,
        [
          newId(),
          sourceRow.id,
          item.source_record_id,
          item.brand ?? null,
          item.model ?? null,
          item.protocol.trim(),
          normalized.protocolNorm,
          item.frequency_hz ?? null,
          normalized.frequencyNormHz,
          item.payload,
          normalized.payloadFormat,
          normalized.payloadFingerprint,
          JSON.stringify(normalized.normalizedPayload),
          JSON.stringify(item.metadata),
          nowIso(),
          nowIso()
        ]
      );
      upserted += 1;
    }

    return reply.send({
      ok: true,
      source: serializeIrLibrarySource(sourceRow),
      upserted
    });
  });

  server.get("/:id/sensor-state", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const rows = await query<DeviceSensorStateRow>(
      `SELECT
         id, device_id, sensor_key, sensor_type, state, observed_at, source, created_at, updated_at
       FROM device_sensor_state
       WHERE device_id = $1
       ORDER BY sensor_key ASC`,
      [params.id]
    );
    return reply.send(rows.rows.map((row) => serializeSensorState(row)));
  });

  server.post("/:id/sensor-state", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = sensorStateUpsertSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const observedAt = parsed.data.observed_at ?? nowIso();
    await upsertSensorState({
      deviceId: params.id,
      sensorKey: parsed.data.sensor_key,
      sensorType: parsed.data.sensor_type,
      state: parsed.data.state,
      observedAt,
      source: parsed.data.source
    });
    await insertSensorEvent({
      deviceId: params.id,
      sensorKey: parsed.data.sensor_key,
      sensorType: parsed.data.sensor_type,
      eventKind: "state_update",
      value: parsed.data.state,
      observedAt,
      source: parsed.data.source
    });

    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_sensor_state_upsert",
      source: "api",
      details: {
        sensor_key: parsed.data.sensor_key,
        sensor_type: parsed.data.sensor_type,
        observed_at: observedAt
      }
    });

    return reply.code(201).send({
      ok: true,
      sensor_key: parsed.data.sensor_key,
      observed_at: observedAt
    });
  });

  server.get("/:id/sensor-events", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const queryParams = request.query as { sensor_key?: string; sensor_type?: string; limit?: string };
    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const filters: string[] = ["device_id = $1"];
    const values: unknown[] = [params.id];
    if (queryParams.sensor_key) {
      values.push(queryParams.sensor_key);
      filters.push(`sensor_key = $${values.length}`);
    }
    if (queryParams.sensor_type) {
      values.push(queryParams.sensor_type);
      filters.push(`sensor_type = $${values.length}`);
    }
    const limit = Math.min(Math.max(Number.parseInt(queryParams.limit ?? "100", 10) || 100, 1), 1000);
    values.push(limit);
    const limitArg = values.length;

    const rows = await query<DeviceSensorEventRow>(
      `SELECT
         id, device_id, sensor_key, sensor_type, event_kind, value, observed_at, source, created_at
       FROM device_sensor_events
       WHERE ${filters.join(" AND ")}
       ORDER BY observed_at DESC
       LIMIT $${limitArg}`,
      values
    );
    return reply.send(rows.rows.map((row) => serializeSensorEvent(row)));
  });

  server.post("/:id/sensor-events", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = sensorEventsIngestSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getAccessibleDevice({
      deviceId: params.id,
      userId: request.user.sub,
      role: request.user.role
    });
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    for (const event of parsed.data.events) {
      const observedAt = event.observed_at ?? nowIso();
      await insertSensorEvent({
        deviceId: params.id,
        sensorKey: event.sensor_key,
        sensorType: event.sensor_type,
        eventKind: event.event_kind,
        value: event.value,
        observedAt,
        source: event.source
      });
      await upsertSensorState({
        deviceId: params.id,
        sensorKey: event.sensor_key,
        sensorType: event.sensor_type,
        state: event.value,
        observedAt,
        source: event.source
      });
    }

    await writeAudit({
      deviceId: params.id,
      userId: request.user.sub,
      action: "device_sensor_events_ingest",
      source: "api",
      details: {
        count: parsed.data.events.length
      }
    });

    return reply.code(201).send({
      ok: true,
      ingested: parsed.data.events.length
    });
  });

  server.post("/sensor-report", async (request, reply) => {
    const parsed = deviceSensorReportSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const auth = await query<DeviceAuthRow>(
      `SELECT id, device_uid, owner_user_id
       FROM devices
       WHERE device_uid = $1
         AND device_token_hash = $2
         AND is_active = TRUE
       LIMIT 1`,
      [parsed.data.device_uid, sha256(parsed.data.device_token)]
    );
    const device = auth.rows[0];
    if (!device) {
      return sendApiError(reply, 401, "unauthorized", "Device credentials are invalid.");
    }

    for (const event of parsed.data.events) {
      const observedAt = event.observed_at ?? nowIso();
      await insertSensorEvent({
        deviceId: device.id,
        sensorKey: event.sensor_key,
        sensorType: event.sensor_type,
        eventKind: event.event_kind,
        value: event.value,
        observedAt,
        source: event.source
      });
      await upsertSensorState({
        deviceId: device.id,
        sensorKey: event.sensor_key,
        sensorType: event.sensor_type,
        state: event.value,
        observedAt,
        source: event.source
      });
    }

    await writeAudit({
      deviceId: device.id,
      action: "device_sensor_report",
      source: "system",
      details: {
        device_uid: device.device_uid,
        count: parsed.data.events.length
      }
    });

    return reply.send({
      ok: true,
      device_uid: device.device_uid,
      ingested: parsed.data.events.length
    });
  });
}
