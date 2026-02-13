import { FastifyInstance } from "fastify";
import { z } from "zod";
import { query } from "../../db/connection";
import { authenticate } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
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
  frequency_hz: number | null;
  payload: string;
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
  payload: z.string().min(1).max(20000),
  metadata: z.record(z.unknown()).default({})
});

const irCodePatchSchema = z.object({
  code_name: z.string().min(1).max(120).optional(),
  protocol: z.string().min(1).max(80).optional(),
  frequency_hz: z.number().int().min(1).max(1000000).nullable().optional(),
  payload: z.string().min(1).max(20000).optional(),
  metadata: z.record(z.unknown()).optional()
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
    frequency_hz: row.frequency_hz,
    payload: row.payload,
    metadata: asObject(row.metadata),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
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
         id, device_id, owner_user_id, code_name, protocol, frequency_hz, payload, metadata, created_at, updated_at
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

    try {
      const created = await query<DeviceIrCodeRow>(
        `INSERT INTO device_ir_codes (
           id, device_id, owner_user_id, code_name, protocol, frequency_hz, payload, metadata, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10
         )
         RETURNING
           id, device_id, owner_user_id, code_name, protocol, frequency_hz, payload, metadata, created_at, updated_at`,
        [
          newId(),
          params.id,
          request.user.sub,
          parsed.data.code_name.trim(),
          parsed.data.protocol.trim(),
          parsed.data.frequency_hz ?? null,
          parsed.data.payload,
          JSON.stringify(parsed.data.metadata),
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
    if (Object.keys(parsed.data).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    const fields: string[] = [];
    const values: unknown[] = [];
    if (typeof parsed.data.code_name !== "undefined") {
      values.push(parsed.data.code_name.trim());
      fields.push(`code_name = $${values.length}`);
    }
    if (typeof parsed.data.protocol !== "undefined") {
      values.push(parsed.data.protocol.trim());
      fields.push(`protocol = $${values.length}`);
    }
    if (typeof parsed.data.frequency_hz !== "undefined") {
      values.push(parsed.data.frequency_hz);
      fields.push(`frequency_hz = $${values.length}`);
    }
    if (typeof parsed.data.payload !== "undefined") {
      values.push(parsed.data.payload);
      fields.push(`payload = $${values.length}`);
    }
    if (typeof parsed.data.metadata !== "undefined") {
      values.push(JSON.stringify(parsed.data.metadata));
      fields.push(`metadata = $${values.length}::jsonb`);
    }
    values.push(nowIso());
    fields.push(`updated_at = $${values.length}`);
    values.push(params.id);
    const deviceArg = values.length;
    values.push(params.codeId);
    const codeArg = values.length;

    try {
      const updated = await query<DeviceIrCodeRow>(
        `UPDATE device_ir_codes
         SET ${fields.join(", ")}
         WHERE device_id = $${deviceArg}
           AND id = $${codeArg}
         RETURNING
           id, device_id, owner_user_id, code_name, protocol, frequency_hz, payload, metadata, created_at, updated_at`,
        values
      );
      if (!updated.rowCount || updated.rowCount === 0) {
        return sendApiError(reply, 404, "not_found", "IR code not found.");
      }

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
