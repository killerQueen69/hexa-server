import { FastifyInstance } from "fastify";
import { z } from "zod";
import { query, withTransaction } from "../../db/connection";
import { authenticate, requireRole } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import { realtimeHub } from "../../realtime/hub";
import { automationService } from "../../services/automation-service";
import { RelayServiceError, relayService } from "../../services/relay-service";
import { newId, randomClaimCode, randomToken, sha256 } from "../../utils/crypto";
import { deriveStableClaimCode } from "../../utils/claim-code";
import { nowIso } from "../../utils/time";

type DeviceRow = {
  id: string;
  device_uid: string;
  hardware_uid: string | null;
  name: string;
  model: string;
  device_class: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid";
  capabilities: unknown;
  relay_count: number;
  button_count: number;
  relay_names: unknown;
  input_config: unknown;
  power_restore_mode: string;
  firmware_version: string | null;
  last_seen_at: Date | string | null;
  last_ip: string | null;
  is_active: boolean;
  owner_user_id: string | null;
  claim_code: string | null;
  config: unknown;
  created_at: Date | string;
  updated_at: Date | string;
};

type InputConfigRow = {
  input_index: number;
  input_type: "push_button" | "rocker_switch";
  linked: boolean;
  target_relay_index: number | null;
  rocker_mode: "edge_toggle" | "follow_position" | null;
  invert_input: boolean;
  hold_seconds: number | null;
};

type ConnectivityUpdatePayload = {
  mode?: "cloud_ws" | "local_mqtt";
  mqtt?: {
    enabled?: boolean;
    host?: string;
    port?: number;
    username?: string;
    password?: string;
    discovery_prefix?: string;
    base_topic?: string;
    show_config?: boolean;
  };
};

type CapabilitySummary = {
  key: string;
  kind: string;
  enabled: boolean;
};

const deviceClassSchema = z.enum(["relay_controller", "ir_hub", "sensor_hub", "hybrid"]);
const capabilitySummaryItemSchema = z.object({
  key: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
  kind: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
  enabled: z.boolean().default(true)
});

const createDeviceSchema = z.object({
  device_uid: z.string().min(3).max(100).regex(/^[a-zA-Z0-9._-]+$/),
  hardware_uid: z.string().min(3).max(100).regex(/^[a-zA-Z0-9._:-]+$/).optional(),
  name: z.string().min(1).max(100),
  model: z.string().min(1).max(100).default("hexa-mini-switch-v1"),
  device_class: deviceClassSchema.default("relay_controller"),
  relay_count: z.number().int().min(0).max(8).default(3),
  button_count: z.number().int().min(0).max(8).default(3),
  capabilities: z.array(capabilitySummaryItemSchema).optional(),
  relay_names: z.array(z.string().min(1).max(50)).optional(),
  input_config: z.array(z.unknown()).default([]),
  power_restore_mode: z.enum(["last_state", "all_off", "all_on"]).default("last_state"),
  config: z.record(z.unknown()).default({})
});

const inputConfigItemSchema = z.object({
  input_index: z.number().int().min(0),
  input_type: z.enum(["push_button", "rocker_switch"]),
  linked: z.boolean(),
  target_relay_index: z.number().int().min(0).nullable(),
  rocker_mode: z.enum(["edge_toggle", "follow_position"]).nullable(),
  invert_input: z.boolean(),
  hold_seconds: z.number().int().min(1).max(600).nullable()
});

const updateDeviceSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  is_active: z.boolean().optional(),
  firmware_version: z.string().min(1).max(100).optional(),
  device_class: deviceClassSchema.optional(),
  capabilities: z.array(capabilitySummaryItemSchema).optional(),
  input_config: z.array(inputConfigItemSchema).optional(),
  power_restore_mode: z.enum(["last_state", "all_off", "all_on"]).optional(),
  config: z.record(z.unknown()).optional()
});

const updateIoConfigSchema = z.object({
  input_config: z.array(inputConfigItemSchema)
});

const updatePowerRestoreSchema = z.object({
  power_restore_mode: z.enum(["last_state", "all_off", "all_on"])
});

const claimDeviceSchema = z.object({
  claim_code: z.string().min(6).max(24).regex(/^[a-zA-Z0-9]+$/)
});

const relayCommandSchema = z.object({
  action: z.enum(["on", "off", "toggle"]),
  timeout_ms: z.number().int().min(1000).max(30000).optional()
});

const allRelayCommandSchema = z.object({
  action: z.enum(["on", "off"]),
  timeout_ms: z.number().int().min(1000).max(30000).optional()
});

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function serializeDevice(row: DeviceRow, userId?: string) {
  return {
    id: row.id,
    device_uid: row.device_uid,
    hardware_uid: row.hardware_uid,
    name: row.name,
    model: row.model,
    device_class: row.device_class,
    capabilities: normalizeCapabilities(row.device_class, row.relay_count, row.capabilities),
    relay_count: row.relay_count,
    button_count: row.button_count,
    relay_names: row.relay_names,
    input_config: row.input_config,
    power_restore_mode: row.power_restore_mode,
    firmware_version: row.firmware_version,
    last_seen_at: row.last_seen_at ? toIso(row.last_seen_at) : null,
    last_ip: row.last_ip,
    is_active: row.is_active,
    is_claimed: row.owner_user_id !== null,
    is_owner: userId ? row.owner_user_id === userId : false,
    config: row.config,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function defaultCapabilities(
  deviceClass: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid",
  relayCount: number
): CapabilitySummary[] {
  const out: CapabilitySummary[] = [];
  if (relayCount > 0 && (deviceClass === "relay_controller" || deviceClass === "hybrid")) {
    out.push({
      key: "relay",
      kind: "actuator",
      enabled: true
    });
  }
  if (deviceClass === "ir_hub" || deviceClass === "hybrid") {
    out.push({
      key: "ir_tx",
      kind: "infrared",
      enabled: true
    });
    out.push({
      key: "ir_rx",
      kind: "infrared",
      enabled: true
    });
  }
  if (deviceClass === "sensor_hub" || deviceClass === "hybrid") {
    out.push({
      key: "sensor",
      kind: "telemetry",
      enabled: true
    });
  }
  return out;
}

function normalizeCapabilities(
  deviceClass: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid",
  relayCount: number,
  capabilities: unknown
): CapabilitySummary[] {
  if (!Array.isArray(capabilities)) {
    return defaultCapabilities(deviceClass, relayCount);
  }

  const seen = new Set<string>();
  const normalized: CapabilitySummary[] = [];
  for (const item of capabilities) {
    const parsed = capabilitySummaryItemSchema.safeParse(item);
    if (!parsed.success) {
      continue;
    }
    const key = parsed.data.key.trim();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    normalized.push({
      key,
      kind: parsed.data.kind.trim(),
      enabled: parsed.data.enabled
    });
  }

  if (normalized.length > 0) {
    return normalized;
  }
  return defaultCapabilities(deviceClass, relayCount);
}

function buildRelayNames(relayCount: number): string[] {
  return Array.from({ length: relayCount }, (_, idx) => `Relay ${idx + 1}`);
}

function validateInputConfigMatrix(
  device: DeviceRow,
  inputConfig: InputConfigRow[]
): InputConfigRow[] {
  if (inputConfig.length !== device.button_count) {
    throw new Error("input_config_size_mismatch");
  }

  const seen = new Set<number>();
  for (const cfg of inputConfig) {
    if (cfg.input_index >= device.button_count) {
      throw new Error("input_index_out_of_range");
    }

    if (seen.has(cfg.input_index)) {
      throw new Error("duplicate_input_index");
    }
    seen.add(cfg.input_index);

    if (cfg.linked) {
      if (!Number.isInteger(cfg.target_relay_index)) {
        throw new Error("target_relay_required");
      }
      if (
        (cfg.target_relay_index as number) < 0 ||
        (cfg.target_relay_index as number) >= device.relay_count
      ) {
        throw new Error("target_relay_out_of_range");
      }
    } else if (cfg.target_relay_index !== null) {
      throw new Error("target_relay_not_allowed");
    }

    if (cfg.input_type === "push_button") {
      if (cfg.rocker_mode !== null) {
        throw new Error("rocker_mode_not_allowed");
      }
    } else {
      if (cfg.rocker_mode === null) {
        throw new Error("rocker_mode_required");
      }
      if (cfg.hold_seconds !== null) {
        throw new Error("hold_seconds_not_allowed");
      }
    }
  }

  for (let i = 0; i < device.button_count; i += 1) {
    if (!seen.has(i)) {
      throw new Error("missing_input_index");
    }
  }

  return [...inputConfig].sort((a, b) => a.input_index - b.input_index);
}

function normalizeInputConfigError(error: Error): string {
  switch (error.message) {
    case "input_config_size_mismatch":
      return "input_config length must match device button_count.";
    case "input_index_out_of_range":
      return "input_index is outside device button range.";
    case "duplicate_input_index":
      return "input_index values must be unique.";
    case "missing_input_index":
      return "input_config must include every input index from 0..button_count-1.";
    case "target_relay_required":
      return "target_relay_index is required when linked is true.";
    case "target_relay_out_of_range":
      return "target_relay_index is outside relay range.";
    case "target_relay_not_allowed":
      return "target_relay_index must be null when linked is false.";
    case "rocker_mode_not_allowed":
      return "rocker_mode must be null for push_button input_type.";
    case "rocker_mode_required":
      return "rocker_mode is required for rocker_switch input_type.";
    case "hold_seconds_not_allowed":
      return "hold_seconds must be null for rocker_switch input_type.";
    default:
      return "Invalid input_config matrix.";
  }
}

function pushDeviceConfigUpdate(
  deviceUid: string,
  payload: {
    io_config?: InputConfigRow[];
    power_restore_mode?: "last_state" | "all_off" | "all_on";
    connectivity?: ConnectivityUpdatePayload;
  }
): void {
  realtimeHub.sendToDevice(deviceUid, {
    type: "config_update",
    ...payload,
    ts: nowIso()
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function normalizeConnectionMode(value: unknown): "cloud_ws" | "local_mqtt" | null {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "cloud_ws" || normalized === "cloud" || normalized === "app") {
    return "cloud_ws";
  }
  if (normalized === "local_mqtt" || normalized === "ha" || normalized === "mqtt") {
    return "local_mqtt";
  }
  return null;
}

function extractConnectivityUpdate(configValue: unknown): ConnectivityUpdatePayload | undefined {
  const config = asRecord(configValue);
  if (!config) {
    return undefined;
  }

  const connectivity = asRecord(config.connectivity) ?? asRecord(config.connection);
  if (!connectivity) {
    return undefined;
  }

  const out: ConnectivityUpdatePayload = {};
  const mode = normalizeConnectionMode(
    connectivity.mode ?? connectivity.connection_mode ?? connectivity.transport_mode
  );
  if (mode) {
    out.mode = mode;
  }

  const mqttSource =
    asRecord(connectivity.mqtt) ??
    asRecord(connectivity.local_mqtt) ??
    asRecord(config.local_mqtt);
  if (mqttSource) {
    const mqtt: NonNullable<ConnectivityUpdatePayload["mqtt"]> = {};
    if (typeof mqttSource.enabled === "boolean") {
      mqtt.enabled = mqttSource.enabled;
    } else if (typeof mqttSource.enable === "boolean") {
      mqtt.enabled = mqttSource.enable;
    }
    if (typeof mqttSource.host === "string" && mqttSource.host.trim().length > 0) {
      mqtt.host = mqttSource.host.trim();
    }
    if (typeof mqttSource.port === "number" && Number.isInteger(mqttSource.port)) {
      const port = mqttSource.port;
      if (port > 0 && port <= 65535) {
        mqtt.port = port;
      }
    }
    if (typeof mqttSource.username === "string") {
      mqtt.username = mqttSource.username;
    } else if (typeof mqttSource.user === "string") {
      mqtt.username = mqttSource.user;
    }
    if (typeof mqttSource.password === "string") {
      mqtt.password = mqttSource.password;
    } else if (typeof mqttSource.pass === "string") {
      mqtt.password = mqttSource.pass;
    }
    if (typeof mqttSource.discovery_prefix === "string") {
      mqtt.discovery_prefix = mqttSource.discovery_prefix;
    }
    if (typeof mqttSource.base_topic === "string") {
      mqtt.base_topic = mqttSource.base_topic;
    }
    if (typeof mqttSource.show_config === "boolean") {
      mqtt.show_config = mqttSource.show_config;
    } else if (typeof mqttSource.showConfig === "boolean") {
      mqtt.show_config = mqttSource.showConfig;
    }

    if (Object.keys(mqtt).length > 0) {
      out.mqtt = mqtt;
    }
  }

  if (!out.mode && !out.mqtt) {
    return undefined;
  }
  return out;
}

async function getOwnedDevice(deviceId: string, userId: string): Promise<DeviceRow | null> {
  const result = await query<DeviceRow>(
    `SELECT
       id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
       input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
       is_active, owner_user_id, claim_code, config, created_at, updated_at
     FROM devices
     WHERE id = $1
       AND owner_user_id = $2
     LIMIT 1`,
    [deviceId, userId]
  );
  return result.rows[0] ?? null;
}

export async function deviceRoutes(server: FastifyInstance): Promise<void> {
  server.get("/", { preHandler: [authenticate] }, async (request, reply) => {
    const result = await query<DeviceRow>(
      `SELECT
         id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
         input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
         is_active, owner_user_id, claim_code, config, created_at, updated_at
       FROM devices
       WHERE owner_user_id = $1
       ORDER BY created_at DESC`,
      [request.user.sub]
    );

    return reply.send(result.rows.map((row) => serializeDevice(row, request.user.sub)));
  });

  server.get("/:id", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const row = await getOwnedDevice(params.id, request.user.sub);
    if (!row) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    return reply.send(serializeDevice(row, request.user.sub));
  });

  server.post(
    "/claim",
    { preHandler: [authenticate] },
    async (request, reply) => {
      const parsed = claimDeviceSchema.safeParse(request.body);
      if (!parsed.success) {
        return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
      }

      const claimCode = parsed.data.claim_code.trim().toUpperCase();
      const now = nowIso();

      const claimed = await withTransaction(async (client) => {
        const candidate = await client.query<DeviceRow>(
          `SELECT
             id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
             input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
             is_active, owner_user_id, claim_code, config, created_at, updated_at
           FROM devices
           WHERE claim_code = $1
             AND owner_user_id IS NULL
             AND is_active = TRUE
           LIMIT 1
           FOR UPDATE`,
          [claimCode]
        );
        const row = candidate.rows[0];
        if (!row) {
          return null;
        }

        await client.query(
          `UPDATE devices
           SET owner_user_id = $1,
               updated_at = $2
           WHERE id = $3`,
          [request.user.sub, now, row.id]
        );

        await client.query("DELETE FROM user_devices WHERE device_id = $1", [row.id]);
        await client.query(
          `INSERT INTO user_devices (id, user_id, device_id, permission, created_at)
           VALUES ($1, $2, $3, 'admin', $4)`,
          [newId(), request.user.sub, row.id, now]
        );

        return {
          ...row,
          owner_user_id: request.user.sub,
          claim_code: row.claim_code,
          updated_at: now
        };
      });

      if (!claimed) {
        return sendApiError(reply, 404, "claim_code_invalid", "Claim code is invalid or already used.");
      }

      if (realtimeHub.getDevice(claimed.device_uid)) {
        realtimeHub.broadcastToUser(request.user.sub, {
          type: "device_online",
          device_uid: claimed.device_uid,
          ts: nowIso()
        });
      }

      await automationService.ensureDefaultHoldRule(request.user.sub, claimed.id);

      return reply.send({
        ok: true,
        device: serializeDevice(claimed, request.user.sub)
      });
    }
  );

  server.post("/:id/release", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const now = nowIso();

    const released = await withTransaction(async (client) => {
      const ownerCheck = await client.query<{
        id: string;
        device_uid: string;
        hardware_uid: string | null;
        claim_code: string | null;
        claim_code_created_at: Date | string | null;
      }>(
        `SELECT id, device_uid, hardware_uid, claim_code, claim_code_created_at
         FROM devices
         WHERE id = $1
           AND owner_user_id = $2
         LIMIT 1
         FOR UPDATE`,
        [params.id, request.user.sub]
      );
      const row = ownerCheck.rows[0];
      if (!row) {
        return null;
      }
      const claimCode = deriveStableClaimCode({
        existingClaimCode: row.claim_code,
        hardwareUid: row.hardware_uid,
        deviceUid: row.device_uid
      });
      const claimCodeCreatedAt = row.claim_code_created_at
        ? (row.claim_code_created_at instanceof Date
            ? row.claim_code_created_at.toISOString()
            : row.claim_code_created_at)
        : now;

      await client.query(
        `UPDATE devices
         SET owner_user_id = NULL,
             claim_code = $1,
             claim_code_created_at = $2,
             updated_at = $3
         WHERE id = $4`,
        [claimCode, claimCodeCreatedAt, now, params.id]
      );
      await client.query("DELETE FROM user_devices WHERE device_id = $1", [params.id]);

      return {
        ...row,
        claim_code: claimCode
      };
    });

    if (!released) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    return reply.send({
      ok: true,
      claim_code: released.claim_code
    });
  });

  server.post(
    "/",
    { preHandler: [authenticate, requireRole(["admin"])] },
    async (request, reply) => {
      const parsed = createDeviceSchema.safeParse(request.body);
      if (!parsed.success) {
        return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
      }

      const payload = parsed.data;
      const relayNames = payload.relay_names ?? buildRelayNames(payload.relay_count);
      if (relayNames.length !== payload.relay_count) {
        return sendApiError(reply, 400, "validation_error", "relay_names length must match relay_count.");
      }
      const normalizedCapabilities = normalizeCapabilities(
        payload.device_class,
        payload.relay_count,
        payload.capabilities
      );

      const deviceId = newId();
      const rawToken = randomToken(32);
      const tokenHash = sha256(rawToken);
      const claimCode = randomClaimCode(8);
      const now = nowIso();

      try {
        const createdDevice = await withTransaction(async (client) => {
          const inserted = await client.query<DeviceRow>(
            `INSERT INTO devices (
               id, device_uid, hardware_uid, name, device_token_hash, model, device_class, capabilities, relay_count, button_count,
               relay_names, input_config, power_restore_mode, firmware_version, is_active, owner_user_id,
               claim_code, claim_code_created_at, config, created_at, updated_at
             ) VALUES (
               $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10,
               $11::jsonb, $12::jsonb, $13, NULL, TRUE, NULL,
               $14, $15, $16::jsonb, $17, $18
             )
             RETURNING
               id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
               input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
               is_active, owner_user_id, claim_code, config, created_at, updated_at`,
            [
              deviceId,
              payload.device_uid,
              payload.hardware_uid ?? null,
              payload.name.trim(),
              tokenHash,
              payload.model,
              payload.device_class,
              JSON.stringify(normalizedCapabilities),
              payload.relay_count,
              payload.button_count,
              JSON.stringify(relayNames),
              JSON.stringify(payload.input_config),
              payload.power_restore_mode,
              claimCode,
              now,
              JSON.stringify(payload.config),
              now,
              now
            ]
          );

          for (let idx = 0; idx < payload.relay_count; idx += 1) {
            await client.query(
              `INSERT INTO relay_states (
                 id, device_id, relay_index, relay_name, is_on, last_changed_at
               ) VALUES ($1, $2, $3, $4, FALSE, $5)`,
              [newId(), deviceId, idx, relayNames[idx], now]
            );
          }

          return inserted.rows[0];
        });

        return reply.code(201).send({
          device: serializeDevice(createdDevice),
          device_token: rawToken,
          claim_code: claimCode
        });
      } catch (error) {
        const pgError = error as { code?: string; constraint?: string } | undefined;
        if (pgError?.code === "23505" && pgError.constraint?.includes("device_uid")) {
          return sendApiError(reply, 409, "device_uid_exists", "Device UID already exists.");
        }
        if (pgError?.code === "23505" && pgError.constraint?.includes("hardware_uid")) {
          return sendApiError(reply, 409, "hardware_uid_exists", "Hardware UID already exists.");
        }
        throw error;
      }
    }
  );

  server.patch("/:id", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateDeviceSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const owned = await getOwnedDevice(params.id, request.user.sub);
    if (!owned) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    let nextInputConfig: InputConfigRow[] | null = null;
    if (typeof changes.input_config !== "undefined") {
      try {
        nextInputConfig = validateInputConfigMatrix(owned, changes.input_config as InputConfigRow[]);
      } catch (error) {
        return sendApiError(reply, 400, "validation_error", normalizeInputConfigError(error as Error));
      }
    }

    const fields: string[] = [];
    const values: unknown[] = [];

    if (typeof changes.name !== "undefined") {
      values.push(changes.name.trim());
      fields.push(`name = $${values.length}`);
    }
    if (typeof changes.is_active !== "undefined") {
      values.push(changes.is_active);
      fields.push(`is_active = $${values.length}`);
    }
    if (typeof changes.firmware_version !== "undefined") {
      values.push(changes.firmware_version);
      fields.push(`firmware_version = $${values.length}`);
    }
    let nextCapabilities: CapabilitySummary[] | null = null;
    if (typeof changes.capabilities !== "undefined") {
      nextCapabilities = normalizeCapabilities(
        changes.device_class ?? owned.device_class,
        owned.relay_count,
        changes.capabilities
      );
    } else if (typeof changes.device_class !== "undefined") {
      nextCapabilities = normalizeCapabilities(changes.device_class, owned.relay_count, owned.capabilities);
    }
    if (typeof changes.device_class !== "undefined") {
      values.push(changes.device_class);
      fields.push(`device_class = $${values.length}`);
    }
    if (nextCapabilities) {
      values.push(JSON.stringify(nextCapabilities));
      fields.push(`capabilities = $${values.length}::jsonb`);
    }
    if (typeof changes.input_config !== "undefined") {
      values.push(JSON.stringify(nextInputConfig ?? changes.input_config));
      fields.push(`input_config = $${values.length}::jsonb`);
    }
    if (typeof changes.power_restore_mode !== "undefined") {
      values.push(changes.power_restore_mode);
      fields.push(`power_restore_mode = $${values.length}`);
    }
    if (typeof changes.config !== "undefined") {
      values.push(JSON.stringify(changes.config));
      fields.push(`config = $${values.length}::jsonb`);
    }

    values.push(nowIso());
    fields.push(`updated_at = $${values.length}`);

    values.push(params.id);
    values.push(request.user.sub);
    const idArgPos = values.length - 1;
    const ownerArgPos = values.length;

    const updated = await query<DeviceRow>(
      `UPDATE devices
       SET ${fields.join(", ")}
       WHERE id = $${idArgPos}
         AND owner_user_id = $${ownerArgPos}
       RETURNING
         id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
         input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
         is_active, owner_user_id, claim_code, config, created_at, updated_at`,
      values
    );

    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    const connectivityUpdate =
      typeof changes.config !== "undefined" ? extractConnectivityUpdate(updated.rows[0].config) : undefined;

    if (nextInputConfig || typeof changes.power_restore_mode !== "undefined" || connectivityUpdate) {
      pushDeviceConfigUpdate(updated.rows[0].device_uid, {
        io_config: nextInputConfig ?? undefined,
        power_restore_mode: changes.power_restore_mode,
        connectivity: connectivityUpdate
      });
    }

    return reply.send(serializeDevice(updated.rows[0], request.user.sub));
  });

  server.patch("/:id/io-config", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateIoConfigSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const owned = await getOwnedDevice(params.id, request.user.sub);
    if (!owned) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    let normalized: InputConfigRow[];
    try {
      normalized = validateInputConfigMatrix(owned, parsed.data.input_config);
    } catch (error) {
      return sendApiError(reply, 400, "validation_error", normalizeInputConfigError(error as Error));
    }

    const updated = await query<DeviceRow>(
      `UPDATE devices
       SET input_config = $1::jsonb,
           updated_at = $2
       WHERE id = $3
         AND owner_user_id = $4
       RETURNING
         id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
         input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
         is_active, owner_user_id, claim_code, config, created_at, updated_at`,
      [JSON.stringify(normalized), nowIso(), params.id, request.user.sub]
    );
    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    pushDeviceConfigUpdate(updated.rows[0].device_uid, {
      io_config: normalized
    });

    return reply.send(serializeDevice(updated.rows[0], request.user.sub));
  });

  server.patch("/:id/power-restore-mode", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updatePowerRestoreSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const owned = await getOwnedDevice(params.id, request.user.sub);
    if (!owned) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    const updated = await query<DeviceRow>(
      `UPDATE devices
       SET power_restore_mode = $1,
           updated_at = $2
       WHERE id = $3
         AND owner_user_id = $4
       RETURNING
         id, device_uid, hardware_uid, name, model, device_class, capabilities, relay_count, button_count, relay_names,
         input_config, power_restore_mode, firmware_version, last_seen_at, last_ip,
         is_active, owner_user_id, claim_code, config, created_at, updated_at`,
      [parsed.data.power_restore_mode, nowIso(), params.id, request.user.sub]
    );
    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    pushDeviceConfigUpdate(updated.rows[0].device_uid, {
      power_restore_mode: parsed.data.power_restore_mode
    });

    return reply.send(serializeDevice(updated.rows[0], request.user.sub));
  });

  server.post("/:id/relays/:index", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string; index: string };
    const relayIndex = Number.parseInt(params.index, 10);
    if (!Number.isInteger(relayIndex)) {
      return sendApiError(reply, 400, "validation_error", "Relay index must be an integer.");
    }

    const parsed = relayCommandSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const owned = await getOwnedDevice(params.id, request.user.sub);
    if (!owned) {
      return sendApiError(reply, 403, "forbidden", "Only the device owner can control this device.");
    }

    try {
      const result = await relayService.setRelay({
        deviceId: params.id,
        relayIndex,
        action: parsed.data.action,
        timeoutMs: parsed.data.timeout_ms,
        source: {
          actorUserId: request.user.sub,
          source: "api"
        }
      });

      return reply.send(result);
    } catch (error) {
      if (error instanceof RelayServiceError) {
        return sendApiError(reply, error.statusCode, error.code, error.message, error.details);
      }

      throw error;
    }
  });

  server.post("/:id/relays/all", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = allRelayCommandSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const owned = await getOwnedDevice(params.id, request.user.sub);
    if (!owned) {
      return sendApiError(reply, 403, "forbidden", "Only the device owner can control this device.");
    }

    try {
      const result = await relayService.setAllRelays({
        deviceId: params.id,
        action: parsed.data.action,
        timeoutMs: parsed.data.timeout_ms,
        source: {
          actorUserId: request.user.sub,
          source: "api"
        }
      });

      return reply.send(result);
    } catch (error) {
      if (error instanceof RelayServiceError) {
        return sendApiError(reply, error.statusCode, error.code, error.message, error.details);
      }

      throw error;
    }
  });

  server.post("/:id/token/rotate", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const owned = await getOwnedDevice(params.id, request.user.sub);
    if (!owned) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    const rawToken = randomToken(32);
    const tokenHash = sha256(rawToken);
    await query(
      `UPDATE devices
       SET device_token_hash = $1, updated_at = $2
       WHERE id = $3`,
      [tokenHash, nowIso(), params.id]
    );

    return reply.send({
      ok: true,
      device_token: rawToken
    });
  });

  server.delete("/:id", { preHandler: [authenticate, requireRole(["admin"])] }, async (request, reply) => {
    const params = request.params as { id: string };
    const result = await query("DELETE FROM devices WHERE id = $1", [params.id]);
    if (!result.rowCount || result.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    return reply.send({ ok: true });
  });
}
