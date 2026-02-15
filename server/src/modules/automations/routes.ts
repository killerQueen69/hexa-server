import { FastifyInstance } from "fastify";
import { z } from "zod";
import { query } from "../../db/connection";
import { authenticate } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import { deviceFallbackSyncService } from "../../services/device-fallback-sync-service";
import { newId } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type DeviceOwnershipRow = {
  id: string;
  relay_count: number;
  button_count: number;
};

type AutomationRuleRow = {
  id: string;
  user_id: string;
  device_id: string | null;
  name: string;
  trigger_type: "input_event" | "button_hold" | "device_online" | "device_offline";
  trigger_config: unknown;
  condition_config: unknown;
  action_type: "set_relay" | "set_all_relays";
  action_config: unknown;
  cooldown_seconds: number;
  is_enabled: boolean;
  last_triggered_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

const createAutomationSchema = z.object({
  device_id: z.string().min(1),
  name: z.string().min(1).max(120),
  trigger_type: z.enum(["input_event", "button_hold", "device_online", "device_offline"]),
  trigger_config: z.record(z.unknown()).default({}),
  condition_config: z.record(z.unknown()).default({}),
  action_type: z.enum(["set_relay", "set_all_relays"]),
  action_config: z.record(z.unknown()).default({}),
  cooldown_seconds: z.number().int().min(0).max(86400).default(0),
  is_enabled: z.boolean().default(true)
});

const updateAutomationSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  trigger_type: z.enum(["input_event", "button_hold", "device_online", "device_offline"]).optional(),
  trigger_config: z.record(z.unknown()).optional(),
  condition_config: z.record(z.unknown()).optional(),
  action_type: z.enum(["set_relay", "set_all_relays"]).optional(),
  action_config: z.record(z.unknown()).optional(),
  cooldown_seconds: z.number().int().min(0).max(86400).optional(),
  is_enabled: z.boolean().optional()
});

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toIsoOrNull(value: Date | string | null): string | null {
  if (!value) {
    return null;
  }
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function parseNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function validateAutomationConfig(params: {
  triggerType: "input_event" | "button_hold" | "device_online" | "device_offline";
  triggerConfig: Record<string, unknown>;
  actionType: "set_relay" | "set_all_relays";
  actionConfig: Record<string, unknown>;
  relayCount: number;
  buttonCount: number;
}): void {
  if (params.triggerType === "input_event" || params.triggerType === "button_hold") {
    const inputIndex = parseNumber(params.triggerConfig.input_index);
    if (inputIndex !== null && (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= params.buttonCount)) {
      throw new Error("invalid_input_index");
    }
  }

  if (params.triggerType === "button_hold") {
    const holdSeconds = parseNumber(params.triggerConfig.hold_seconds);
    if (holdSeconds === null || holdSeconds <= 0 || holdSeconds > 600) {
      throw new Error("invalid_hold_seconds");
    }
  }

  if (params.triggerType === "device_online" || params.triggerType === "device_offline") {
    const keys = Object.keys(params.triggerConfig);
    if (keys.length > 0) {
      throw new Error("trigger_config_not_allowed");
    }
  }

  if (params.actionType === "set_all_relays") {
    if (params.actionConfig.action !== "on" && params.actionConfig.action !== "off") {
      throw new Error("invalid_all_relays_action");
    }
    return;
  }

  const relayIndex = parseNumber(params.actionConfig.relay_index);
  if (relayIndex === null || !Number.isInteger(relayIndex)) {
    throw new Error("invalid_relay_index");
  }
  if (relayIndex < 0 || relayIndex >= params.relayCount) {
    throw new Error("invalid_relay_index");
  }
  if (
    params.actionConfig.action !== "on" &&
    params.actionConfig.action !== "off" &&
    params.actionConfig.action !== "toggle"
  ) {
    throw new Error("invalid_relay_action");
  }
}

function normalizeError(error: Error): string {
  switch (error.message) {
    case "invalid_input_index":
      return "trigger_config.input_index is out of device input range.";
    case "invalid_hold_seconds":
      return "trigger_config.hold_seconds must be between 1 and 600 for button_hold.";
    case "trigger_config_not_allowed":
      return "trigger_config must be empty for device_online/device_offline triggers.";
    case "invalid_all_relays_action":
      return "action_config.action must be on or off for set_all_relays.";
    case "invalid_relay_index":
      return "action_config.relay_index is out of device relay range.";
    case "invalid_relay_action":
      return "action_config.action must be on, off, or toggle for set_relay.";
    default:
      return "Automation configuration is invalid.";
  }
}

function serializeAutomation(row: AutomationRuleRow) {
  return {
    id: row.id,
    user_id: row.user_id,
    device_id: row.device_id,
    name: row.name,
    trigger_type: row.trigger_type,
    trigger_config: asRecord(row.trigger_config),
    condition_config: asRecord(row.condition_config),
    action_type: row.action_type,
    action_config: asRecord(row.action_config),
    cooldown_seconds: row.cooldown_seconds,
    is_enabled: row.is_enabled,
    last_triggered_at: toIsoOrNull(row.last_triggered_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

async function getOwnedDevice(deviceId: string, userId: string): Promise<DeviceOwnershipRow | null> {
  const result = await query<DeviceOwnershipRow>(
    `SELECT id, relay_count, button_count
     FROM devices
     WHERE id = $1
       AND owner_user_id = $2
       AND is_active = TRUE
     LIMIT 1`,
    [deviceId, userId]
  );
  return result.rows[0] ?? null;
}

export async function automationRoutes(server: FastifyInstance): Promise<void> {
  server.get("/", { preHandler: [authenticate] }, async (request, reply) => {
    const queryParams = request.query as { device_id?: string };
    const filters: string[] = ["user_id = $1"];
    const values: unknown[] = [request.user.sub];

    if (queryParams.device_id) {
      values.push(queryParams.device_id);
      filters.push(`device_id = $${values.length}`);
    }

    const result = await query<AutomationRuleRow>(
      `SELECT
         id, user_id, device_id, name, trigger_type, trigger_config,
         condition_config, action_type, action_config, cooldown_seconds,
         is_enabled, last_triggered_at, created_at, updated_at
       FROM automation_rules
       WHERE ${filters.join(" AND ")}
       ORDER BY created_at DESC`,
      values
    );

    return reply.send(result.rows.map((row) => serializeAutomation(row)));
  });

  server.post("/", { preHandler: [authenticate] }, async (request, reply) => {
    const parsed = createAutomationSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const body = parsed.data;
    const ownedDevice = await getOwnedDevice(body.device_id, request.user.sub);
    if (!ownedDevice) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    try {
      validateAutomationConfig({
        triggerType: body.trigger_type,
        triggerConfig: body.trigger_config,
        actionType: body.action_type,
        actionConfig: body.action_config,
        relayCount: ownedDevice.relay_count,
        buttonCount: ownedDevice.button_count
      });

      const now = nowIso();
      const inserted = await query<AutomationRuleRow>(
        `INSERT INTO automation_rules (
           id, user_id, device_id, name, trigger_type, trigger_config,
           condition_config, action_type, action_config, cooldown_seconds,
           is_enabled, definition_updated_at, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6::jsonb,
           $7::jsonb, $8, $9::jsonb, $10,
           $11, $12, $13, $14
         )
         RETURNING
           id, user_id, device_id, name, trigger_type, trigger_config,
           condition_config, action_type, action_config, cooldown_seconds,
           is_enabled, last_triggered_at, created_at, updated_at`,
        [
          newId(),
          request.user.sub,
          body.device_id,
          body.name.trim(),
          body.trigger_type,
          JSON.stringify(body.trigger_config),
          JSON.stringify(body.condition_config),
          body.action_type,
          JSON.stringify(body.action_config),
          body.cooldown_seconds,
          body.is_enabled,
          now,
          now,
          now
        ]
      );

      void deviceFallbackSyncService.syncDeviceFallback(body.device_id).catch(() => undefined);
      return reply.code(201).send(serializeAutomation(inserted.rows[0]));
    } catch (error) {
      return sendApiError(reply, 400, "validation_error", normalizeError(error as Error));
    }
  });

  server.patch("/:id", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateAutomationSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    const existingLookup = await query<AutomationRuleRow>(
      `SELECT
         id, user_id, device_id, name, trigger_type, trigger_config,
         condition_config, action_type, action_config, cooldown_seconds,
         is_enabled, last_triggered_at, created_at, updated_at
       FROM automation_rules
       WHERE id = $1
         AND user_id = $2
       LIMIT 1`,
      [params.id, request.user.sub]
    );
    const existing = existingLookup.rows[0];
    if (!existing || !existing.device_id) {
      return sendApiError(reply, 404, "not_found", "Automation not found.");
    }

    const ownedDevice = await getOwnedDevice(existing.device_id, request.user.sub);
    if (!ownedDevice) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    const merged = {
      name: typeof changes.name === "string" ? changes.name.trim() : existing.name,
      trigger_type: changes.trigger_type ?? existing.trigger_type,
      trigger_config:
        typeof changes.trigger_config !== "undefined"
          ? changes.trigger_config
          : asRecord(existing.trigger_config),
      condition_config:
        typeof changes.condition_config !== "undefined"
          ? changes.condition_config
          : asRecord(existing.condition_config),
      action_type: changes.action_type ?? existing.action_type,
      action_config:
        typeof changes.action_config !== "undefined"
          ? changes.action_config
          : asRecord(existing.action_config),
      cooldown_seconds:
        typeof changes.cooldown_seconds === "number"
          ? changes.cooldown_seconds
          : existing.cooldown_seconds,
      is_enabled:
        typeof changes.is_enabled === "boolean"
          ? changes.is_enabled
          : existing.is_enabled
    } as const;

    try {
      validateAutomationConfig({
        triggerType: merged.trigger_type,
        triggerConfig: merged.trigger_config,
        actionType: merged.action_type,
        actionConfig: merged.action_config,
        relayCount: ownedDevice.relay_count,
        buttonCount: ownedDevice.button_count
      });

      const updated = await query<AutomationRuleRow>(
        `UPDATE automation_rules
         SET name = $1,
             trigger_type = $2,
             trigger_config = $3::jsonb,
             condition_config = $4::jsonb,
             action_type = $5,
             action_config = $6::jsonb,
             cooldown_seconds = $7,
             is_enabled = $8,
             definition_updated_at = $9,
             updated_at = $10
         WHERE id = $11
           AND user_id = $12
         RETURNING
           id, user_id, device_id, name, trigger_type, trigger_config,
           condition_config, action_type, action_config, cooldown_seconds,
           is_enabled, last_triggered_at, created_at, updated_at`,
        [
          merged.name,
          merged.trigger_type,
          JSON.stringify(merged.trigger_config),
          JSON.stringify(merged.condition_config),
          merged.action_type,
          JSON.stringify(merged.action_config),
          merged.cooldown_seconds,
          merged.is_enabled,
          nowIso(),
          nowIso(),
          params.id,
          request.user.sub
        ]
      );

      if (existing.device_id) {
        void deviceFallbackSyncService.syncDeviceFallback(existing.device_id).catch(() => undefined);
      }
      return reply.send(serializeAutomation(updated.rows[0]));
    } catch (error) {
      return sendApiError(reply, 400, "validation_error", normalizeError(error as Error));
    }
  });

  server.post("/:id/enable", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const updated = await query<AutomationRuleRow>(
      `UPDATE automation_rules
       SET is_enabled = TRUE,
           definition_updated_at = $1,
           updated_at = $1
       WHERE id = $2
         AND user_id = $3
       RETURNING
         id, user_id, device_id, name, trigger_type, trigger_config,
         condition_config, action_type, action_config, cooldown_seconds,
         is_enabled, last_triggered_at, created_at, updated_at`,
      [nowIso(), params.id, request.user.sub]
    );

    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Automation not found.");
    }

    if (updated.rows[0].device_id) {
      void deviceFallbackSyncService.syncDeviceFallback(updated.rows[0].device_id).catch(() => undefined);
    }
    return reply.send(serializeAutomation(updated.rows[0]));
  });

  server.post("/:id/disable", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const updated = await query<AutomationRuleRow>(
      `UPDATE automation_rules
       SET is_enabled = FALSE,
           definition_updated_at = $1,
           updated_at = $1
       WHERE id = $2
         AND user_id = $3
       RETURNING
         id, user_id, device_id, name, trigger_type, trigger_config,
         condition_config, action_type, action_config, cooldown_seconds,
         is_enabled, last_triggered_at, created_at, updated_at`,
      [nowIso(), params.id, request.user.sub]
    );

    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Automation not found.");
    }

    if (updated.rows[0].device_id) {
      void deviceFallbackSyncService.syncDeviceFallback(updated.rows[0].device_id).catch(() => undefined);
    }
    return reply.send(serializeAutomation(updated.rows[0]));
  });

  server.delete("/:id", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const deleted = await query<{ device_id: string | null }>(
      `DELETE FROM automation_rules
       WHERE id = $1
         AND user_id = $2
       RETURNING device_id`,
      [params.id, request.user.sub]
    );

    if (!deleted.rowCount || deleted.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Automation not found.");
    }

    const deviceId = deleted.rows[0]?.device_id;
    if (deviceId) {
      void deviceFallbackSyncService.syncDeviceFallback(deviceId).catch(() => undefined);
    }
    return reply.send({ ok: true });
  });
}
