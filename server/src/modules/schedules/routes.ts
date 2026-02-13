import { FastifyInstance } from "fastify";
import { z } from "zod";
import { query } from "../../db/connection";
import { authenticate } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import {
  ScheduleType,
  computeNextExecution,
  toIsoOrNull,
  validateCronExpression
} from "../../services/schedule-utils";
import { newId } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type DeviceOwnershipRow = {
  id: string;
  relay_count: number;
};

type ScheduleRow = {
  id: string;
  user_id: string;
  device_id: string;
  relay_index: number | null;
  target_scope: "single" | "all";
  name: string | null;
  schedule_type: ScheduleType;
  cron_expression: string | null;
  execute_at: Date | string | null;
  timezone: string;
  action: "on" | "off" | "toggle";
  is_enabled: boolean;
  last_executed: Date | string | null;
  next_execution: Date | string | null;
  execution_count: number;
  created_at: Date | string;
  updated_at: Date | string;
};

const createScheduleSchema = z.object({
  device_id: z.string().min(1),
  target_scope: z.enum(["single", "all"]).default("single"),
  relay_index: z.number().int().min(0).nullable().optional(),
  name: z.string().min(1).max(120).nullable().optional(),
  schedule_type: z.enum(["once", "cron"]),
  cron_expression: z.string().min(1).max(120).nullable().optional(),
  execute_at: z.string().datetime().nullable().optional(),
  timezone: z.string().min(1).max(120).default("UTC"),
  action: z.enum(["on", "off", "toggle"]),
  is_enabled: z.boolean().default(true)
});

const updateScheduleSchema = z.object({
  target_scope: z.enum(["single", "all"]).optional(),
  relay_index: z.number().int().min(0).nullable().optional(),
  name: z.string().min(1).max(120).nullable().optional(),
  schedule_type: z.enum(["once", "cron"]).optional(),
  cron_expression: z.string().min(1).max(120).nullable().optional(),
  execute_at: z.string().datetime().nullable().optional(),
  timezone: z.string().min(1).max(120).optional(),
  action: z.enum(["on", "off", "toggle"]).optional(),
  is_enabled: z.boolean().optional()
});

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function serializeSchedule(row: ScheduleRow) {
  return {
    id: row.id,
    user_id: row.user_id,
    device_id: row.device_id,
    relay_index: row.relay_index,
    target_scope: row.target_scope,
    name: row.name,
    schedule_type: row.schedule_type,
    cron_expression: row.cron_expression,
    execute_at: toIsoOrNull(row.execute_at),
    timezone: row.timezone,
    action: row.action,
    is_enabled: row.is_enabled,
    last_executed: toIsoOrNull(row.last_executed),
    next_execution: toIsoOrNull(row.next_execution),
    execution_count: row.execution_count,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

async function getOwnedDevice(deviceId: string, userId: string): Promise<DeviceOwnershipRow | null> {
  const result = await query<DeviceOwnershipRow>(
    `SELECT id, relay_count
     FROM devices
     WHERE id = $1
       AND owner_user_id = $2
       AND is_active = TRUE
     LIMIT 1`,
    [deviceId, userId]
  );
  return result.rows[0] ?? null;
}

function validateSchedulePayload(params: {
  targetScope: "single" | "all";
  relayIndex: number | null;
  action: "on" | "off" | "toggle";
  scheduleType: ScheduleType;
  cronExpression: string | null;
  executeAt: string | null;
  timezone: string;
  relayCount: number;
}): { nextExecution: string | null } {
  if (params.targetScope === "single") {
    if (!Number.isInteger(params.relayIndex)) {
      throw new Error("relay_index_required");
    }
    if ((params.relayIndex as number) < 0 || (params.relayIndex as number) >= params.relayCount) {
      throw new Error("relay_index_out_of_range");
    }
  } else {
    if (params.action === "toggle") {
      throw new Error("invalid_action_for_all_scope");
    }
  }

  if (params.scheduleType === "cron") {
    validateCronExpression(params.cronExpression ?? "", params.timezone);
  }

  const next = computeNextExecution({
    scheduleType: params.scheduleType,
    cronExpression: params.cronExpression,
    executeAt: params.executeAt,
    timezone: params.timezone
  });
  const nextIso = toIsoOrNull(next);

  if (!nextIso) {
    throw new Error("schedule_in_past");
  }

  return { nextExecution: nextIso };
}

function normalizeError(error: Error): { code: string; message: string } {
  switch (error.message) {
    case "relay_index_required":
      return {
        code: "validation_error",
        message: "relay_index is required for single target scope."
      };
    case "relay_index_out_of_range":
      return {
        code: "validation_error",
        message: "relay_index is outside device relay range."
      };
    case "invalid_action_for_all_scope":
      return {
        code: "validation_error",
        message: "All-relays schedules support on/off actions only."
      };
    case "invalid_timezone":
      return {
        code: "validation_error",
        message: "timezone is invalid."
      };
    case "cron_expression_required":
      return {
        code: "validation_error",
        message: "cron_expression is required for cron schedule."
      };
    case "execute_at_required":
      return {
        code: "validation_error",
        message: "execute_at is required for once schedule."
      };
    case "invalid_execute_at":
      return {
        code: "validation_error",
        message: "execute_at must be a valid timestamp."
      };
    case "schedule_in_past":
      return {
        code: "validation_error",
        message: "Schedule next execution must be in the future."
      };
    default:
      return {
        code: "validation_error",
        message: "Invalid schedule configuration."
      };
  }
}

export async function scheduleRoutes(server: FastifyInstance): Promise<void> {
  server.get("/", { preHandler: [authenticate] }, async (request, reply) => {
    const queryParams = request.query as { device_id?: string };
    const filters: string[] = ["user_id = $1"];
    const values: unknown[] = [request.user.sub];

    if (queryParams.device_id) {
      values.push(queryParams.device_id);
      filters.push(`device_id = $${values.length}`);
    }

    const result = await query<ScheduleRow>(
      `SELECT
         id, user_id, device_id, relay_index, target_scope, name,
         schedule_type, cron_expression, execute_at, timezone, action,
         is_enabled, last_executed, next_execution, execution_count,
         created_at, updated_at
       FROM schedules
       WHERE ${filters.join(" AND ")}
       ORDER BY created_at DESC`,
      values
    );

    return reply.send(result.rows.map((row) => serializeSchedule(row)));
  });

  server.post("/", { preHandler: [authenticate] }, async (request, reply) => {
    const parsed = createScheduleSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const body = parsed.data;
    const ownedDevice = await getOwnedDevice(body.device_id, request.user.sub);
    if (!ownedDevice) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    try {
      const validation = validateSchedulePayload({
        targetScope: body.target_scope,
        relayIndex: body.target_scope === "single" ? body.relay_index ?? null : null,
        action: body.action,
        scheduleType: body.schedule_type,
        cronExpression: body.cron_expression ?? null,
        executeAt: body.execute_at ?? null,
        timezone: body.timezone,
        relayCount: ownedDevice.relay_count
      });

      const now = nowIso();
      const id = newId();

      const inserted = await query<ScheduleRow>(
        `INSERT INTO schedules (
           id, user_id, device_id, relay_index, target_scope, name,
           schedule_type, cron_expression, execute_at, timezone, action,
           is_enabled, next_execution, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, $8, $9, $10, $11,
           $12, $13, $14, $15
         )
         RETURNING
           id, user_id, device_id, relay_index, target_scope, name,
           schedule_type, cron_expression, execute_at, timezone, action,
           is_enabled, last_executed, next_execution, execution_count,
           created_at, updated_at`,
        [
          id,
          request.user.sub,
          body.device_id,
          body.target_scope === "single" ? body.relay_index : null,
          body.target_scope,
          body.name?.trim() ?? null,
          body.schedule_type,
          body.schedule_type === "cron" ? body.cron_expression?.trim() ?? null : null,
          body.schedule_type === "once" ? body.execute_at ?? null : null,
          body.timezone,
          body.action,
          body.is_enabled,
          body.is_enabled ? validation.nextExecution : null,
          now,
          now
        ]
      );

      return reply.code(201).send(serializeSchedule(inserted.rows[0]));
    } catch (error) {
      const normalized = normalizeError(error as Error);
      return sendApiError(reply, 400, normalized.code, normalized.message);
    }
  });

  server.patch("/:id", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateScheduleSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    const existingLookup = await query<ScheduleRow>(
      `SELECT
         id, user_id, device_id, relay_index, target_scope, name,
         schedule_type, cron_expression, execute_at, timezone, action,
         is_enabled, last_executed, next_execution, execution_count,
         created_at, updated_at
       FROM schedules
       WHERE id = $1
         AND user_id = $2
       LIMIT 1`,
      [params.id, request.user.sub]
    );
    const existing = existingLookup.rows[0];
    if (!existing) {
      return sendApiError(reply, 404, "not_found", "Schedule not found.");
    }

    const ownedDevice = await getOwnedDevice(existing.device_id, request.user.sub);
    if (!ownedDevice) {
      return sendApiError(reply, 404, "not_found", "Owned device not found.");
    }

    const merged = {
      target_scope: changes.target_scope ?? existing.target_scope,
      relay_index:
        typeof changes.relay_index !== "undefined"
          ? changes.relay_index
          : existing.relay_index,
      name: typeof changes.name !== "undefined" ? changes.name : existing.name,
      schedule_type: changes.schedule_type ?? existing.schedule_type,
      cron_expression:
        typeof changes.cron_expression !== "undefined"
          ? changes.cron_expression
          : existing.cron_expression,
      execute_at:
        typeof changes.execute_at !== "undefined"
          ? changes.execute_at
          : toIsoOrNull(existing.execute_at),
      timezone: changes.timezone ?? existing.timezone,
      action: changes.action ?? existing.action,
      is_enabled:
        typeof changes.is_enabled === "boolean"
          ? changes.is_enabled
          : existing.is_enabled
    };

    try {
      const validation = validateSchedulePayload({
        targetScope: merged.target_scope,
        relayIndex: merged.target_scope === "single" ? merged.relay_index ?? null : null,
        action: merged.action,
        scheduleType: merged.schedule_type,
        cronExpression: merged.cron_expression ?? null,
        executeAt: merged.execute_at ?? null,
        timezone: merged.timezone,
        relayCount: ownedDevice.relay_count
      });

      const now = nowIso();
      const updated = await query<ScheduleRow>(
        `UPDATE schedules
         SET relay_index = $1,
             target_scope = $2,
             name = $3,
             schedule_type = $4,
             cron_expression = $5,
             execute_at = $6,
             timezone = $7,
             action = $8,
             is_enabled = $9,
             next_execution = $10,
             updated_at = $11
         WHERE id = $12
           AND user_id = $13
         RETURNING
           id, user_id, device_id, relay_index, target_scope, name,
           schedule_type, cron_expression, execute_at, timezone, action,
           is_enabled, last_executed, next_execution, execution_count,
           created_at, updated_at`,
        [
          merged.target_scope === "single" ? merged.relay_index : null,
          merged.target_scope,
          merged.name?.trim() ?? null,
          merged.schedule_type,
          merged.schedule_type === "cron" ? merged.cron_expression?.trim() ?? null : null,
          merged.schedule_type === "once" ? merged.execute_at : null,
          merged.timezone,
          merged.action,
          merged.is_enabled,
          merged.is_enabled ? validation.nextExecution : null,
          now,
          params.id,
          request.user.sub
        ]
      );

      return reply.send(serializeSchedule(updated.rows[0]));
    } catch (error) {
      const normalized = normalizeError(error as Error);
      return sendApiError(reply, 400, normalized.code, normalized.message);
    }
  });

  server.post("/:id/enable", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const lookup = await query<ScheduleRow>(
      `SELECT
         id, user_id, device_id, relay_index, target_scope, name,
         schedule_type, cron_expression, execute_at, timezone, action,
         is_enabled, last_executed, next_execution, execution_count,
         created_at, updated_at
       FROM schedules
       WHERE id = $1
         AND user_id = $2
       LIMIT 1`,
      [params.id, request.user.sub]
    );
    const row = lookup.rows[0];
    if (!row) {
      return sendApiError(reply, 404, "not_found", "Schedule not found.");
    }

    try {
      const next = computeNextExecution({
        scheduleType: row.schedule_type,
        cronExpression: row.cron_expression,
        executeAt: row.execute_at,
        timezone: row.timezone
      });
      const nextIso = toIsoOrNull(next);
      if (!nextIso) {
        return sendApiError(reply, 400, "validation_error", "Schedule execution window has expired.");
      }

      const now = nowIso();
      const updated = await query<ScheduleRow>(
        `UPDATE schedules
         SET is_enabled = TRUE,
             next_execution = $1,
             updated_at = $2
         WHERE id = $3
           AND user_id = $4
         RETURNING
           id, user_id, device_id, relay_index, target_scope, name,
           schedule_type, cron_expression, execute_at, timezone, action,
           is_enabled, last_executed, next_execution, execution_count,
           created_at, updated_at`,
        [nextIso, now, params.id, request.user.sub]
      );
      return reply.send(serializeSchedule(updated.rows[0]));
    } catch (error) {
      const normalized = normalizeError(error as Error);
      return sendApiError(reply, 400, normalized.code, normalized.message);
    }
  });

  server.post("/:id/disable", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const updated = await query<ScheduleRow>(
      `UPDATE schedules
       SET is_enabled = FALSE,
           next_execution = NULL,
           updated_at = $1
       WHERE id = $2
         AND user_id = $3
       RETURNING
         id, user_id, device_id, relay_index, target_scope, name,
         schedule_type, cron_expression, execute_at, timezone, action,
         is_enabled, last_executed, next_execution, execution_count,
         created_at, updated_at`,
      [nowIso(), params.id, request.user.sub]
    );

    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Schedule not found.");
    }

    return reply.send(serializeSchedule(updated.rows[0]));
  });

  server.delete("/:id", { preHandler: [authenticate] }, async (request, reply) => {
    const params = request.params as { id: string };
    const deleted = await query(
      `DELETE FROM schedules
       WHERE id = $1
         AND user_id = $2`,
      [params.id, request.user.sub]
    );

    if (!deleted.rowCount || deleted.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Schedule not found.");
    }

    return reply.send({ ok: true });
  });
}
