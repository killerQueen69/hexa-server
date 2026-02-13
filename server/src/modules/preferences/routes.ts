import { FastifyInstance } from "fastify";
import { z } from "zod";
import { query } from "../../db/connection";
import { authenticate } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import { nowIso } from "../../utils/time";

type PreferenceRow = {
  user_id: string;
  dashboard_layout: unknown;
  dashboard_settings: unknown;
  device_view_state: unknown;
  notification_settings: unknown;
  created_at: Date | string;
  updated_at: Date | string;
};

const updatePreferencesSchema = z.object({
  dashboard_layout: z.record(z.unknown()).optional(),
  dashboard_settings: z.record(z.unknown()).optional(),
  device_view_state: z.record(z.unknown()).optional(),
  notification_settings: z.record(z.unknown()).optional(),
  merge: z.boolean().default(true)
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

function mergeObject(
  current: Record<string, unknown>,
  next: Record<string, unknown>,
  shouldMerge: boolean
): Record<string, unknown> {
  if (!shouldMerge) {
    return next;
  }
  return {
    ...current,
    ...next
  };
}

function serializePreferences(row: PreferenceRow) {
  return {
    user_id: row.user_id,
    dashboard_layout: asObject(row.dashboard_layout),
    dashboard_settings: asObject(row.dashboard_settings),
    device_view_state: asObject(row.device_view_state),
    notification_settings: asObject(row.notification_settings),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

async function ensurePreferences(userId: string): Promise<PreferenceRow> {
  await query(
    `INSERT INTO user_preferences (
       user_id,
       dashboard_layout,
       dashboard_settings,
       device_view_state,
       notification_settings,
       created_at,
       updated_at
     ) VALUES (
       $1,
       '{}'::jsonb,
       '{}'::jsonb,
       '{}'::jsonb,
       '{}'::jsonb,
       $2,
       $3
     )
     ON CONFLICT (user_id) DO NOTHING`,
    [userId, nowIso(), nowIso()]
  );

  const result = await query<PreferenceRow>(
    `SELECT
       user_id,
       dashboard_layout,
       dashboard_settings,
       device_view_state,
       notification_settings,
       created_at,
       updated_at
     FROM user_preferences
     WHERE user_id = $1
     LIMIT 1`,
    [userId]
  );
  return result.rows[0];
}

export async function preferenceRoutes(server: FastifyInstance): Promise<void> {
  server.get("/", { preHandler: [authenticate] }, async (request, reply) => {
    const row = await ensurePreferences(request.user.sub);
    return reply.send(serializePreferences(row));
  });

  server.patch("/", { preHandler: [authenticate] }, async (request, reply) => {
    const parsed = updatePreferencesSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const changes = parsed.data;
    if (
      typeof changes.dashboard_layout === "undefined" &&
      typeof changes.dashboard_settings === "undefined" &&
      typeof changes.device_view_state === "undefined" &&
      typeof changes.notification_settings === "undefined"
    ) {
      return sendApiError(reply, 400, "validation_error", "No preference fields provided for update.");
    }

    const current = await ensurePreferences(request.user.sub);
    const mergedLayout =
      typeof changes.dashboard_layout === "undefined"
        ? asObject(current.dashboard_layout)
        : mergeObject(asObject(current.dashboard_layout), changes.dashboard_layout, changes.merge);
    const mergedSettings =
      typeof changes.dashboard_settings === "undefined"
        ? asObject(current.dashboard_settings)
        : mergeObject(asObject(current.dashboard_settings), changes.dashboard_settings, changes.merge);
    const mergedDeviceViewState =
      typeof changes.device_view_state === "undefined"
        ? asObject(current.device_view_state)
        : mergeObject(asObject(current.device_view_state), changes.device_view_state, changes.merge);
    const mergedNotificationSettings =
      typeof changes.notification_settings === "undefined"
        ? asObject(current.notification_settings)
        : mergeObject(asObject(current.notification_settings), changes.notification_settings, changes.merge);

    const updated = await query<PreferenceRow>(
      `UPDATE user_preferences
       SET dashboard_layout = $1::jsonb,
           dashboard_settings = $2::jsonb,
           device_view_state = $3::jsonb,
           notification_settings = $4::jsonb,
           updated_at = $5
       WHERE user_id = $6
       RETURNING
         user_id,
         dashboard_layout,
         dashboard_settings,
         device_view_state,
         notification_settings,
         created_at,
         updated_at`,
      [
        JSON.stringify(mergedLayout),
        JSON.stringify(mergedSettings),
        JSON.stringify(mergedDeviceViewState),
        JSON.stringify(mergedNotificationSettings),
        nowIso(),
        request.user.sub
      ]
    );

    return reply.send(serializePreferences(updated.rows[0]));
  });
}
