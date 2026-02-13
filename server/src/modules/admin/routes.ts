import { FastifyInstance } from "fastify";
import { z } from "zod";
import { env } from "../../config/env";
import { query, withTransaction } from "../../db/connection";
import { authenticate, requireRole } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import { metricsService } from "../../services/metrics-service";
import { opsBackupService } from "../../services/ops-backup-service";
import { RelayServiceError, relayService } from "../../services/relay-service";
import { newId, randomClaimCode, randomToken, sha256 } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type UserRow = {
  id: string;
  email: string;
  name: string;
  role: "admin" | "user";
  is_active: boolean;
  created_at: Date | string;
  updated_at: Date | string;
  device_count: string;
};

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
  power_restore_mode: "last_state" | "all_off" | "all_on";
  firmware_version: string | null;
  ota_channel: "dev" | "beta" | "stable";
  ota_security_version: number;
  last_seen_at: Date | string | null;
  last_ip: string | null;
  is_active: boolean;
  owner_user_id: string | null;
  owner_email: string | null;
  claim_code: string | null;
  last_action_at: Date | string | null;
  last_action: unknown;
  last_input_event: unknown;
  created_at: Date | string;
  updated_at: Date | string;
  relays: unknown;
};

type AuditRow = {
  id: string;
  device_id: string | null;
  device_uid: string | null;
  device_name: string | null;
  user_id: string | null;
  user_email: string | null;
  schedule_id: string | null;
  automation_id: string | null;
  action: string;
  details: unknown;
  source: string | null;
  created_at: Date | string;
};

type OverviewDeviceStats = {
  total: string;
  claimed: string;
  unclaimed: string;
  online_estimate: string;
  inactive: string;
};

type OverviewUserStats = {
  total: string;
  admins: string;
  active: string;
};

type OverviewScheduleStats = {
  total: string;
  enabled: string;
  due_now: string;
};

type OverviewAutomationStats = {
  total: string;
  enabled: string;
};

type OverviewOtaStats = {
  releases_total: string;
  active_releases: string;
  failed_reports_24h: string;
  reports_24h: string;
};

type OverviewBackupStats = {
  last_backup_at: Date | string | null;
  last_restore_drill_at: Date | string | null;
  backup_failures_24h: string;
};

const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  role: z.enum(["admin", "user"]).optional(),
  is_active: z.boolean().optional()
});

const updateDeviceSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  is_active: z.boolean().optional(),
  owner_user_id: z.string().min(1).nullable().optional(),
  device_class: z.enum(["relay_controller", "ir_hub", "sensor_hub", "hybrid"]).optional(),
  capabilities: z.array(
    z.object({
      key: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
      kind: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
      enabled: z.boolean().default(true)
    })
  ).optional(),
  ota_channel: z.enum(["dev", "beta", "stable"]).optional(),
  firmware_version: z.string().min(1).max(100).nullable().optional()
});

const relayCommandSchema = z.object({
  action: z.enum(["on", "off", "toggle"]),
  timeout_ms: z.number().int().min(1000).max(30000).optional()
});

const allRelayCommandSchema = z.object({
  action: z.enum(["on", "off"]),
  timeout_ms: z.number().int().min(1000).max(30000).optional()
});

const restoreDrillSchema = z.object({
  backup_path: z.string().min(1).optional()
});

const alertSimulationSchema = z.object({
  api_5xx_threshold: z.number().int().min(1).max(1_000_000).default(10),
  command_timeout_threshold: z.number().int().min(1).max(1_000_000).default(5),
  scheduler_error_threshold: z.number().int().min(1).max(1_000_000).default(3),
  backup_failure_threshold: z.number().int().min(1).max(1_000_000).default(1)
});

function toIso(value: Date | string | null): string | null {
  if (!value) {
    return null;
  }
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function asNullableObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asRelayList(value: unknown): Array<{
  relay_index: number;
  relay_name: string | null;
  is_on: boolean;
}> {
  if (!Array.isArray(value)) {
    return [];
  }

  const output: Array<{
    relay_index: number;
    relay_name: string | null;
    is_on: boolean;
  }> = [];
  for (const row of value) {
    if (!row || typeof row !== "object") {
      continue;
    }
    const relay = row as Record<string, unknown>;
    if (!Number.isInteger(relay.relay_index) || typeof relay.is_on !== "boolean") {
      continue;
    }
    output.push({
      relay_index: relay.relay_index as number,
      relay_name: typeof relay.relay_name === "string" ? relay.relay_name : null,
      is_on: relay.is_on
    });
  }
  return output;
}

function asCapabilities(value: unknown): Array<{
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
    if (typeof row.key !== "string" || typeof row.kind !== "string") {
      continue;
    }
    out.push({
      key: row.key,
      kind: row.kind,
      enabled: row.enabled !== false
    });
  }
  return out;
}

function serializeUser(row: UserRow) {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    is_active: row.is_active,
    device_count: Number(row.device_count),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function serializeDevice(row: DeviceRow) {
  return {
    id: row.id,
    device_uid: row.device_uid,
    hardware_uid: row.hardware_uid,
    name: row.name,
    model: row.model,
    device_class: row.device_class,
    capabilities: asCapabilities(row.capabilities),
    relay_count: row.relay_count,
    button_count: row.button_count,
    relay_names: Array.isArray(row.relay_names) ? row.relay_names : [],
    input_config: Array.isArray(row.input_config) ? row.input_config : [],
    power_restore_mode: row.power_restore_mode,
    firmware_version: row.firmware_version,
    ota_channel: row.ota_channel,
    ota_security_version: row.ota_security_version,
    last_seen_at: toIso(row.last_seen_at),
    last_ip: row.last_ip,
    is_active: row.is_active,
    owner_user_id: row.owner_user_id,
    owner_email: row.owner_email,
    claim_code: row.claim_code,
    last_action_at: toIso(row.last_action_at),
    last_action: asNullableObject(row.last_action),
    last_input_event: asNullableObject(row.last_input_event),
    relays: asRelayList(row.relays),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function serializeAudit(row: AuditRow) {
  return {
    id: row.id,
    device_id: row.device_id,
    device_uid: row.device_uid,
    device_name: row.device_name,
    user_id: row.user_id,
    user_email: row.user_email,
    schedule_id: row.schedule_id,
    automation_id: row.automation_id,
    action: row.action,
    details: asObject(row.details),
    source: row.source,
    created_at: toIso(row.created_at)
  };
}

async function userExists(userId: string): Promise<boolean> {
  const result = await query<{ id: string }>(
    `SELECT id
     FROM users
     WHERE id = $1
     LIMIT 1`,
    [userId]
  );
  return Boolean(result.rowCount && result.rowCount > 0);
}

async function listGlobalDevices(): Promise<DeviceRow[]> {
  const result = await query<DeviceRow>(
    `SELECT
       d.id,
       d.device_uid,
       d.hardware_uid,
       d.name,
       d.model,
       d.device_class,
       d.capabilities,
       d.relay_count,
       d.button_count,
       d.relay_names,
       d.input_config,
       d.power_restore_mode,
       d.firmware_version,
       d.ota_channel,
       d.ota_security_version,
       d.last_seen_at,
       d.last_ip,
       d.is_active,
       d.owner_user_id,
       d.claim_code,
       (
         SELECT a.created_at
         FROM audit_log a
         WHERE a.device_id = d.id
         ORDER BY a.created_at DESC
         LIMIT 1
       ) AS last_action_at,
       (
         SELECT json_build_object(
           'action', a.action,
           'source', a.source,
           'created_at', a.created_at,
           'details', a.details
         )
         FROM audit_log a
         WHERE a.device_id = d.id
         ORDER BY a.created_at DESC
         LIMIT 1
       ) AS last_action,
       (
         SELECT json_build_object(
           'source', a.source,
           'created_at', a.created_at,
           'details', a.details
         )
         FROM audit_log a
         WHERE a.device_id = d.id
           AND a.action = 'input_event'
         ORDER BY a.created_at DESC
         LIMIT 1
       ) AS last_input_event,
       d.created_at,
       d.updated_at,
       u.email AS owner_email,
       COALESCE(
         json_agg(
           json_build_object(
             'relay_index', rs.relay_index,
             'relay_name', rs.relay_name,
             'is_on', rs.is_on
           )
           ORDER BY rs.relay_index ASC
         ) FILTER (WHERE rs.device_id IS NOT NULL),
         '[]'::json
       ) AS relays
     FROM devices d
     LEFT JOIN users u ON u.id = d.owner_user_id
     LEFT JOIN relay_states rs ON rs.device_id = d.id
     GROUP BY d.id, u.email
     ORDER BY d.created_at DESC`
  );
  return result.rows;
}

export async function adminRoutes(server: FastifyInstance): Promise<void> {
  const preHandlers = [authenticate, requireRole(["admin"])];

  server.get("/overview", { preHandler: preHandlers }, async (_request, reply) => {
    const [deviceStats, userStats, scheduleStats, automationStats, otaStats, backupStats, signingKeys] =
      await Promise.all([
        query<OverviewDeviceStats>(
          `SELECT
             COUNT(*)::text AS total,
             COUNT(*) FILTER (WHERE owner_user_id IS NOT NULL)::text AS claimed,
             COUNT(*) FILTER (WHERE owner_user_id IS NULL)::text AS unclaimed,
             COUNT(*) FILTER (WHERE last_seen_at > now() - interval '90 seconds')::text AS online_estimate,
             COUNT(*) FILTER (WHERE is_active = FALSE)::text AS inactive
           FROM devices`
        ),
        query<OverviewUserStats>(
          `SELECT
             COUNT(*)::text AS total,
             COUNT(*) FILTER (WHERE role = 'admin')::text AS admins,
             COUNT(*) FILTER (WHERE is_active = TRUE)::text AS active
           FROM users`
        ),
        query<OverviewScheduleStats>(
          `SELECT
             COUNT(*)::text AS total,
             COUNT(*) FILTER (WHERE is_enabled = TRUE)::text AS enabled,
             COUNT(*) FILTER (WHERE is_enabled = TRUE AND next_execution <= now())::text AS due_now
           FROM schedules`
        ),
        query<OverviewAutomationStats>(
          `SELECT
             COUNT(*)::text AS total,
             COUNT(*) FILTER (WHERE is_enabled = TRUE)::text AS enabled
           FROM automation_rules`
        ),
        query<OverviewOtaStats>(
          `SELECT
             (SELECT COUNT(*)::text FROM ota_releases) AS releases_total,
             (SELECT COUNT(*)::text FROM ota_releases WHERE is_active = TRUE AND expires_at > now()) AS active_releases,
             (SELECT COUNT(*)::text FROM ota_reports WHERE status IN ('error', 'rejected') AND created_at > now() - interval '24 hours') AS failed_reports_24h,
             (SELECT COUNT(*)::text FROM ota_reports WHERE created_at > now() - interval '24 hours') AS reports_24h`
        ),
        query<OverviewBackupStats>(
          `SELECT
             (SELECT MAX(finished_at) FROM ops_backup_runs WHERE operation = 'backup' AND status = 'ok') AS last_backup_at,
             (SELECT MAX(finished_at) FROM ops_backup_runs WHERE operation = 'restore_drill' AND status = 'ok') AS last_restore_drill_at,
             (SELECT COUNT(*)::text FROM ops_backup_runs WHERE status = 'error' AND started_at > now() - interval '24 hours') AS backup_failures_24h`
        ),
        query<{ status: string; total: string }>(
          `SELECT status, COUNT(*)::text AS total
           FROM ota_signing_keys
           GROUP BY status`
        )
      ]);

    const metricsSnapshot = metricsService.snapshot();
    const signingKeyTotals = {
      active: 0,
      next: 0,
      retired: 0
    };
    for (const row of signingKeys.rows) {
      if (row.status === "active" || row.status === "next" || row.status === "retired") {
        signingKeyTotals[row.status] = Number(row.total);
      }
    }

    return reply.send({
      generated_at: nowIso(),
      api_versions: {
        rest: env.API_REST_VERSION,
        ws: env.API_WS_VERSION,
        deprecation_window_days: env.API_DEPRECATION_WINDOW_DAYS,
        deprecation_notice: env.API_DEPRECATION_NOTICE ?? null
      },
      fleet: {
        devices: {
          total: Number(deviceStats.rows[0]?.total ?? "0"),
          claimed: Number(deviceStats.rows[0]?.claimed ?? "0"),
          unclaimed: Number(deviceStats.rows[0]?.unclaimed ?? "0"),
          online_estimate: Number(deviceStats.rows[0]?.online_estimate ?? "0"),
          inactive: Number(deviceStats.rows[0]?.inactive ?? "0")
        },
        users: {
          total: Number(userStats.rows[0]?.total ?? "0"),
          admins: Number(userStats.rows[0]?.admins ?? "0"),
          active: Number(userStats.rows[0]?.active ?? "0")
        }
      },
      automations: {
        total: Number(automationStats.rows[0]?.total ?? "0"),
        enabled: Number(automationStats.rows[0]?.enabled ?? "0")
      },
      schedules: {
        total: Number(scheduleStats.rows[0]?.total ?? "0"),
        enabled: Number(scheduleStats.rows[0]?.enabled ?? "0"),
        due_now: Number(scheduleStats.rows[0]?.due_now ?? "0")
      },
      ota: {
        releases_total: Number(otaStats.rows[0]?.releases_total ?? "0"),
        active_releases: Number(otaStats.rows[0]?.active_releases ?? "0"),
        reports_24h: Number(otaStats.rows[0]?.reports_24h ?? "0"),
        failed_reports_24h: Number(otaStats.rows[0]?.failed_reports_24h ?? "0"),
        signing_keys: signingKeyTotals
      },
      backup: {
        last_backup_at: toIso(backupStats.rows[0]?.last_backup_at ?? null),
        last_restore_drill_at: toIso(backupStats.rows[0]?.last_restore_drill_at ?? null),
        failures_24h: Number(backupStats.rows[0]?.backup_failures_24h ?? "0"),
        policy: opsBackupService.getPolicy()
      },
      metrics_snapshot: metricsSnapshot
    });
  });

  server.get("/users", { preHandler: preHandlers }, async (_request, reply) => {
    const result = await query<UserRow>(
      `SELECT
         u.id,
         u.email,
         u.name,
         u.role,
         u.is_active,
         u.created_at,
         u.updated_at,
         COUNT(d.id)::text AS device_count
       FROM users u
       LEFT JOIN devices d ON d.owner_user_id = u.id
       GROUP BY u.id
       ORDER BY u.created_at DESC`
    );
    return reply.send(result.rows.map((row) => serializeUser(row)));
  });

  server.patch("/users/:id", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateUserSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }
    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    const fields: string[] = [];
    const values: unknown[] = [];

    if (typeof changes.name !== "undefined") {
      values.push(changes.name.trim());
      fields.push(`name = $${values.length}`);
    }
    if (typeof changes.role !== "undefined") {
      values.push(changes.role);
      fields.push(`role = $${values.length}`);
    }
    if (typeof changes.is_active !== "undefined") {
      values.push(changes.is_active);
      fields.push(`is_active = $${values.length}`);
    }
    values.push(nowIso());
    fields.push(`updated_at = $${values.length}`);

    values.push(params.id);
    const idArg = values.length;
    const updated = await query<UserRow>(
      `UPDATE users
       SET ${fields.join(", ")}
       WHERE id = $${idArg}
       RETURNING
         id, email, name, role, is_active, created_at, updated_at,
         '0'::text AS device_count`
      ,
      values
    );

    if (!updated.rowCount || updated.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "User not found.");
    }
    return reply.send(serializeUser(updated.rows[0]));
  });

  server.get("/devices", { preHandler: preHandlers }, async (_request, reply) => {
    const rows = await listGlobalDevices();
    return reply.send(rows.map((row) => serializeDevice(row)));
  });

  server.patch("/devices/:id", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = updateDeviceSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }
    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return sendApiError(reply, 400, "validation_error", "No fields provided for update.");
    }

    if (typeof changes.owner_user_id === "string") {
      const exists = await userExists(changes.owner_user_id);
      if (!exists) {
        return sendApiError(reply, 404, "not_found", "owner_user_id does not match a user.");
      }
    }

    const updated = await withTransaction(async (client) => {
      const lookup = await client.query<{ owner_user_id: string | null }>(
        `SELECT owner_user_id
         FROM devices
         WHERE id = $1
         LIMIT 1
         FOR UPDATE`,
        [params.id]
      );
      if (!lookup.rowCount || lookup.rowCount === 0) {
        return null;
      }

      const fields: string[] = [];
      const values: unknown[] = [];
      let nextOwnerId = lookup.rows[0].owner_user_id;

      if (typeof changes.name !== "undefined") {
        values.push(changes.name.trim());
        fields.push(`name = $${values.length}`);
      }
      if (typeof changes.is_active !== "undefined") {
        values.push(changes.is_active);
        fields.push(`is_active = $${values.length}`);
      }
      if (typeof changes.ota_channel !== "undefined") {
        values.push(changes.ota_channel);
        fields.push(`ota_channel = $${values.length}`);
      }
      if (typeof changes.firmware_version !== "undefined") {
        values.push(changes.firmware_version);
        fields.push(`firmware_version = $${values.length}`);
      }
      if (typeof changes.device_class !== "undefined") {
        values.push(changes.device_class);
        fields.push(`device_class = $${values.length}`);
      }
      if (typeof changes.capabilities !== "undefined") {
        values.push(JSON.stringify(changes.capabilities));
        fields.push(`capabilities = $${values.length}::jsonb`);
      }
      if (typeof changes.owner_user_id !== "undefined") {
        values.push(changes.owner_user_id);
        fields.push(`owner_user_id = $${values.length}`);
        nextOwnerId = changes.owner_user_id;

        if (changes.owner_user_id) {
          values.push(null);
          fields.push(`claim_code = $${values.length}`);
          values.push(null);
          fields.push(`claim_code_created_at = $${values.length}`);
        } else {
          values.push(randomClaimCode(8));
          fields.push(`claim_code = $${values.length}`);
          values.push(nowIso());
          fields.push(`claim_code_created_at = $${values.length}`);
        }
      }

      values.push(nowIso());
      fields.push(`updated_at = $${values.length}`);
      values.push(params.id);
      const idArg = values.length;

      const write = await client.query(
        `UPDATE devices
         SET ${fields.join(", ")}
         WHERE id = $${idArg}`,
        values
      );
      if (!write.rowCount || write.rowCount === 0) {
        return null;
      }

      if (typeof changes.owner_user_id !== "undefined") {
        await client.query(`DELETE FROM user_devices WHERE device_id = $1`, [params.id]);
        if (nextOwnerId) {
          await client.query(
            `INSERT INTO user_devices (id, user_id, device_id, permission, created_at)
             VALUES ($1, $2, $3, 'admin', $4)`,
            [newId(), nextOwnerId, params.id, nowIso()]
          );
        }
      }

      const full = await client.query<DeviceRow>(
        `SELECT
           d.id,
           d.device_uid,
           d.hardware_uid,
           d.name,
           d.model,
           d.device_class,
           d.capabilities,
           d.relay_count,
           d.button_count,
           d.relay_names,
           d.input_config,
           d.power_restore_mode,
           d.firmware_version,
           d.ota_channel,
           d.ota_security_version,
           d.last_seen_at,
           d.last_ip,
           d.is_active,
           d.owner_user_id,
           d.claim_code,
           (
             SELECT a.created_at
             FROM audit_log a
             WHERE a.device_id = d.id
             ORDER BY a.created_at DESC
             LIMIT 1
           ) AS last_action_at,
           (
             SELECT json_build_object(
               'action', a.action,
               'source', a.source,
               'created_at', a.created_at,
               'details', a.details
             )
             FROM audit_log a
             WHERE a.device_id = d.id
             ORDER BY a.created_at DESC
             LIMIT 1
           ) AS last_action,
           (
             SELECT json_build_object(
               'source', a.source,
               'created_at', a.created_at,
               'details', a.details
             )
             FROM audit_log a
             WHERE a.device_id = d.id
               AND a.action = 'input_event'
             ORDER BY a.created_at DESC
             LIMIT 1
           ) AS last_input_event,
           d.created_at,
           d.updated_at,
           u.email AS owner_email,
           COALESCE(
             json_agg(
               json_build_object(
                 'relay_index', rs.relay_index,
                 'relay_name', rs.relay_name,
                 'is_on', rs.is_on
               )
               ORDER BY rs.relay_index ASC
             ) FILTER (WHERE rs.device_id IS NOT NULL),
             '[]'::json
           ) AS relays
         FROM devices d
         LEFT JOIN users u ON u.id = d.owner_user_id
         LEFT JOIN relay_states rs ON rs.device_id = d.id
         WHERE d.id = $1
         GROUP BY d.id, u.email`,
        [params.id]
      );
      return full.rows[0] ?? null;
    });

    if (!updated) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    return reply.send(serializeDevice(updated));
  });

  server.post("/devices/:id/token/rotate", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const token = randomToken(32);
    const result = await query(
      `UPDATE devices
       SET device_token_hash = $1,
           updated_at = $2
       WHERE id = $3`,
      [sha256(token), nowIso(), params.id]
    );
    if (!result.rowCount || result.rowCount === 0) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    return reply.send({
      ok: true,
      device_token: token
    });
  });

  server.post("/devices/:id/release", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const claimCode = randomClaimCode(8);
    const released = await withTransaction(async (client) => {
      const lookup = await client.query<{ id: string }>(
        `SELECT id
         FROM devices
         WHERE id = $1
         LIMIT 1
         FOR UPDATE`,
        [params.id]
      );
      if (!lookup.rowCount || lookup.rowCount === 0) {
        return false;
      }

      await client.query(
        `UPDATE devices
         SET owner_user_id = NULL,
             claim_code = $1,
             claim_code_created_at = $2,
             updated_at = $3
         WHERE id = $4`,
        [claimCode, nowIso(), nowIso(), params.id]
      );
      await client.query(`DELETE FROM user_devices WHERE device_id = $1`, [params.id]);
      return true;
    });
    if (!released) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    return reply.send({
      ok: true,
      claim_code: claimCode
    });
  });

  server.post("/devices/:id/relays/:index", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string; index: string };
    const relayIndex = Number.parseInt(params.index, 10);
    if (!Number.isInteger(relayIndex)) {
      return sendApiError(reply, 400, "validation_error", "Relay index must be an integer.");
    }

    const parsed = relayCommandSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
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

  server.post("/devices/:id/relays/all", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = allRelayCommandSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
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

  server.get("/audit", { preHandler: preHandlers }, async (request, reply) => {
    const queryParams = request.query as {
      device_id?: string;
      source?: string;
      action?: string;
      limit?: string;
      offset?: string;
    };

    const limit = Math.min(Math.max(Number.parseInt(queryParams.limit ?? "100", 10) || 100, 1), 500);
    const offset = Math.max(Number.parseInt(queryParams.offset ?? "0", 10) || 0, 0);
    const filters: string[] = [];
    const values: unknown[] = [];

    if (queryParams.device_id) {
      values.push(queryParams.device_id);
      filters.push(`a.device_id = $${values.length}`);
    }
    if (queryParams.source) {
      values.push(queryParams.source);
      filters.push(`a.source = $${values.length}`);
    }
    if (queryParams.action) {
      values.push(queryParams.action);
      filters.push(`a.action = $${values.length}`);
    }

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
    values.push(limit);
    const limitArg = values.length;
    values.push(offset);
    const offsetArg = values.length;

    const result = await query<AuditRow>(
      `SELECT
         a.id,
         a.device_id,
         d.device_uid,
         d.name AS device_name,
         a.user_id,
         u.email AS user_email,
         a.schedule_id,
         a.automation_id,
         a.action,
         a.details,
         a.source,
         a.created_at
       FROM audit_log a
       LEFT JOIN devices d ON d.id = a.device_id
       LEFT JOIN users u ON u.id = a.user_id
       ${whereClause}
       ORDER BY a.created_at DESC
       LIMIT $${limitArg}
       OFFSET $${offsetArg}`,
      values
    );

    return reply.send(result.rows.map((row) => serializeAudit(row)));
  });

  server.get("/ops/backup/policy", { preHandler: preHandlers }, async (_request, reply) => {
    return reply.send(opsBackupService.getPolicy());
  });

  server.get("/ops/backup/runs", { preHandler: preHandlers }, async (request, reply) => {
    const queryParams = request.query as { limit?: string };
    const limit = Number.parseInt(queryParams.limit ?? "50", 10);
    return reply.send(await opsBackupService.listRuns(limit));
  });

  server.post("/ops/backup/run", { preHandler: preHandlers }, async (request, reply) => {
    try {
      const result = await opsBackupService.runBackup({
        initiatedBy: request.user.sub
      });
      return reply.code(201).send(result);
    } catch (error) {
      const code =
        error instanceof Error && error.message === "backup_encryption_key_missing"
          ? "backup_encryption_key_missing"
          : "backup_failed";
      return sendApiError(reply, 500, code, error instanceof Error ? error.message : "Backup failed.");
    }
  });

  server.post("/ops/restore-drill/run", { preHandler: preHandlers }, async (request, reply) => {
    const parsed = restoreDrillSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    try {
      const result = await opsBackupService.runRestoreDrill({
        backupPath: parsed.data.backup_path
      });
      return reply.code(201).send(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Restore drill failed.";
      if (message === "backup_not_found") {
        return sendApiError(reply, 404, "backup_not_found", "No backup file is available for restore drill.");
      }
      if (message === "restore_drill_rto_target_exceeded") {
        return sendApiError(reply, 409, "restore_drill_rto_target_exceeded", "Restore drill exceeded configured RTO target.");
      }
      return sendApiError(reply, 500, "restore_drill_failed", message);
    }
  });

  server.post("/ops/alerts/simulate", { preHandler: preHandlers }, async (request, reply) => {
    const parsed = alertSimulationSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }
    const thresholds = parsed.data;

    const snapshot = metricsService.snapshot();
    const api5xx = snapshot.api_errors
      .filter((row) => row.status_code >= 500)
      .reduce((sum, row) => sum + row.total, 0);
    const commandTimeouts = snapshot.command_totals
      .filter((row) => row.result === "timeout")
      .reduce((sum, row) => sum + row.total, 0);
    const schedulerErrors = snapshot.scheduler.tick_error + snapshot.scheduler.execution_error;

    const backupFailures = await query<{ total: string }>(
      `SELECT COUNT(*)::text AS total
       FROM ops_backup_runs
       WHERE status = 'error'
         AND started_at > now() - interval '24 hours'`
    );
    const backupFailureTotal = Number(backupFailures.rows[0]?.total ?? "0");

    const alerts = [
      {
        id: "api_5xx_spike",
        metric: "api_5xx_total",
        threshold: thresholds.api_5xx_threshold,
        current: api5xx,
        fired: api5xx >= thresholds.api_5xx_threshold,
        severity: "critical"
      },
      {
        id: "command_timeout_spike",
        metric: "command_timeout_total",
        threshold: thresholds.command_timeout_threshold,
        current: commandTimeouts,
        fired: commandTimeouts >= thresholds.command_timeout_threshold,
        severity: "high"
      },
      {
        id: "scheduler_error_spike",
        metric: "scheduler_error_total",
        threshold: thresholds.scheduler_error_threshold,
        current: schedulerErrors,
        fired: schedulerErrors >= thresholds.scheduler_error_threshold,
        severity: "high"
      },
      {
        id: "backup_failures_recent",
        metric: "backup_failures_24h",
        threshold: thresholds.backup_failure_threshold,
        current: backupFailureTotal,
        fired: backupFailureTotal >= thresholds.backup_failure_threshold,
        severity: "critical"
      }
    ];

    const notifications = alerts
      .filter((item) => item.fired)
      .map((item) => ({
        channel: "ops",
        alert_id: item.id,
        severity: item.severity,
        message: `${item.id} fired (${item.current} >= ${item.threshold})`
      }));

    return reply.send({
      evaluated_at: nowIso(),
      alerts,
      notifications
    });
  });

  server.get("/versioning", { preHandler: preHandlers }, async (_request, reply) => {
    return reply.send({
      rest_version: env.API_REST_VERSION,
      ws_version: env.API_WS_VERSION,
      deprecation_window_days: env.API_DEPRECATION_WINDOW_DAYS,
      deprecation_notice: env.API_DEPRECATION_NOTICE ?? null,
      docs: {
        policy: "docs/api/versioning-policy.md",
        changelog_required: true
      }
    });
  });
}
