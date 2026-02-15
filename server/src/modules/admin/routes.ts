import { FastifyInstance } from "fastify";
import { z } from "zod";
import { env } from "../../config/env";
import { query, withTransaction } from "../../db/connection";
import { authenticate, requireRole } from "../../http/auth-guards";
import { sendApiError } from "../../http/api-error";
import { realtimeHub } from "../../realtime/hub";
import { automationService } from "../../services/automation-service";
import { deviceFallbackSyncService } from "../../services/device-fallback-sync-service";
import { metricsService } from "../../services/metrics-service";
import { opsBackupService } from "../../services/ops-backup-service";
import { RelayServiceError, relayService } from "../../services/relay-service";
import {
  type ScheduleType,
  computeNextExecution,
  toIsoOrNull as toScheduleIsoOrNull,
  validateCronExpression
} from "../../services/schedule-utils";
import { schedulerService } from "../../services/scheduler-service";
import { newId, randomToken, sha256 } from "../../utils/crypto";
import { deriveStableClaimCode } from "../../utils/claim-code";
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
  config: unknown;
  last_action_at: Date | string | null;
  last_action: unknown;
  last_input_event: unknown;
  created_at: Date | string;
  updated_at: Date | string;
  relays: unknown;
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

type InputConfigValidationDevice = {
  relay_count: number;
  button_count: number;
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

type AdminAutomationRow = {
  id: string;
  user_id: string;
  device_id: string | null;
  name: string;
  trigger_type: string;
  trigger_config: unknown;
  condition_config: unknown;
  action_type: string;
  action_config: unknown;
  cooldown_seconds: number;
  is_enabled: boolean;
  last_triggered_at: Date | string | null;
  definition_updated_at: Date | string;
  created_at: Date | string;
  updated_at: Date | string;
};

type AdminScheduleRow = {
  id: string;
  user_id: string;
  device_id: string;
  relay_index: number | null;
  target_scope: "single" | "all";
  name: string | null;
  schedule_type: "once" | "cron";
  cron_expression: string | null;
  execute_at: Date | string | null;
  timezone: string;
  action: "on" | "off" | "toggle";
  is_enabled: boolean;
  last_executed: Date | string | null;
  next_execution: Date | string | null;
  execution_count: number;
  definition_updated_at: Date | string;
  created_at: Date | string;
  updated_at: Date | string;
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
  input_config: z.array(
    z.object({
      input_index: z.number().int().min(0),
      input_type: z.enum(["push_button", "rocker_switch"]),
      linked: z.boolean(),
      target_relay_index: z.number().int().min(0).nullable(),
      rocker_mode: z.enum(["edge_toggle", "follow_position"]).nullable(),
      invert_input: z.boolean(),
      hold_seconds: z.number().int().min(1).max(600).nullable()
    })
  ).optional(),
  power_restore_mode: z.enum(["last_state", "all_off", "all_on"]).optional(),
  ota_channel: z.enum(["dev", "beta", "stable"]).optional(),
  firmware_version: z.string().min(1).max(100).nullable().optional(),
  config: z.record(z.unknown()).optional()
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

const adminCreateAutomationSchema = z.object({
  name: z.string().min(1).max(120),
  trigger_type: z.enum(["input_event", "button_hold", "device_online", "device_offline"]),
  trigger_config: z.record(z.unknown()).default({}),
  condition_config: z.record(z.unknown()).default({}),
  action_type: z.enum(["set_relay", "set_all_relays"]),
  action_config: z.record(z.unknown()).default({}),
  cooldown_seconds: z.number().int().min(0).max(86400).default(0),
  is_enabled: z.boolean().default(true)
});

const adminCreateScheduleSchema = z.object({
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
    if (Object.keys(params.triggerConfig).length > 0) {
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

function normalizeAutomationError(error: Error): string {
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
  } else if (params.action === "toggle") {
    throw new Error("invalid_action_for_all_scope");
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
  const nextIso = toScheduleIsoOrNull(next);
  if (!nextIso) {
    throw new Error("schedule_in_past");
  }
  return { nextExecution: nextIso };
}

function normalizeScheduleError(error: Error): { code: string; message: string } {
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
    config: row.config,
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

function serializeAutomation(row: AdminAutomationRow) {
  return {
    id: row.id,
    user_id: row.user_id,
    device_id: row.device_id,
    name: row.name,
    trigger_type: row.trigger_type,
    trigger_config: asObject(row.trigger_config),
    condition_config: asObject(row.condition_config),
    action_type: row.action_type,
    action_config: asObject(row.action_config),
    cooldown_seconds: row.cooldown_seconds,
    is_enabled: row.is_enabled,
    last_triggered_at: toIso(row.last_triggered_at),
    definition_updated_at: toIso(row.definition_updated_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function serializeSchedule(row: AdminScheduleRow) {
  return {
    id: row.id,
    user_id: row.user_id,
    device_id: row.device_id,
    relay_index: row.relay_index,
    target_scope: row.target_scope,
    name: row.name,
    schedule_type: row.schedule_type,
    cron_expression: row.cron_expression,
    execute_at: toIso(row.execute_at),
    timezone: row.timezone,
    action: row.action,
    is_enabled: row.is_enabled,
    last_executed: toIso(row.last_executed),
    next_execution: toIso(row.next_execution),
    execution_count: row.execution_count,
    definition_updated_at: toIso(row.definition_updated_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at)
  };
}

function validateInputConfigMatrix(
  device: InputConfigValidationDevice,
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

async function getClaimedDevice(deviceId: string): Promise<{
  id: string;
  device_uid: string;
  owner_user_id: string;
  relay_count: number;
  button_count: number;
} | null> {
  const result = await query<{
    id: string;
    device_uid: string;
    owner_user_id: string | null;
    relay_count: number;
    button_count: number;
  }>(
    `SELECT id, device_uid, owner_user_id, relay_count, button_count
     FROM devices
     WHERE id = $1
       AND is_active = TRUE
     LIMIT 1`,
    [deviceId]
  );
  const row = result.rows[0];
  if (!row || !row.owner_user_id) {
    return null;
  }
  return {
    id: row.id,
    device_uid: row.device_uid,
    owner_user_id: row.owner_user_id,
    relay_count: row.relay_count,
    button_count: row.button_count
  };
}

async function adminUserCount(client?: { query: (sql: string, params?: unknown[]) => Promise<{ rows: Array<{ total: string }> }> }): Promise<number> {
  if (client) {
    const result = await client.query(
      `SELECT COUNT(*)::text AS total
       FROM users
       WHERE role = 'admin'`
    );
    return Number(result.rows[0]?.total ?? "0");
  }

  const result = await query<{ total: string }>(
    `SELECT COUNT(*)::text AS total
     FROM users
     WHERE role = 'admin'`
  );
  return Number(result.rows[0]?.total ?? "0");
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
        d.config,
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

  server.delete("/users/:id", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    if (!params.id || typeof params.id !== "string") {
      return sendApiError(reply, 400, "validation_error", "User id is required.");
    }

    if (params.id === request.user.sub) {
      return sendApiError(reply, 400, "validation_error", "You cannot delete your own admin account.");
    }

    const outcome = await withTransaction(async (client) => {
      const existing = await client.query<{ id: string; role: "admin" | "user" }>(
        `SELECT id, role
         FROM users
         WHERE id = $1
         LIMIT 1
         FOR UPDATE`,
        [params.id]
      );

      if (!existing.rowCount || existing.rowCount === 0) {
        return { kind: "not_found" as const };
      }

      const userRole = existing.rows[0].role;
      if (userRole === "admin") {
        const admins = await adminUserCount(client);
        if (admins <= 1) {
          return { kind: "last_admin" as const };
        }
      }

      const now = nowIso();
      const releasedDevices = await client.query<{ id: string }>(
        `UPDATE devices
         SET owner_user_id = NULL,
             claim_code = COALESCE(
               NULLIF(claim_code, ''),
               UPPER(LPAD(RIGHT(REGEXP_REPLACE(COALESCE(hardware_uid, device_uid), '[^A-Fa-f0-9]', '', 'g'), 8), 8, '0'))
             ),
             claim_code_created_at = COALESCE(claim_code_created_at, $2),
             updated_at = $2
         WHERE owner_user_id = $1
         RETURNING id`,
        [params.id, now]
      );

      await client.query(`DELETE FROM user_devices WHERE user_id = $1`, [params.id]);

      await client.query(
        `DELETE FROM users
         WHERE id = $1`,
        [params.id]
      );

      return {
        kind: "deleted" as const,
        releasedDeviceIds: releasedDevices.rows.map((row) => row.id)
      };
    });

    if (outcome.kind === "not_found") {
      return sendApiError(reply, 404, "not_found", "User not found.");
    }

    if (outcome.kind === "last_admin") {
      return sendApiError(reply, 409, "last_admin", "Cannot delete the last admin user.");
    }

    for (const deviceId of outcome.releasedDeviceIds) {
      void deviceFallbackSyncService.syncDeviceFallback(deviceId).catch(() => undefined);
    }

    return reply.send({
      ok: true,
      deleted_user_id: params.id,
      released_devices: outcome.releasedDeviceIds.length
    });
  });

  server.get("/devices", { preHandler: preHandlers }, async (_request, reply) => {
    const rows = await listGlobalDevices();
    return reply.send(rows.map((row) => serializeDevice(row)));
  });

  server.get("/devices/:id/automations", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const device = await getClaimedDevice(params.id);
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Claimed device not found.");
    }

    const rules = await query<AdminAutomationRow>(
      `SELECT
         id, user_id, device_id, name, trigger_type, trigger_config, condition_config,
         action_type, action_config, cooldown_seconds, is_enabled, last_triggered_at,
         definition_updated_at, created_at, updated_at
       FROM automation_rules
       WHERE device_id = $1
         AND user_id = $2
       ORDER BY definition_updated_at DESC, created_at DESC`,
      [device.id, device.owner_user_id]
    );
    return reply.send(rules.rows.map((row) => serializeAutomation(row)));
  });

  server.post("/devices/:id/automations", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = adminCreateAutomationSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getClaimedDevice(params.id);
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Claimed device not found.");
    }

    const body = parsed.data;
    try {
      validateAutomationConfig({
        triggerType: body.trigger_type,
        triggerConfig: body.trigger_config,
        actionType: body.action_type,
        actionConfig: body.action_config,
        relayCount: device.relay_count,
        buttonCount: device.button_count
      });

      const now = nowIso();
      const inserted = await query<AdminAutomationRow>(
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
           is_enabled, last_triggered_at, definition_updated_at, created_at, updated_at`,
        [
          newId(),
          device.owner_user_id,
          device.id,
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
      void deviceFallbackSyncService.syncDeviceFallback(device.id).catch(() => undefined);
      return reply.code(201).send(serializeAutomation(inserted.rows[0]));
    } catch (error) {
      return sendApiError(reply, 400, "validation_error", normalizeAutomationError(error as Error));
    }
  });

  server.get("/devices/:id/schedules", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const device = await getClaimedDevice(params.id);
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Claimed device not found.");
    }

    const schedules = await query<AdminScheduleRow>(
      `SELECT
         id, user_id, device_id, relay_index, target_scope, name,
         schedule_type, cron_expression, execute_at, timezone, action,
         is_enabled, last_executed, next_execution, execution_count,
         definition_updated_at, created_at, updated_at
       FROM schedules
       WHERE device_id = $1
         AND user_id = $2
       ORDER BY definition_updated_at DESC, created_at DESC`,
      [device.id, device.owner_user_id]
    );
    return reply.send(schedules.rows.map((row) => serializeSchedule(row)));
  });

  server.post("/devices/:id/schedules", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const parsed = adminCreateScheduleSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const device = await getClaimedDevice(params.id);
    if (!device) {
      return sendApiError(reply, 404, "not_found", "Claimed device not found.");
    }

    const body = parsed.data;
    try {
      const validation = validateSchedulePayload({
        targetScope: body.target_scope,
        relayIndex: body.target_scope === "single" ? body.relay_index ?? null : null,
        action: body.action,
        scheduleType: body.schedule_type,
        cronExpression: body.cron_expression ?? null,
        executeAt: body.execute_at ?? null,
        timezone: body.timezone,
        relayCount: device.relay_count
      });

      const now = nowIso();
      const inserted = await query<AdminScheduleRow>(
        `INSERT INTO schedules (
           id, user_id, device_id, relay_index, target_scope, name,
           schedule_type, cron_expression, execute_at, timezone, action,
           is_enabled, next_execution, definition_updated_at, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, $8, $9, $10, $11,
           $12, $13, $14, $15, $16
         )
         RETURNING
           id, user_id, device_id, relay_index, target_scope, name,
           schedule_type, cron_expression, execute_at, timezone, action,
           is_enabled, last_executed, next_execution, execution_count,
           definition_updated_at, created_at, updated_at`,
        [
          newId(),
          device.owner_user_id,
          device.id,
          body.target_scope === "single" ? body.relay_index ?? null : null,
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
          now,
          now
        ]
      );
      void deviceFallbackSyncService.syncDeviceFallback(device.id).catch(() => undefined);
      return reply.code(201).send(serializeSchedule(inserted.rows[0]));
    } catch (error) {
      const normalized = normalizeScheduleError(error as Error);
      return sendApiError(reply, 400, normalized.code, normalized.message);
    }
  });

  server.post("/automations/:id/run-now", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const ownership = await query<{
      id: string;
      user_id: string;
      device_id: string | null;
      owner_user_id: string | null;
    }>(
      `SELECT ar.id, ar.user_id, ar.device_id, d.owner_user_id
       FROM automation_rules ar
       LEFT JOIN devices d ON d.id = ar.device_id
       WHERE ar.id = $1
       LIMIT 1`,
      [params.id]
    );
    const row = ownership.rows[0];
    if (!row || !row.device_id || !row.owner_user_id) {
      return sendApiError(reply, 404, "not_found", "Automation for claimed device not found.");
    }
    if (row.user_id !== row.owner_user_id) {
      return sendApiError(
        reply,
        409,
        "ownership_mismatch",
        "Automation does not belong to the current device owner."
      );
    }

    const runResult = await automationService.runNowById(params.id);
    if (!runResult) {
      return sendApiError(reply, 404, "not_found", "Automation not found.");
    }
    return reply.send(runResult);
  });

  server.post("/schedules/:id/run-now", { preHandler: preHandlers }, async (request, reply) => {
    const params = request.params as { id: string };
    const ownership = await query<{
      id: string;
      user_id: string;
      device_id: string;
      owner_user_id: string | null;
    }>(
      `SELECT s.id, s.user_id, s.device_id, d.owner_user_id
       FROM schedules s
       JOIN devices d ON d.id = s.device_id
       WHERE s.id = $1
       LIMIT 1`,
      [params.id]
    );
    const row = ownership.rows[0];
    if (!row || !row.owner_user_id) {
      return sendApiError(reply, 404, "not_found", "Schedule for claimed device not found.");
    }
    if (row.user_id !== row.owner_user_id) {
      return sendApiError(
        reply,
        409,
        "ownership_mismatch",
        "Schedule does not belong to the current device owner."
      );
    }

    const runResult = await schedulerService.runNowById(params.id);
    if (!runResult) {
      return sendApiError(reply, 404, "not_found", "Schedule not found.");
    }
    return reply.send(runResult);
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

    let normalizedInputConfig: InputConfigRow[] | undefined;

    let updated: DeviceRow | null;
    try {
      updated = await withTransaction(async (client) => {
      const lookup = await client.query<{
        owner_user_id: string | null;
        relay_count: number;
        button_count: number;
        claim_code: string | null;
        claim_code_created_at: Date | string | null;
        hardware_uid: string | null;
        device_uid: string;
      }>(
        `SELECT owner_user_id, relay_count, button_count, claim_code, claim_code_created_at, hardware_uid, device_uid
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

      if (typeof changes.input_config !== "undefined") {
        try {
          normalizedInputConfig = validateInputConfigMatrix(
            {
              relay_count: lookup.rows[0].relay_count,
              button_count: lookup.rows[0].button_count
            },
            changes.input_config
          );
        } catch (error) {
          throw new Error(`input_config_invalid:${normalizeInputConfigError(error as Error)}`);
        }
      }

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
      if (typeof changes.input_config !== "undefined") {
        values.push(JSON.stringify(normalizedInputConfig ?? changes.input_config));
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
      if (typeof changes.owner_user_id !== "undefined") {
        values.push(changes.owner_user_id);
        fields.push(`owner_user_id = $${values.length}`);
        nextOwnerId = changes.owner_user_id;

        if (!changes.owner_user_id) {
          const claimCode = deriveStableClaimCode({
            existingClaimCode: lookup.rows[0].claim_code,
            hardwareUid: lookup.rows[0].hardware_uid,
            deviceUid: lookup.rows[0].device_uid
          });
          const claimCodeCreatedAt = lookup.rows[0].claim_code_created_at
            ? (lookup.rows[0].claim_code_created_at instanceof Date
                ? lookup.rows[0].claim_code_created_at.toISOString()
                : lookup.rows[0].claim_code_created_at)
            : nowIso();

          values.push(claimCode);
          fields.push(`claim_code = $${values.length}`);
          values.push(claimCodeCreatedAt);
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
           d.config,
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
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("input_config_invalid:")) {
        const message = error.message.replace("input_config_invalid:", "") || "Invalid input_config matrix.";
        return sendApiError(reply, 400, "validation_error", message);
      }
      throw error;
    }

    if (!updated) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }

    const connectivityUpdate =
      typeof changes.config !== "undefined" ? extractConnectivityUpdate(updated.config) : undefined;
    if (
      normalizedInputConfig ||
      typeof changes.power_restore_mode !== "undefined" ||
      connectivityUpdate
    ) {
      pushDeviceConfigUpdate(updated.device_uid, {
        io_config: normalizedInputConfig,
        power_restore_mode: changes.power_restore_mode,
        connectivity: connectivityUpdate
      });
    }
    if (typeof changes.owner_user_id !== "undefined") {
      void deviceFallbackSyncService.syncDeviceFallback(updated.id).catch(() => undefined);
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
    const released = await withTransaction(async (client) => {
      const lookup = await client.query<{
        id: string;
        device_uid: string;
        hardware_uid: string | null;
        claim_code: string | null;
        claim_code_created_at: Date | string | null;
      }>(
        `SELECT id, device_uid, hardware_uid, claim_code, claim_code_created_at
         FROM devices
         WHERE id = $1
         LIMIT 1
         FOR UPDATE`,
        [params.id]
      );
      if (!lookup.rowCount || lookup.rowCount === 0) {
        return false;
      }
      const row = lookup.rows[0];
      const claimCode = deriveStableClaimCode({
        existingClaimCode: row.claim_code,
        hardwareUid: row.hardware_uid,
        deviceUid: row.device_uid
      });
      const claimCodeCreatedAt = row.claim_code_created_at
        ? (row.claim_code_created_at instanceof Date
            ? row.claim_code_created_at.toISOString()
            : row.claim_code_created_at)
        : nowIso();

      await client.query(
        `UPDATE devices
         SET owner_user_id = NULL,
             claim_code = $1,
             claim_code_created_at = $2,
             updated_at = $3
         WHERE id = $4`,
        [claimCode, claimCodeCreatedAt, nowIso(), params.id]
      );
      await client.query(`DELETE FROM user_devices WHERE device_id = $1`, [params.id]);
      return claimCode;
    });
    if (!released) {
      return sendApiError(reply, 404, "not_found", "Device not found.");
    }
    void deviceFallbackSyncService.syncDeviceFallback(params.id).catch(() => undefined);
    return reply.send({
      ok: true,
      claim_code: released
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

  server.delete("/audit", { preHandler: preHandlers }, async (request, reply) => {
    const queryParams = request.query as {
      device_id?: string;
      source?: string;
      action?: string;
    };

    const filters: string[] = [];
    const values: unknown[] = [];

    if (queryParams.device_id) {
      values.push(queryParams.device_id);
      filters.push(`device_id = $${values.length}`);
    }
    if (queryParams.source) {
      values.push(queryParams.source);
      filters.push(`source = $${values.length}`);
    }
    if (queryParams.action) {
      values.push(queryParams.action);
      filters.push(`action = $${values.length}`);
    }

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
    const deleted = await query<{ total: string }>(
      `WITH removed AS (
         DELETE FROM audit_log
         ${whereClause}
         RETURNING 1
       )
       SELECT COUNT(*)::text AS total
       FROM removed`,
      values
    );

    return reply.send({
      ok: true,
      deleted: Number(deleted.rows[0]?.total ?? "0"),
      filters: {
        device_id: queryParams.device_id ?? null,
        source: queryParams.source ?? null,
        action: queryParams.action ?? null
      }
    });
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
