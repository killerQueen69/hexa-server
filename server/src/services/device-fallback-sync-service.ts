import { query } from "../db/connection";
import { realtimeHub } from "../realtime/hub";
import { nowIso } from "../utils/time";

type DeviceOwnerRow = {
  id: string;
  device_uid: string;
  owner_user_id: string | null;
  is_active: boolean;
};

type AutomationFallbackRow = {
  id: string;
  trigger_type: "input_event" | "button_hold" | "device_online" | "device_offline";
  trigger_config: unknown;
  condition_config: unknown;
  action_type: "set_relay" | "set_all_relays";
  action_config: unknown;
  cooldown_seconds: number;
  definition_updated_at: Date | string;
};

type ScheduleFallbackRow = {
  id: string;
  relay_index: number | null;
  target_scope: "single" | "all";
  schedule_type: "once" | "cron";
  cron_expression: string | null;
  execute_at: Date | string | null;
  timezone: string;
  action: "on" | "off" | "toggle";
  definition_updated_at: Date | string;
};

type FallbackRulePayload = {
  id: string;
  source_type: "automation" | "schedule";
  source_id: string;
  trigger_type: "input_event" | "button_hold" | "time_once" | "time_cron";
  trigger_config: Record<string, unknown>;
  condition_config: Record<string, unknown>;
  action_type: "set_relay" | "set_all_relays";
  action_config: Record<string, unknown>;
  cooldown_seconds: number;
  enabled: boolean;
  trigger_index?: number;
  trigger_event?: string;
  relay_index?: number;
  action?: "on" | "off" | "toggle";
};

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
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

function toMs(value: Date | string | null): number | null {
  if (!value) {
    return null;
  }
  const ms = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(ms)) {
    return null;
  }
  return ms;
}

function normalizeCronExpressionToUtc(expression: string): string | null {
  const trimmed = expression.trim();
  if (!trimmed) {
    return null;
  }

  const parts = trimmed.split(/\s+/);
  if (parts.length !== 5) {
    return null;
  }
  return parts.join(" ");
}

function mapAutomationRule(row: AutomationFallbackRow): FallbackRulePayload | null {
  if (row.trigger_type !== "input_event" && row.trigger_type !== "button_hold") {
    return null;
  }

  const triggerConfig = asRecord(row.trigger_config);
  const conditionConfig = asRecord(row.condition_config);
  const actionConfig = asRecord(row.action_config);
  const cooldownSeconds = Math.max(0, Math.trunc(row.cooldown_seconds || 0));

  if (row.action_type === "set_all_relays") {
    const action = actionConfig.action;
    if (action !== "on" && action !== "off") {
      return null;
    }

    const payload: FallbackRulePayload = {
      id: `automation:${row.id}`,
      source_type: "automation",
      source_id: row.id,
      trigger_type: row.trigger_type,
      trigger_config: triggerConfig,
      condition_config: conditionConfig,
      action_type: row.action_type,
      action_config: actionConfig,
      cooldown_seconds: cooldownSeconds,
      enabled: true,
      action
    };

    const inputIndex = parseNumber(triggerConfig.input_index);
    if (inputIndex !== null && Number.isInteger(inputIndex)) {
      payload.trigger_index = inputIndex;
    }
    if (typeof triggerConfig.event === "string" && triggerConfig.event.trim().length > 0) {
      payload.trigger_event = triggerConfig.event.trim();
    }

    return payload;
  }

  if (row.action_type !== "set_relay") {
    return null;
  }

  const relayIndex = parseNumber(actionConfig.relay_index);
  if (relayIndex === null || !Number.isInteger(relayIndex) || relayIndex < 0) {
    return null;
  }
  const action = actionConfig.action;
  if (action !== "on" && action !== "off" && action !== "toggle") {
    return null;
  }

  const payload: FallbackRulePayload = {
    id: `automation:${row.id}`,
    source_type: "automation",
    source_id: row.id,
    trigger_type: row.trigger_type,
    trigger_config: triggerConfig,
    condition_config: conditionConfig,
    action_type: row.action_type,
    action_config: actionConfig,
    cooldown_seconds: cooldownSeconds,
    enabled: true,
    relay_index: relayIndex,
    action
  };

  const inputIndex = parseNumber(triggerConfig.input_index);
  if (inputIndex !== null && Number.isInteger(inputIndex)) {
    payload.trigger_index = inputIndex;
  }
  if (typeof triggerConfig.event === "string" && triggerConfig.event.trim().length > 0) {
    payload.trigger_event = triggerConfig.event.trim();
  }

  return payload;
}

function mapScheduleRule(row: ScheduleFallbackRow): FallbackRulePayload | null {
  const actionConfig: Record<string, unknown> = {};
  let actionType: "set_relay" | "set_all_relays";

  if (row.target_scope === "all") {
    if (row.action !== "on" && row.action !== "off") {
      return null;
    }
    actionType = "set_all_relays";
    actionConfig.action = row.action;
  } else {
    if (!Number.isInteger(row.relay_index) || (row.relay_index as number) < 0) {
      return null;
    }
    if (row.action !== "on" && row.action !== "off" && row.action !== "toggle") {
      return null;
    }
    actionType = "set_relay";
    actionConfig.relay_index = row.relay_index;
    actionConfig.action = row.action;
  }

  const triggerConfig: Record<string, unknown> = {};
  let triggerType: "time_once" | "time_cron";

  if (row.schedule_type === "once") {
    const executeAtMs = toMs(row.execute_at);
    if (executeAtMs === null) {
      return null;
    }
    triggerType = "time_once";
    triggerConfig.execute_at_epoch_utc = Math.floor(executeAtMs / 1000);
  } else {
    const expressionUtc = normalizeCronExpressionToUtc(row.cron_expression ?? "");
    if (!expressionUtc) {
      return null;
    }
    triggerType = "time_cron";
    triggerConfig.cron_expression_utc = expressionUtc;
  }

  const payload: FallbackRulePayload = {
    id: `schedule:${row.id}`,
    source_type: "schedule",
    source_id: row.id,
    trigger_type: triggerType,
    trigger_config: triggerConfig,
    condition_config: {},
    action_type: actionType,
    action_config: actionConfig,
    cooldown_seconds: 0,
    enabled: true,
    action: row.action
  };

  if (actionType === "set_relay") {
    payload.relay_index = row.relay_index as number;
  }

  return payload;
}

class DeviceFallbackSyncService {
  private readonly maxRules = 5;

  async syncDeviceFallback(deviceId: string): Promise<{ device_uid: string | null; sent: boolean; count: number }> {
    const device = await query<DeviceOwnerRow>(
      `SELECT id, device_uid, owner_user_id, is_active
       FROM devices
       WHERE id = $1
       LIMIT 1`,
      [deviceId]
    );
    const row = device.rows[0];
    if (!row || !row.is_active) {
      return {
        device_uid: null,
        sent: false,
        count: 0
      };
    }

    const payload = row.owner_user_id
      ? await this.buildFallbackRules({
          deviceId: row.id,
          ownerUserId: row.owner_user_id
        })
      : [];

    const sent = realtimeHub.sendToDevice(row.device_uid, {
      type: "sync_automations",
      automations: payload,
      ts: nowIso()
    });

    return {
      device_uid: row.device_uid,
      sent,
      count: payload.length
    };
  }

  private async buildFallbackRules(params: {
    deviceId: string;
    ownerUserId: string;
  }): Promise<FallbackRulePayload[]> {
    const [automationRules, scheduleRules] = await Promise.all([
      query<AutomationFallbackRow>(
        `SELECT
           id,
           trigger_type,
           trigger_config,
           condition_config,
           action_type,
           action_config,
           cooldown_seconds,
           definition_updated_at
         FROM automation_rules
         WHERE device_id = $1
           AND user_id = $2
           AND is_enabled = TRUE
         ORDER BY definition_updated_at DESC
         LIMIT 64`,
        [params.deviceId, params.ownerUserId]
      ),
      query<ScheduleFallbackRow>(
        `SELECT
           id,
           relay_index,
           target_scope,
           schedule_type,
           cron_expression,
           execute_at,
           timezone,
           action,
           definition_updated_at
         FROM schedules
         WHERE device_id = $1
           AND user_id = $2
           AND is_enabled = TRUE
         ORDER BY definition_updated_at DESC
         LIMIT 64`,
        [params.deviceId, params.ownerUserId]
      )
    ]);

    const candidates: Array<{
      updatedAtMs: number;
      payload: FallbackRulePayload;
    }> = [];

    for (const row of automationRules.rows) {
      const payload = mapAutomationRule(row);
      if (!payload) {
        continue;
      }
      candidates.push({
        updatedAtMs: toMs(row.definition_updated_at) ?? 0,
        payload
      });
    }

    for (const row of scheduleRules.rows) {
      const payload = mapScheduleRule(row);
      if (!payload) {
        continue;
      }
      candidates.push({
        updatedAtMs: toMs(row.definition_updated_at) ?? 0,
        payload
      });
    }

    candidates.sort((a, b) => {
      if (b.updatedAtMs !== a.updatedAtMs) {
        return b.updatedAtMs - a.updatedAtMs;
      }
      return a.payload.id.localeCompare(b.payload.id);
    });
    return candidates.slice(0, this.maxRules).map((entry) => entry.payload);
  }
}

export const deviceFallbackSyncService = new DeviceFallbackSyncService();
