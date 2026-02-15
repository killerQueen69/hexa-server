import { query } from "../db/connection";
import { realtimeHub } from "../realtime/hub";
import { newId } from "../utils/crypto";
import { nowIso } from "../utils/time";
import { RelayServiceError, relayService } from "./relay-service";

type AutomationRuleRow = {
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
  device_uid: string;
};

export type AutomationRunStatus = "executed" | "skipped" | "failed";

export type AutomationRunResult = {
  status: AutomationRunStatus;
  reason?: string;
  code?: string;
  message?: string;
  action_result?: unknown;
};

type RelayStateConditionRow = {
  is_on: boolean;
};

type InputEventPayload = {
  type: "input_event";
  deviceUid: string;
  input_index?: number;
  input_type?: string;
  event?: string;
  duration_ms?: number;
  ts?: string;
  raw: Record<string, unknown>;
};

type DeviceEventPayload = {
  type: "device_online" | "device_offline";
  deviceUid: string;
  ts?: string;
  raw: Record<string, unknown>;
};

type AutomationEvent = InputEventPayload | DeviceEventPayload;

type LoggerLike = {
  warn: (obj: unknown, msg?: string) => void;
  error: (obj: unknown, msg?: string) => void;
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

function eventKey(ruleId: string, event: AutomationEvent): string | null {
  if (event.type === "input_event") {
    if (!event.ts) {
      return null;
    }
    return [
      ruleId,
      event.type,
      event.input_index ?? "na",
      event.event ?? "na",
      event.ts ?? "na"
    ].join(":");
  }

  if (!event.ts) {
    return null;
  }

  return [
    ruleId,
    event.type,
    event.ts ?? "na"
  ].join(":");
}

async function writeAutomationFailureAudit(params: {
  ruleId: string;
  userId: string;
  deviceId: string;
  code: string;
  message: string;
}): Promise<void> {
  await query(
    `INSERT INTO audit_log (
       id, device_id, user_id, automation_id, action, details, source, created_at
     ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
    [
      newId(),
      params.deviceId,
      params.userId,
      params.ruleId,
      "automation_execution_failed",
      JSON.stringify({
        code: params.code,
        message: params.message
      }),
      "automation",
      nowIso()
    ]
  );
}

class AutomationService {
  private readonly recentEvents = new Map<string, number>();
  private readonly dedupeWindowMs = 15_000;

  async ensureDefaultHoldRule(userId: string, deviceId: string): Promise<void> {
    const existing = await query<{ id: string }>(
      `SELECT id
       FROM automation_rules
       WHERE user_id = $1
         AND device_id = $2
         AND name = $3
       LIMIT 1`,
      [userId, deviceId, "Template: Hold 10s -> All relays off"]
    );
    if (existing.rowCount && existing.rowCount > 0) {
      return;
    }

    const now = nowIso();
    await query(
      `INSERT INTO automation_rules (
         id, user_id, device_id, name, trigger_type, trigger_config,
         condition_config, action_type, action_config, cooldown_seconds,
         is_enabled, created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6::jsonb,
         $7::jsonb, $8, $9::jsonb, $10,
         TRUE, $11, $12
       )`,
      [
        newId(),
        userId,
        deviceId,
        "Template: Hold 10s -> All relays off",
        "input_event",
        JSON.stringify({
          input_index: 0,
          event: "hold",
          hold_seconds: 10
        }),
        "{}",
        "set_all_relays",
        JSON.stringify({
          action: "off"
        }),
        15,
        now,
        now
      ]
    );
  }

  async handleInputEvent(
    payload: Record<string, unknown>,
    logger?: LoggerLike
  ): Promise<void> {
    const deviceUid = typeof payload.device_uid === "string" ? payload.device_uid : "";
    if (!deviceUid) {
      return;
    }

    const event: InputEventPayload = {
      type: "input_event",
      deviceUid,
      input_index: parseNumber(payload.input_index) ?? undefined,
      input_type: typeof payload.input_type === "string" ? payload.input_type : undefined,
      event: typeof payload.event === "string" ? payload.event : undefined,
      duration_ms: parseNumber(payload.duration_ms) ?? undefined,
      ts: typeof payload.ts === "string" ? payload.ts : undefined,
      raw: payload
    };

    await this.dispatchEvent(event, logger);
  }

  async handleDeviceEvent(
    payload: {
      type: "device_online" | "device_offline";
      device_uid: string;
      ts?: string;
    },
    logger?: LoggerLike
  ): Promise<void> {
    if (!payload.device_uid) {
      return;
    }

    const event: DeviceEventPayload = {
      type: payload.type,
      deviceUid: payload.device_uid,
      ts: payload.ts,
      raw: {
        type: payload.type,
        device_uid: payload.device_uid,
        ts: payload.ts
      }
    };

    await this.dispatchEvent(event, logger);
  }

  async runNowById(automationId: string): Promise<{
    automation_id: string;
    device_id: string | null;
    device_uid: string;
    status: AutomationRunStatus;
    reason?: string;
    code?: string;
    message?: string;
    action_result?: unknown;
  } | null> {
    const lookup = await query<AutomationRuleRow>(
      `SELECT
         ar.id,
         ar.user_id,
         ar.device_id,
         ar.name,
         ar.trigger_type,
         ar.trigger_config,
         ar.condition_config,
         ar.action_type,
         ar.action_config,
         ar.cooldown_seconds,
         ar.is_enabled,
         ar.last_triggered_at,
         d.device_uid
       FROM automation_rules ar
       JOIN devices d ON d.id = ar.device_id
       WHERE ar.id = $1
       LIMIT 1`,
      [automationId]
    );
    const rule = lookup.rows[0];
    if (!rule) {
      return null;
    }

    if (!rule.is_enabled) {
      return {
        automation_id: rule.id,
        device_id: rule.device_id,
        device_uid: rule.device_uid,
        status: "skipped",
        reason: "automation_disabled"
      };
    }

    const now = nowIso();
    const triggerConfig = asRecord(rule.trigger_config);
    let event: AutomationEvent;
    if (rule.trigger_type === "input_event" || rule.trigger_type === "button_hold") {
      const holdSeconds = parseNumber(triggerConfig.hold_seconds);
      const minimumDurationMs = parseNumber(triggerConfig.minimum_duration_ms);
      const durationFromHold =
        holdSeconds !== null && holdSeconds > 0 ? Math.floor(holdSeconds * 1000) : null;
      const durationMs = Math.max(
        durationFromHold ?? 0,
        minimumDurationMs !== null ? Math.floor(minimumDurationMs) : 0
      );

      event = {
        type: "input_event",
        deviceUid: rule.device_uid,
        input_index: parseNumber(triggerConfig.input_index) ?? undefined,
        input_type: typeof triggerConfig.input_type === "string" ? triggerConfig.input_type : "push_button",
        event:
          typeof triggerConfig.event === "string"
            ? triggerConfig.event
            : rule.trigger_type === "button_hold"
              ? "hold"
              : "press",
        duration_ms: durationMs > 0 ? durationMs : undefined,
        ts: now,
        raw: {
          type: "input_event",
          ts: now,
          synthetic: true
        }
      };
    } else if (rule.trigger_type === "device_online" || rule.trigger_type === "device_offline") {
      event = {
        type: rule.trigger_type,
        deviceUid: rule.device_uid,
        ts: now,
        raw: {
          type: rule.trigger_type,
          ts: now,
          synthetic: true
        }
      };
    } else {
      return {
        automation_id: rule.id,
        device_id: rule.device_id,
        device_uid: rule.device_uid,
        status: "skipped",
        reason: "unsupported_trigger_for_run_now"
      };
    }

    const outcome = await this.processRule(rule, event, undefined, {
      skipDedupe: true
    });
    return {
      automation_id: rule.id,
      device_id: rule.device_id,
      device_uid: rule.device_uid,
      status: outcome.status,
      reason: outcome.reason,
      code: outcome.code,
      message: outcome.message,
      action_result: outcome.action_result
    };
  }

  private async dispatchEvent(event: AutomationEvent, logger?: LoggerLike): Promise<void> {
    const rows = await query<AutomationRuleRow>(
      `SELECT
         ar.id,
         ar.user_id,
         ar.device_id,
         ar.name,
         ar.trigger_type,
         ar.trigger_config,
         ar.condition_config,
         ar.action_type,
         ar.action_config,
         ar.cooldown_seconds,
         ar.is_enabled,
         ar.last_triggered_at,
         d.device_uid
       FROM automation_rules ar
       JOIN devices d ON d.id = ar.device_id
       WHERE ar.is_enabled = TRUE
         AND d.device_uid = $1
         AND d.is_active = TRUE`,
      [event.deviceUid]
    );

    for (const rule of rows.rows) {
      await this.processRule(rule, event, logger);
    }
  }

  private async processRule(
    rule: AutomationRuleRow,
    event: AutomationEvent,
    logger?: LoggerLike,
    options?: {
      skipDedupe?: boolean;
    }
  ): Promise<AutomationRunResult> {
    if (!rule.device_id) {
      return {
        status: "skipped",
        reason: "device_not_attached"
      };
    }
    if (!this.matchesTrigger(rule, event)) {
      return {
        status: "skipped",
        reason: "trigger_mismatch"
      };
    }
    if (!(await this.matchesCondition(rule, event))) {
      return {
        status: "skipped",
        reason: "condition_not_met"
      };
    }

    const nowMs = Date.now();
    const dedupeKey = eventKey(rule.id, event);
    if (!options?.skipDedupe && dedupeKey) {
      const seenAt = this.recentEvents.get(dedupeKey);
      if (typeof seenAt === "number" && nowMs - seenAt < this.dedupeWindowMs) {
        return {
          status: "skipped",
          reason: "dedupe_window"
        };
      }
      this.recentEvents.set(dedupeKey, nowMs);
      this.pruneDedupe(nowMs);
    }

    if (rule.last_triggered_at) {
      const lastTriggered = new Date(rule.last_triggered_at).getTime();
      if (!Number.isNaN(lastTriggered)) {
        const cooldownMs = Math.max(0, rule.cooldown_seconds) * 1000;
        if (nowMs - lastTriggered < cooldownMs) {
          return {
            status: "skipped",
            reason: "cooldown_active"
          };
        }
      }
    }

    try {
      const actionResult = await this.executeAction(rule, event);
      const now = nowIso();
      await query(
        `UPDATE automation_rules
         SET last_triggered_at = $1,
             updated_at = $1
         WHERE id = $2`,
        [now, rule.id]
      );

      realtimeHub.broadcastToUser(rule.user_id, {
        type: "automation_fired",
        automation_id: rule.id,
        automation_name: rule.name,
        device_uid: event.deviceUid,
        ts: now
      });
      return {
        status: "executed",
        action_result: actionResult
      };
    } catch (error) {
      const code = error instanceof RelayServiceError ? error.code : "automation_execution_failed";
      const message = error instanceof Error ? error.message : "Automation execution failed.";
      await writeAutomationFailureAudit({
        ruleId: rule.id,
        userId: rule.user_id,
        deviceId: rule.device_id,
        code,
        message
      });
      logger?.warn(
        {
          rule_id: rule.id,
          device_uid: event.deviceUid,
          code,
          message
        },
        "automation_rule_execution_failed"
      );
      return {
        status: "failed",
        code,
        message
      };
    }
  }

  private matchesTrigger(rule: AutomationRuleRow, event: AutomationEvent): boolean {
    const triggerType = rule.trigger_type;
    const trigger = asRecord(rule.trigger_config);

    if (triggerType === "device_online" || triggerType === "device_offline") {
      return event.type === triggerType;
    }

    if (triggerType === "button_hold") {
      if (event.type !== "input_event") {
        return false;
      }
      if (event.event !== "hold") {
        return false;
      }

      const requiredInput = parseNumber(trigger.input_index);
      if (requiredInput !== null && event.input_index !== requiredInput) {
        return false;
      }

      const holdSeconds = parseNumber(trigger.hold_seconds);
      if (holdSeconds !== null) {
        const duration = event.duration_ms ?? 0;
        if (duration < holdSeconds * 1000) {
          return false;
        }
      }
      return true;
    }

    if (triggerType !== "input_event") {
      return false;
    }

    if (event.type !== "input_event") {
      return false;
    }

    const requiredInputIndex = parseNumber(trigger.input_index);
    if (requiredInputIndex !== null && event.input_index !== requiredInputIndex) {
      return false;
    }

    if (typeof trigger.event === "string" && event.event !== trigger.event) {
      return false;
    }

    if (typeof trigger.input_type === "string" && event.input_type !== trigger.input_type) {
      return false;
    }

    const holdSeconds = parseNumber(trigger.hold_seconds);
    if (holdSeconds !== null) {
      const duration = event.duration_ms ?? 0;
      if (duration < holdSeconds * 1000) {
        return false;
      }
    }

    const minimumDurationMs = parseNumber(trigger.minimum_duration_ms);
    if (minimumDurationMs !== null) {
      const duration = event.duration_ms ?? 0;
      if (duration < minimumDurationMs) {
        return false;
      }
    }

    return true;
  }

  private async matchesCondition(rule: AutomationRuleRow, _event: AutomationEvent): Promise<boolean> {
    const condition = asRecord(rule.condition_config);
    const relayState = asRecord(condition.required_relay_state);

    if (Object.keys(relayState).length === 0) {
      return true;
    }
    if (!rule.device_id) {
      return false;
    }

    const relayIndex = parseNumber(relayState.relay_index);
    if (relayIndex === null || !Number.isInteger(relayIndex)) {
      return false;
    }
    if (typeof relayState.is_on !== "boolean") {
      return false;
    }

    const relay = await query<RelayStateConditionRow>(
      `SELECT is_on
       FROM relay_states
       WHERE device_id = $1
         AND relay_index = $2
       LIMIT 1`,
      [rule.device_id, relayIndex]
    );
    const row = relay.rows[0];
    if (!row) {
      return false;
    }

    return row.is_on === relayState.is_on;
  }

  private async executeAction(rule: AutomationRuleRow, _event: AutomationEvent): Promise<unknown> {
    if (!rule.device_id) {
      return null;
    }
    const action = asRecord(rule.action_config);

    if (rule.action_type === "set_all_relays") {
      if (action.action !== "on" && action.action !== "off") {
        throw new Error("invalid_automation_action");
      }
      return await relayService.setAllRelays({
        deviceId: rule.device_id,
        action: action.action,
        source: {
          actorUserId: rule.user_id,
          source: "automation",
          automationId: rule.id
        }
      });
    }

    if (rule.action_type === "set_relay") {
      const relayIndex = parseNumber(action.relay_index);
      if (relayIndex === null || !Number.isInteger(relayIndex)) {
        throw new Error("invalid_automation_action");
      }
      if (action.action !== "on" && action.action !== "off" && action.action !== "toggle") {
        throw new Error("invalid_automation_action");
      }

      return await relayService.setRelay({
        deviceId: rule.device_id,
        relayIndex,
        action: action.action,
        source: {
          actorUserId: rule.user_id,
          source: "automation",
          automationId: rule.id
        }
      });
    }

    throw new Error("unsupported_automation_action");
  }

  private pruneDedupe(nowMs: number): void {
    for (const [key, createdAt] of this.recentEvents) {
      if (nowMs - createdAt > this.dedupeWindowMs) {
        this.recentEvents.delete(key);
      }
    }
  }
}

export const automationService = new AutomationService();
