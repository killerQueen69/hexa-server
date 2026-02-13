import { env } from "../config/env";
import { query, withTransaction } from "../db/connection";
import { realtimeHub } from "../realtime/hub";
import { newId } from "../utils/crypto";
import { nowIso } from "../utils/time";
import { deviceStateCache } from "./device-state-cache";
import { metricsService } from "./metrics-service";
import { smartHomeService } from "./smart-home-service";

type DeviceRow = {
  id: string;
  device_uid: string;
  relay_count: number;
  owner_user_id: string | null;
};

type RelayStateRow = {
  is_on: boolean;
  last_changed_at?: Date | string;
};

type RelayStateSetRow = {
  relay_index: number;
  is_on: boolean;
  last_changed_at: Date | string;
};

type RelayAction = "on" | "off" | "toggle";
type AllRelayAction = "on" | "off";

export class RelayServiceError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown
  ) {
    super(message);
  }
}

export type RelayCommandSource = {
  actorUserId?: string;
  source: "api" | "ws_client" | "schedule" | "automation" | "system" | "homekit" | "alexa" | "ha";
  scheduleId?: string;
  automationId?: string;
};

type SetRelayParams = {
  deviceId: string;
  relayIndex: number;
  action: RelayAction;
  source: RelayCommandSource;
  timeoutMs?: number;
};

type SetAllRelaysParams = {
  deviceId: string;
  action: AllRelayAction;
  source: RelayCommandSource;
  timeoutMs?: number;
};

type RelayResult = {
  device_id: string;
  device_uid: string;
  relay_index?: number;
  action: RelayAction | AllRelayAction;
  is_on?: boolean;
  latency_ms: number;
};

async function getDeviceById(deviceId: string): Promise<DeviceRow> {
  const result = await query<DeviceRow>(
    `SELECT id, device_uid, relay_count, owner_user_id
     FROM devices
     WHERE id = $1 AND is_active = TRUE
     LIMIT 1`,
    [deviceId]
  );
  const device = result.rows[0];
  if (!device) {
    throw new RelayServiceError(404, "device_not_found", "Device not found.");
  }
  return device;
}

async function resolveTargetState(deviceId: string, relayIndex: number, action: RelayAction): Promise<boolean> {
  if (action === "on") {
    return true;
  }
  if (action === "off") {
    return false;
  }

  const current = await query<RelayStateRow>(
    `SELECT is_on
     FROM relay_states
     WHERE device_id = $1 AND relay_index = $2
     LIMIT 1`,
    [deviceId, relayIndex]
  );
  const existing = current.rows[0];
  return !existing?.is_on;
}

function ackErrorCode(error: unknown): string {
  if (error instanceof Error && error.message === "ack_timeout") {
    return "device_ack_timeout";
  }
  if (error instanceof Error && error.message === "device_disconnected") {
    return "device_disconnected";
  }
  return "device_ack_failed";
}

type AckFailure = {
  statusCode: number;
  code: string;
  message: string;
};

function mapAckError(error: unknown): AckFailure {
  const code = ackErrorCode(error);
  if (code === "device_ack_timeout") {
    return {
      statusCode: 504,
      code,
      message: "Device ACK not received in time."
    };
  }
  if (code === "device_disconnected") {
    return {
      statusCode: 409,
      code,
      message: "Device disconnected before ACK."
    };
  }
  return {
    statusCode: 504,
    code,
    message: "Device ACK failed."
  };
}

function toEpochMs(value: Date | string | null | undefined): number {
  if (!value) {
    return 0;
  }
  const ms = value instanceof Date ? value.getTime() : Date.parse(value);
  return Number.isFinite(ms) ? ms : 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function waitForDeviceSession(deviceUid: string, attempts = 4, waitMs = 150): Promise<boolean> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (realtimeHub.getDevice(deviceUid)) {
      return true;
    }
    if (attempt < attempts - 1) {
      await sleep(waitMs);
    }
  }
  return false;
}

async function waitForObservedRelayState(params: {
  deviceId: string;
  deviceUid: string;
  relayIndex: number;
  expectedState: boolean;
  commandStartedAtMs: number;
  waitWindowMs: number;
  pollMs: number;
}): Promise<boolean> {
  if (params.waitWindowMs <= 0) {
    return false;
  }

  const deadline = Date.now() + params.waitWindowMs;
  while (Date.now() <= deadline) {
    const snapshot = deviceStateCache.getSnapshotByUid(params.deviceUid);
    if (snapshot) {
      const relayState =
        params.relayIndex >= 0 && params.relayIndex < snapshot.relays.length
          ? snapshot.relays[params.relayIndex]
          : null;
      if (
        relayState === params.expectedState &&
        toEpochMs(snapshot.updatedAt) >= params.commandStartedAtMs
      ) {
        return true;
      }
    }

    const observed = await query<RelayStateRow>(
      `SELECT is_on, last_changed_at
       FROM relay_states
       WHERE device_id = $1
         AND relay_index = $2
       LIMIT 1`,
      [params.deviceId, params.relayIndex]
    );
    const row = observed.rows[0];
    if (
      row &&
      row.is_on === params.expectedState &&
      toEpochMs(row.last_changed_at) >= params.commandStartedAtMs
    ) {
      return true;
    }

    if (Date.now() >= deadline) {
      break;
    }
    await sleep(params.pollMs);
  }

  return false;
}

async function waitForObservedAllRelays(params: {
  deviceId: string;
  deviceUid: string;
  relayCount: number;
  expectedState: boolean;
  commandStartedAtMs: number;
  waitWindowMs: number;
  pollMs: number;
}): Promise<boolean> {
  if (params.waitWindowMs <= 0) {
    return false;
  }

  const deadline = Date.now() + params.waitWindowMs;
  while (Date.now() <= deadline) {
    const snapshot = deviceStateCache.getSnapshotByUid(params.deviceUid);
    if (snapshot) {
      const hasEnoughRelays = snapshot.relays.length >= params.relayCount;
      const allExpected = hasEnoughRelays
        ? snapshot.relays.slice(0, params.relayCount).every((isOn) => isOn === params.expectedState)
        : false;
      if (allExpected && toEpochMs(snapshot.updatedAt) >= params.commandStartedAtMs) {
        return true;
      }
    }

    const observed = await query<RelayStateSetRow>(
      `SELECT relay_index, is_on, last_changed_at
       FROM relay_states
       WHERE device_id = $1`,
      [params.deviceId]
    );

    if (observed.rows.length >= params.relayCount) {
      const byIndex = new Map<number, RelayStateSetRow>();
      for (const row of observed.rows) {
        byIndex.set(row.relay_index, row);
      }

      let complete = true;
      for (let i = 0; i < params.relayCount; i += 1) {
        const row = byIndex.get(i);
        if (
          !row ||
          row.is_on !== params.expectedState ||
          toEpochMs(row.last_changed_at) < params.commandStartedAtMs
        ) {
          complete = false;
          break;
        }
      }

      if (complete) {
        return true;
      }
    }

    if (Date.now() >= deadline) {
      break;
    }
    await sleep(params.pollMs);
  }

  return false;
}

async function persistRelayState(params: {
  deviceId: string;
  relayIndex: number;
  isOn: boolean;
  changedBy: string;
}): Promise<void> {
  await query(
    `INSERT INTO relay_states (
       id, device_id, relay_index, is_on, last_changed_at, changed_by
     ) VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (device_id, relay_index)
     DO UPDATE SET
       is_on = EXCLUDED.is_on,
       last_changed_at = EXCLUDED.last_changed_at,
       changed_by = EXCLUDED.changed_by`,
    [newId(), params.deviceId, params.relayIndex, params.isOn, nowIso(), params.changedBy]
  );
}

async function writeAudit(params: {
  deviceId: string;
  userId?: string;
  action: string;
  source: string;
  scheduleId?: string;
  automationId?: string;
  details: Record<string, unknown>;
}): Promise<void> {
  await query(
    `INSERT INTO audit_log (
       id, device_id, user_id, schedule_id, automation_id, action, details, source, created_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
    [
      newId(),
      params.deviceId,
      params.userId ?? null,
      params.scheduleId ?? null,
      params.automationId ?? null,
      params.action,
      JSON.stringify(params.details),
      params.source,
      nowIso()
    ]
  );
}

class RelayService {
  async setAllRelays(params: SetAllRelaysParams): Promise<RelayResult> {
    const startedAt = Date.now();

    try {
      const result = await this.setAllRelaysInternal(params);
      metricsService.observeCommand({
        source: params.source.source,
        scope: "all",
        result: "success",
        latencyMs: Date.now() - startedAt
      });
      return result;
    } catch (error) {
      const isTimeout =
        error instanceof RelayServiceError &&
        (error.code === "device_ack_timeout" || error.statusCode === 504);
      metricsService.observeCommand({
        source: params.source.source,
        scope: "all",
        result: isTimeout ? "timeout" : "error",
        latencyMs: Date.now() - startedAt
      });
      throw error;
    }
  }

  async setRelay(params: SetRelayParams): Promise<RelayResult> {
    const startedAt = Date.now();

    try {
      const result = await this.setRelayInternal(params);
      metricsService.observeCommand({
        source: params.source.source,
        scope: "single",
        result: "success",
        latencyMs: Date.now() - startedAt
      });
      return result;
    } catch (error) {
      const isTimeout =
        error instanceof RelayServiceError &&
        (error.code === "device_ack_timeout" || error.statusCode === 504);
      metricsService.observeCommand({
        source: params.source.source,
        scope: "single",
        result: isTimeout ? "timeout" : "error",
        latencyMs: Date.now() - startedAt
      });
      throw error;
    }
  }

  private async setRelayInternal(params: SetRelayParams): Promise<RelayResult> {
    const device = await getDeviceById(params.deviceId);

    if (params.relayIndex < 0 || params.relayIndex >= device.relay_count) {
      throw new RelayServiceError(400, "invalid_relay_index", "Relay index out of range.");
    }

    const online = await waitForDeviceSession(device.device_uid);
    if (!online) {
      throw new RelayServiceError(409, "device_offline", "Device is offline.");
    }

    const targetState = await resolveTargetState(params.deviceId, params.relayIndex, params.action);
    const commandId = newId();
    const commandTimeoutMs = params.timeoutMs ?? env.RELAY_COMMAND_TIMEOUT_MS;
    const commandStartedAtMs = Date.now();
    const pendingAck = realtimeHub.createPendingAck(
      commandId,
      device.device_uid,
      commandTimeoutMs
    );

    const relayCommand = {
      type: "set_relay",
      command_id: commandId,
      relay_index: params.relayIndex,
      action: params.action,
      ts: nowIso()
    };

    let sent = realtimeHub.sendToDevice(device.device_uid, relayCommand);
    if (!sent && (await waitForDeviceSession(device.device_uid, 2, 120))) {
      sent = realtimeHub.sendToDevice(device.device_uid, relayCommand);
    }

    if (!sent) {
      realtimeHub.resolveAck(commandId, {
        ok: false,
        error: "device_disconnected"
      });
      throw new RelayServiceError(409, "device_offline", "Device is offline.");
    }

    let ack;
    let ackOrigin: "device_ack" | "state_report_verify" = "device_ack";
    try {
      ack = await pendingAck;
    } catch (error) {
      const mapped = mapAckError(error);
      if (mapped.code === "device_ack_timeout") {
        const observed = await waitForObservedRelayState({
          deviceId: params.deviceId,
          deviceUid: device.device_uid,
          relayIndex: params.relayIndex,
          expectedState: targetState,
          commandStartedAtMs,
          waitWindowMs: env.RELAY_COMMAND_STATE_VERIFY_WINDOW_MS,
          pollMs: env.RELAY_COMMAND_STATE_VERIFY_POLL_MS
        });

        if (observed) {
          ack = {
            commandId,
            ok: true,
            latencyMs: Date.now() - commandStartedAtMs
          };
          ackOrigin = "state_report_verify";
        } else {
          throw new RelayServiceError(mapped.statusCode, mapped.code, mapped.message, {
            command_id: commandId,
            timeout_ms: commandTimeoutMs,
            verify_window_ms: env.RELAY_COMMAND_STATE_VERIFY_WINDOW_MS
          });
        }
      } else {
        throw new RelayServiceError(mapped.statusCode, mapped.code, mapped.message, {
          command_id: commandId
        });
      }
    }

    if (!ack.ok) {
      throw new RelayServiceError(409, "device_rejected_command", ack.error ?? "Device rejected command.");
    }

    const changedAt = nowIso();
    deviceStateCache.setRelayState({
      deviceId: params.deviceId,
      deviceUid: device.device_uid,
      ownerUserId: device.owner_user_id,
      relayIndex: params.relayIndex,
      isOn: targetState,
      relayCount: device.relay_count,
      updatedAt: changedAt
    });

    await persistRelayState({
      deviceId: params.deviceId,
      relayIndex: params.relayIndex,
      isOn: targetState,
      changedBy: params.source.actorUserId ?? params.source.source
    });

    if (device.owner_user_id) {
      realtimeHub.broadcastToUser(device.owner_user_id, {
        type: "device_state",
        device_uid: device.device_uid,
        relays: [{ relay_index: params.relayIndex, is_on: targetState }],
        ts: changedAt
      });
    }

    try {
      await smartHomeService.syncRelayChanges({
        deviceId: params.deviceId,
        deviceUid: device.device_uid,
        ownerUserId: device.owner_user_id,
        relayCount: device.relay_count,
        relays: [{ relayIndex: params.relayIndex, isOn: targetState }],
        updatedAt: changedAt
      });
    } catch {
      // Integration fan-out errors should not fail the primary relay command path.
    }

    await writeAudit({
      deviceId: params.deviceId,
      userId: params.source.actorUserId,
      action: "set_relay",
      source: params.source.source,
      scheduleId: params.source.scheduleId,
      automationId: params.source.automationId,
      details: {
        relay_index: params.relayIndex,
        action: params.action,
        is_on: targetState,
        command_id: commandId,
        latency_ms: ack.latencyMs,
        ack_origin: ackOrigin
      }
    });

    return {
      device_id: params.deviceId,
      device_uid: device.device_uid,
      relay_index: params.relayIndex,
      action: params.action,
      is_on: targetState,
      latency_ms: ack.latencyMs
    };
  }

  private async setAllRelaysInternal(params: SetAllRelaysParams): Promise<RelayResult> {
    const device = await getDeviceById(params.deviceId);
    const online = await waitForDeviceSession(device.device_uid);
    if (!online) {
      throw new RelayServiceError(409, "device_offline", "Device is offline.");
    }

    const commandId = newId();
    const commandTimeoutMs = params.timeoutMs ?? env.RELAY_COMMAND_TIMEOUT_MS;
    const commandStartedAtMs = Date.now();
    const pendingAck = realtimeHub.createPendingAck(
      commandId,
      device.device_uid,
      commandTimeoutMs
    );

    const allRelayCommand = {
      type: "set_all_relays",
      command_id: commandId,
      action: params.action,
      ts: nowIso()
    };

    let sent = realtimeHub.sendToDevice(device.device_uid, allRelayCommand);
    if (!sent && (await waitForDeviceSession(device.device_uid, 2, 120))) {
      sent = realtimeHub.sendToDevice(device.device_uid, allRelayCommand);
    }

    if (!sent) {
      realtimeHub.resolveAck(commandId, {
        ok: false,
        error: "device_disconnected"
      });
      throw new RelayServiceError(409, "device_offline", "Device is offline.");
    }

    let ack;
    let ackOrigin: "device_ack" | "state_report_verify" = "device_ack";
    try {
      ack = await pendingAck;
    } catch (error) {
      const mapped = mapAckError(error);
      if (mapped.code === "device_ack_timeout") {
        const observed = await waitForObservedAllRelays({
          deviceId: params.deviceId,
          deviceUid: device.device_uid,
          relayCount: device.relay_count,
          expectedState: params.action === "on",
          commandStartedAtMs,
          waitWindowMs: env.RELAY_COMMAND_STATE_VERIFY_WINDOW_MS,
          pollMs: env.RELAY_COMMAND_STATE_VERIFY_POLL_MS
        });

        if (observed) {
          ack = {
            commandId,
            ok: true,
            latencyMs: Date.now() - commandStartedAtMs
          };
          ackOrigin = "state_report_verify";
        } else {
          throw new RelayServiceError(mapped.statusCode, mapped.code, mapped.message, {
            command_id: commandId,
            timeout_ms: commandTimeoutMs,
            verify_window_ms: env.RELAY_COMMAND_STATE_VERIFY_WINDOW_MS
          });
        }
      } else {
        throw new RelayServiceError(mapped.statusCode, mapped.code, mapped.message, {
          command_id: commandId
        });
      }
    }

    if (!ack.ok) {
      throw new RelayServiceError(409, "device_rejected_command", ack.error ?? "Device rejected command.");
    }

    const isOn = params.action === "on";
    const changedAt = nowIso();
    const allRelays = Array.from({ length: device.relay_count }, () => isOn);
    deviceStateCache.setAllRelayStates({
      deviceId: params.deviceId,
      deviceUid: device.device_uid,
      ownerUserId: device.owner_user_id,
      relays: allRelays,
      updatedAt: changedAt
    });

    await withTransaction(async (client) => {
      for (let i = 0; i < device.relay_count; i += 1) {
        await client.query(
          `INSERT INTO relay_states (
             id, device_id, relay_index, is_on, last_changed_at, changed_by
           ) VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (device_id, relay_index)
           DO UPDATE SET
             is_on = EXCLUDED.is_on,
             last_changed_at = EXCLUDED.last_changed_at,
             changed_by = EXCLUDED.changed_by`,
          [
            newId(),
            params.deviceId,
            i,
            isOn,
            changedAt,
            params.source.actorUserId ?? params.source.source
          ]
        );
      }
    });

    if (device.owner_user_id) {
      realtimeHub.broadcastToUser(device.owner_user_id, {
        type: "device_state",
        device_uid: device.device_uid,
        relays: Array.from({ length: device.relay_count }, (_, relayIndex) => ({
          relay_index: relayIndex,
          is_on: isOn
        })),
        ts: changedAt
      });
    }

    try {
      await smartHomeService.syncRelayChanges({
        deviceId: params.deviceId,
        deviceUid: device.device_uid,
        ownerUserId: device.owner_user_id,
        relayCount: device.relay_count,
        relays: Array.from({ length: device.relay_count }, (_, relayIndex) => ({
          relayIndex,
          isOn
        })),
        updatedAt: changedAt
      });
    } catch {
      // Integration fan-out errors should not fail the primary relay command path.
    }

    await writeAudit({
      deviceId: params.deviceId,
      userId: params.source.actorUserId,
      action: "set_all_relays",
      source: params.source.source,
      scheduleId: params.source.scheduleId,
      automationId: params.source.automationId,
      details: {
        action: params.action,
        is_on: isOn,
        command_id: commandId,
        latency_ms: ack.latencyMs,
        ack_origin: ackOrigin
      }
    });

    return {
      device_id: params.deviceId,
      device_uid: device.device_uid,
      action: params.action,
      latency_ms: ack.latencyMs
    };
  }
}

export const relayService = new RelayService();
