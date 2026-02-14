import { FastifyInstance } from "fastify";
import { IncomingMessage } from "node:http";
import { env } from "../../config/env";
import { query } from "../../db/connection";
import { realtimeHub } from "../../realtime/hub";
import { automationService } from "../../services/automation-service";
import { deviceStateCache } from "../../services/device-state-cache";
import { RelayServiceError, relayService } from "../../services/relay-service";
import { smartHomeService } from "../../services/smart-home-service";
import { newId, sha256 } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type DeviceAuthRow = {
  id: string;
  device_uid: string;
  owner_user_id: string | null;
};

type ClientRelayCommand =
  | { scope: "all"; action: "on" | "off" }
  | { scope: "single"; action: "on" | "off" | "toggle"; relayIndex: number };

type ClientWifiCommand =
  | { scope: "wifi"; operation: "clear"; reboot: boolean }
  | {
      scope: "wifi";
      operation: "set";
      ssid: string;
      password: string;
      reboot: boolean;
    };

type ClientCommand = ClientRelayCommand | ClientWifiCommand;

type RawWebSocket = {
  readyState: number;
  OPEN: number;
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
  terminate: () => void;
  ping: () => void;
  on: (event: string, listener: (...args: unknown[]) => void) => void;
};

type RawWebSocketServer = {
  on: (event: string, listener: (...args: unknown[]) => void) => void;
  handleUpgrade: (
    req: IncomingMessage,
    socket: unknown,
    head: Buffer,
    done: (socket: RawWebSocket) => void
  ) => void;
  emit: (event: string, ...args: unknown[]) => void;
  close: (done?: () => void) => void;
  clients: Set<{ terminate: () => void }>;
};

const wsPackage = require("ws") as {
  WebSocketServer: new (args: { noServer: boolean; maxPayload: number }) => RawWebSocketServer;
};

const DEVICE_WS_HEARTBEAT_INTERVAL_MS = 2_500;
const DEVICE_WS_HEARTBEAT_MISS_LIMIT = 1;
const DEVICE_OFFLINE_GRACE_MS = 5_000;
const DEVICE_COMMAND_QUEUE_MAX = 40;
const WIFI_CONFIG_COMMAND_TIMEOUT_MS = 12_000;
const WIFI_SSID_MAX_LEN = 32;
const WIFI_PASSWORD_MAX_LEN = 63;
const pendingOfflineTimers = new Map<string, NodeJS.Timeout>();
const deviceCommandQueues = new Map<string, DeviceCommandQueue>();

type DeviceCommandTask = () => Promise<void>;

type DeviceCommandQueue = {
  running: boolean;
  pending: DeviceCommandTask[];
};

function getDeviceCommandQueue(deviceId: string): DeviceCommandQueue {
  const existing = deviceCommandQueues.get(deviceId);
  if (existing) {
    return existing;
  }

  const created: DeviceCommandQueue = {
    running: false,
    pending: []
  };
  deviceCommandQueues.set(deviceId, created);
  return created;
}

function drainDeviceCommandQueue(deviceId: string, queue: DeviceCommandQueue): void {
  if (queue.running) {
    return;
  }

  queue.running = true;
  void (async () => {
    while (queue.pending.length > 0) {
      const nextTask = queue.pending.shift();
      if (!nextTask) {
        continue;
      }
      try {
        await nextTask();
      } catch {
        // Command tasks must handle their own error-to-ack translation.
      }
    }
  })()
    .catch(() => undefined)
    .finally(() => {
      queue.running = false;
      if (queue.pending.length === 0) {
        deviceCommandQueues.delete(deviceId);
      } else {
        drainDeviceCommandQueue(deviceId, queue);
      }
    });
}

function enqueueDeviceCommand(deviceId: string, task: DeviceCommandTask): boolean {
  const queue = getDeviceCommandQueue(deviceId);
  if (queue.pending.length >= DEVICE_COMMAND_QUEUE_MAX) {
    return false;
  }

  queue.pending.push(task);
  drainDeviceCommandQueue(deviceId, queue);
  return true;
}

function broadcastDeviceEvent(ownerUserId: string | null, payload: unknown): void {
  realtimeHub.broadcastToAudience(
    {
      userId: ownerUserId,
      role: "admin"
    },
    payload
  );
}

function sendJson(socket: RawWebSocket, payload: unknown): boolean {
  if (socket.readyState !== socket.OPEN) {
    return false;
  }

  socket.send(JSON.stringify(payload));
  return true;
}

function parseMessage(data: unknown): unknown | null {
  let text = "";

  if (typeof data === "string") {
    text = data;
  } else if (Buffer.isBuffer(data)) {
    text = data.toString("utf8");
  } else if (Array.isArray(data)) {
    text = Buffer.concat(data as Buffer[]).toString("utf8");
  } else if (data instanceof ArrayBuffer) {
    text = Buffer.from(data).toString("utf8");
  } else {
    return null;
  }

  if (text.length > 16_384) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

async function isDeviceOwner(userId: string, deviceId: string): Promise<boolean> {
  const owned = await query<{ id: string }>(
    `SELECT id
     FROM devices
     WHERE id = $1
       AND owner_user_id = $2
     LIMIT 1`,
    [deviceId, userId]
  );
  return Boolean(owned.rowCount && owned.rowCount > 0);
}

async function readOwnerUserId(deviceId: string): Promise<string | null> {
  const result = await query<{ owner_user_id: string | null }>(
    `SELECT owner_user_id
     FROM devices
     WHERE id = $1
     LIMIT 1`,
    [deviceId]
  );
  return result.rows[0]?.owner_user_id ?? null;
}

function cancelPendingOffline(deviceUid: string): void {
  const timer = pendingOfflineTimers.get(deviceUid);
  if (!timer) {
    return;
  }

  clearTimeout(timer);
  pendingOfflineTimers.delete(deviceUid);
}

function scheduleOfflineBroadcast(deviceUid: string, deviceId: string): void {
  cancelPendingOffline(deviceUid);

  const timer = setTimeout(() => {
    pendingOfflineTimers.delete(deviceUid);

    if (realtimeHub.getDevice(deviceUid)) {
      return;
    }

    void readOwnerUserId(deviceId)
      .then((owner) => {
        const ts = nowIso();
        void automationService
          .handleDeviceEvent({
            type: "device_offline",
            device_uid: deviceUid,
            ts
          })
          .catch(() => undefined);

        void smartHomeService.setDeviceAvailability(deviceUid, false);

        broadcastDeviceEvent(owner, {
          type: "device_offline",
          device_uid: deviceUid,
          ts
        });
      })
      .catch(() => undefined);
  }, DEVICE_OFFLINE_GRACE_MS);

  pendingOfflineTimers.set(deviceUid, timer);
}

async function listOwnedDeviceUids(userId: string): Promise<string[]> {
  const result = await query<{ device_uid: string }>(
    `SELECT device_uid
     FROM devices
     WHERE owner_user_id = $1`,
    [userId]
  );
  return result.rows.map((row) => row.device_uid);
}

async function sendWifiConfigCommand(params: {
  userId: string;
  deviceId: string;
  command: ClientWifiCommand;
  timeoutMs: number;
}): Promise<
  | { ok: true; deviceUid: string; latencyMs: number }
  | {
      ok: false;
      code: string;
      message: string;
      details?: Record<string, unknown>;
    }
> {
  const owned = await query<{ device_uid: string }>(
    `SELECT device_uid
     FROM devices
     WHERE id = $1
       AND owner_user_id = $2
       AND is_active = TRUE
     LIMIT 1`,
    [params.deviceId, params.userId]
  );
  const row = owned.rows[0];
  if (!row) {
    return {
      ok: false,
      code: "forbidden",
      message: "Only the device owner can control this device."
    };
  }

  const commandId = newId();
  const pendingAck = realtimeHub.createPendingAck(commandId, row.device_uid, params.timeoutMs);
  const payload =
    params.command.operation === "clear"
      ? {
          type: "config_update",
          command_id: commandId,
          connectivity: {
            wifi: {
              op: "clear",
              reboot: params.command.reboot
            }
          },
          ts: nowIso()
        }
      : {
          type: "config_update",
          command_id: commandId,
          connectivity: {
            wifi: {
              op: "set",
              ssid: params.command.ssid,
              password: params.command.password,
              reboot: params.command.reboot
            }
          },
          ts: nowIso()
        };

  const sent = realtimeHub.sendToDevice(row.device_uid, payload);
  if (!sent) {
    realtimeHub.resolveAck(commandId, {
      ok: false,
      error: "device_disconnected"
    });
    return {
      ok: false,
      code: "device_offline",
      message: "Device is offline."
    };
  }

  try {
    const ack = await pendingAck;
    if (!ack.ok) {
      const errorCode =
        typeof ack.error === "string" && ack.error.trim().length > 0
          ? ack.error.trim()
          : "device_rejected";
      return {
        ok: false,
        code: errorCode,
        message: "Device rejected Wi-Fi update.",
        details: {
          command_id: commandId
        }
      };
    }
    return {
      ok: true,
      deviceUid: row.device_uid,
      latencyMs: ack.latencyMs
    };
  } catch (error) {
    if (error instanceof Error && error.message === "ack_timeout") {
      return {
        ok: false,
        code: "device_unreachable",
        message: "Timed out waiting for device acknowledgement.",
        details: {
          command_id: commandId,
          timeout_ms: params.timeoutMs
        }
      };
    }
    if (error instanceof Error && error.message === "device_disconnected") {
      return {
        ok: false,
        code: "device_offline",
        message: "Device disconnected before acknowledgement.",
        details: {
          command_id: commandId
        }
      };
    }
    return {
      ok: false,
      code: "device_ack_failed",
      message: "Device acknowledgement failed.",
      details: {
        command_id: commandId
      }
    };
  }
}

async function updateLastSeen(deviceId: string, ip: string): Promise<void> {
  await query(
    `UPDATE devices
     SET last_seen_at = $1, last_ip = $2, updated_at = $1
     WHERE id = $3`,
    [nowIso(), ip, deviceId]
  );
}

async function upsertRelaySnapshot(params: {
  deviceId: string;
  relays: boolean[];
  changedAt: string;
}): Promise<void> {
  if (params.relays.length === 0) {
    return;
  }

  const values: unknown[] = [];
  const tuples: string[] = [];

  for (let i = 0; i < params.relays.length; i += 1) {
    const argBase = values.length;
    values.push(newId(), params.deviceId, i, params.relays[i], params.changedAt, "device_state_report");
    tuples.push(`($${argBase + 1}, $${argBase + 2}, $${argBase + 3}, $${argBase + 4}, $${argBase + 5}, $${argBase + 6})`);
  }

  await query(
    `INSERT INTO relay_states (
       id, device_id, relay_index, is_on, last_changed_at, changed_by
     ) VALUES ${tuples.join(", ")}
     ON CONFLICT (device_id, relay_index)
     DO UPDATE SET
       is_on = EXCLUDED.is_on,
       last_changed_at = EXCLUDED.last_changed_at,
       changed_by = EXCLUDED.changed_by`,
    values
  );
}

async function applyRelayStateFromReport(params: {
  deviceId: string;
  deviceUid: string;
  ownerUserId: string | null;
  relays: boolean[];
}): Promise<{
  changedAt: string;
  changedRelays: Array<{ relay_index: number; from: boolean | null; to: boolean }>;
}> {
  const now = nowIso();
  const existing = await query<{ relay_index: number; is_on: boolean }>(
    `SELECT relay_index, is_on
     FROM relay_states
     WHERE device_id = $1`,
    [params.deviceId]
  );
  const previous = new Map<number, boolean>();
  for (const row of existing.rows) {
    previous.set(row.relay_index, row.is_on);
  }

  deviceStateCache.setAllRelayStates({
    deviceId: params.deviceId,
    deviceUid: params.deviceUid,
    ownerUserId: params.ownerUserId,
    relays: params.relays,
    updatedAt: now
  });

  const changedRelays: Array<{ relay_index: number; from: boolean | null; to: boolean }> = [];

  for (let i = 0; i < params.relays.length; i += 1) {
    const next = params.relays[i];
    const previousState = previous.has(i) ? previous.get(i) ?? null : null;

    if (previousState === null || previousState !== next) {
      changedRelays.push({
        relay_index: i,
        from: previousState,
        to: next
      });
    }
  }

  await upsertRelaySnapshot({
    deviceId: params.deviceId,
    relays: params.relays,
    changedAt: now
  });

  return {
    changedAt: now,
    changedRelays
  };
}

function handleDeviceSocket(
  socket: RawWebSocket,
  req: IncomingMessage,
  url: URL
): void {
  const uid = url.searchParams.get("uid")?.trim();
  const token = url.searchParams.get("token")?.trim();

  if (!uid || !token) {
    socket.close(1008, "missing_credentials");
    return;
  }

  let deviceUid: string | null = null;
  let deviceId: string | null = null;
  let ownerUserId: string | null = null;
  let deviceSessionId: string | null = null;
  let heartbeat: NodeJS.Timeout | undefined;
  let authenticated = false;
  let alive = true;
  let missedPongs = 0;
  let shutdownHandled = false;

  socket.on("pong", () => {
    alive = true;
    missedPongs = 0;
  });

  const shutdown = () => {
    if (shutdownHandled) {
      return;
    }
    shutdownHandled = true;

    if (heartbeat) {
      clearInterval(heartbeat);
      heartbeat = undefined;
    }

    if (deviceUid) {
      realtimeHub.unregisterDevice(deviceUid, deviceSessionId ?? undefined);
    }

    if (deviceId && deviceUid && !realtimeHub.getDevice(deviceUid)) {
      scheduleOfflineBroadcast(deviceUid, deviceId);
    }
  };

  socket.on("close", shutdown);
  socket.on("error", shutdown);

  (async () => {
    const auth = await query<DeviceAuthRow>(
      `SELECT id, device_uid, owner_user_id
       FROM devices
       WHERE device_uid = $1
         AND device_token_hash = $2
         AND is_active = TRUE
       LIMIT 1`,
      [uid, sha256(token)]
    );
    const row = auth.rows[0];
    if (!row) {
      socket.close(1008, "unauthorized");
      return;
    }

    deviceUid = row.device_uid;
    deviceId = row.id;
    ownerUserId = row.owner_user_id;
    authenticated = true;
    cancelPendingOffline(row.device_uid);

    const session = realtimeHub.registerDevice({
      deviceId: row.id,
      deviceUid: row.device_uid,
      sendJson: (payload) => sendJson(socket, payload),
      close: () => {
        if (socket.readyState === socket.OPEN) {
          socket.close(1000, "replaced_session");
        }
      }
    });
    deviceSessionId = session.id;

    await updateLastSeen(row.id, req.socket.remoteAddress ?? "");

    const ts = nowIso();
    void automationService
      .handleDeviceEvent({
        type: "device_online",
        device_uid: row.device_uid,
        ts
      })
      .catch(() => undefined);

    void smartHomeService.setDeviceAvailability(row.device_uid, true);

    broadcastDeviceEvent(ownerUserId, {
      type: "device_online",
      device_uid: row.device_uid,
      ts
    });

    heartbeat = setInterval(() => {
      if (!authenticated) {
        return;
      }

      if (!alive) {
        missedPongs += 1;
        if (missedPongs >= DEVICE_WS_HEARTBEAT_MISS_LIMIT) {
          socket.terminate();
          return;
        }
      } else {
        missedPongs = 0;
      }

      alive = false;
      socket.ping();
    }, DEVICE_WS_HEARTBEAT_INTERVAL_MS);
  })().catch(() => {
    socket.close(1011, "auth_error");
  });

  socket.on("message", (raw: unknown) => {
    if (!authenticated || !deviceUid || !deviceId) {
      return;
    }

    // Some embedded clients may not surface explicit pong frames reliably.
    // Treat any inbound device frame as proof of liveness.
    alive = true;
    missedPongs = 0;

    const parsed = parseMessage(raw);
    if (!parsed || typeof parsed !== "object") {
      return;
    }

    const message = parsed as Record<string, unknown>;
    const type = typeof message.type === "string" ? message.type : "";

    if (type === "state_report") {
      void (async () => {
        await updateLastSeen(deviceId, req.socket.remoteAddress ?? "");

        const relays = Array.isArray(message.relays)
          ? message.relays.filter((item): item is boolean => typeof item === "boolean")
          : [];
        if (relays.length === 0) {
          return;
        }

        const syncResult = await applyRelayStateFromReport({
          deviceId,
          deviceUid,
          ownerUserId,
          relays
        });

        const owner = await readOwnerUserId(deviceId);
        ownerUserId = owner;
        broadcastDeviceEvent(owner, {
          type: "device_state",
          device_uid: deviceUid,
          relays,
          telemetry: typeof message.telemetry === "object" ? message.telemetry : null,
          ts: syncResult.changedAt
        });

        try {
          await smartHomeService.syncRelaySnapshot({
            deviceId,
            deviceUid,
            ownerUserId,
            relays,
            updatedAt: syncResult.changedAt
          });
        } catch {
          // Do not fail state report when integration fan-out fails.
        }

        if (syncResult.changedRelays.length > 0) {
          await query(
            `INSERT INTO audit_log (
               id, device_id, user_id, action, details, source, created_at
             ) VALUES ($1, $2, NULL, $3, $4::jsonb, $5, $6)`,
            [
              newId(),
              deviceId,
              "device_state_report",
              JSON.stringify({
                changed_relays: syncResult.changedRelays,
                telemetry: typeof message.telemetry === "object" ? message.telemetry : null
              }),
              "system",
              syncResult.changedAt
            ]
          );
        }
      })().catch(() => undefined);

      return;
    }

    if (type === "ack") {
      const commandId = typeof message.command_id === "string" ? message.command_id : "";
      if (!commandId) {
        return;
      }

      const ok = message.ok !== false;
      const error = typeof message.error === "string" ? message.error : undefined;
      realtimeHub.resolveAck(commandId, {
        ok,
        error,
        payload: message
      });
      return;
    }

    if (type === "input_event" || type === "ota_status") {
      void updateLastSeen(deviceId, req.socket.remoteAddress ?? "").catch(() => undefined);

      if (type === "input_event") {
        void query(
          `INSERT INTO audit_log (
             id, device_id, user_id, action, details, source, created_at
           ) VALUES ($1, $2, NULL, $3, $4::jsonb, $5, $6)`,
          [
            newId(),
            deviceId,
            "input_event",
            JSON.stringify({
              ...message,
              device_uid: deviceUid
            }),
            "device",
            nowIso()
          ]
        ).catch(() => undefined);

        void automationService
          .handleInputEvent({
            ...message,
            device_uid: deviceUid
          })
          .catch(() => undefined);
      } else {
        void query(
          `INSERT INTO audit_log (
             id, device_id, user_id, action, details, source, created_at
           ) VALUES ($1, $2, NULL, $3, $4::jsonb, $5, $6)`,
          [
            newId(),
            deviceId,
            "ota_status_report",
            JSON.stringify({
              ...message,
              device_uid: deviceUid
            }),
            "device",
            nowIso()
          ]
        ).catch(() => undefined);
      }

      void readOwnerUserId(deviceId)
        .then((owner) => {
          ownerUserId = owner;
          broadcastDeviceEvent(owner, {
            ...message,
            device_uid: deviceUid
          });
        })
        .catch(() => undefined);
    }
  });
}

function handleClientSocket(
  socket: RawWebSocket,
  server: FastifyInstance
): void {
  let clientSessionId: string | null = null;
  let authedUserId: string | null = null;

  socket.on("close", () => {
    if (clientSessionId) {
      realtimeHub.unregisterClient(clientSessionId);
    }
  });

  socket.on("message", (raw: unknown) => {
    const parsed = parseMessage(raw);
    if (!parsed || typeof parsed !== "object") {
      return;
    }

    const message = parsed as Record<string, unknown>;
    const type = typeof message.type === "string" ? message.type : "";

    if (type === "auth") {
      const accessToken = typeof message.access_token === "string" ? message.access_token : "";
      if (!accessToken) {
        sendJson(socket, {
          type: "auth_error",
          code: "missing_token"
        });
        return;
      }

      void (async () => {
        try {
          const payload = await server.jwt.verify<{
            sub: string;
            role: string;
            email: string;
          }>(accessToken);

          authedUserId = payload.sub;
          const clientSession = realtimeHub.registerClient({
            userId: payload.sub,
            role: payload.role,
            sendJson: (out) => sendJson(socket, out),
            close: () => {
              if (socket.readyState === socket.OPEN) {
                socket.close(1000, "session_closed");
              }
            }
          });
          clientSessionId = clientSession.id;

          sendJson(socket, {
            type: "auth_ok",
            user_id: payload.sub
          });

          const ownedUids = await listOwnedDeviceUids(payload.sub);
          const onlineSet = new Set([
            ...realtimeHub.listOnlineDeviceUids(),
            ...pendingOfflineTimers.keys()
          ]);
          for (const uid of ownedUids) {
            if (!onlineSet.has(uid)) {
              continue;
            }
            sendJson(socket, {
              type: "device_online",
              device_uid: uid,
              ts: nowIso()
            });
          }
        } catch {
          sendJson(socket, {
            type: "auth_error",
            code: "invalid_token"
          });
        }
      })();
      return;
    }

    if (type !== "cmd") {
      return;
    }

    if (!authedUserId) {
      sendJson(socket, {
        type: "cmd_ack",
        ok: false,
        code: "unauthorized",
        request_id: message.request_id ?? null
      });
      return;
    }

    const requestId = typeof message.request_id === "string" ? message.request_id : newId();
    const deviceId = typeof message.device_id === "string" ? message.device_id : "";
    const scope = typeof message.scope === "string" ? message.scope : "single";
    const action = typeof message.action === "string" ? message.action : "";
    const timeoutMs =
      typeof message.timeout_ms === "number" &&
      Number.isInteger(message.timeout_ms) &&
      message.timeout_ms >= 1000 &&
      message.timeout_ms <= 30000
        ? message.timeout_ms
        : undefined;

    if (!deviceId) {
      sendJson(socket, {
        type: "cmd_ack",
        ok: false,
        code: "validation_error",
        message: "device_id is required.",
        request_id: requestId
      });
      return;
    }

    let command: ClientCommand;
    if (scope === "wifi") {
      const wifiPayload = asRecord(message.wifi);
      const opRaw =
        (typeof wifiPayload?.op === "string" ? wifiPayload.op : null) ??
        (typeof message.action === "string" ? message.action : null) ??
        "";
      const opNormalized = opRaw.trim().toLowerCase();
      const clearFlag =
        wifiPayload?.clear === true ||
        wifiPayload?.remove === true ||
        wifiPayload?.forget === true;
      const ssidRaw =
        (typeof wifiPayload?.ssid === "string" ? wifiPayload.ssid : null) ??
        (typeof message.ssid === "string" ? message.ssid : null) ??
        "";
      const passwordRaw =
        (typeof wifiPayload?.password === "string" ? wifiPayload.password : null) ??
        (typeof message.password === "string" ? message.password : null) ??
        "";
      const reboot =
        typeof wifiPayload?.reboot === "boolean"
          ? wifiPayload.reboot
          : true;

      const opIsSet =
        opNormalized === "set" ||
        opNormalized === "provision" ||
        opNormalized === "update";
      const opIsClear =
        opNormalized === "clear" ||
        opNormalized === "remove" ||
        opNormalized === "forget" ||
        opNormalized === "delete";
      const hasSsid = ssidRaw.trim().length > 0;
      const clearRequested = clearFlag || opIsClear;
      const setRequested = opIsSet || hasSsid;

      if (clearRequested && setRequested) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "Wi-Fi command cannot set and clear credentials together.",
          request_id: requestId
        });
        return;
      }

      if (!clearRequested && !setRequested) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "Wi-Fi command requires op=set|clear or wifi.ssid.",
          request_id: requestId
        });
        return;
      }

      if (clearRequested) {
        command = {
          scope: "wifi",
          operation: "clear",
          reboot
        };
      } else {
        const ssid = ssidRaw.trim();
        const password = passwordRaw;
        if (ssid.length === 0 || ssid.length > WIFI_SSID_MAX_LEN) {
          sendJson(socket, {
            type: "cmd_ack",
            ok: false,
            code: "validation_error",
            message: `wifi.ssid must be 1-${WIFI_SSID_MAX_LEN} chars.`,
            request_id: requestId
          });
          return;
        }
        if (password.length > WIFI_PASSWORD_MAX_LEN) {
          sendJson(socket, {
            type: "cmd_ack",
            ok: false,
            code: "validation_error",
            message: `wifi.password must be <= ${WIFI_PASSWORD_MAX_LEN} chars.`,
            request_id: requestId
          });
          return;
        }
        command = {
          scope: "wifi",
          operation: "set",
          ssid,
          password,
          reboot
        };
      }
    } else if (scope === "all") {
      if (action !== "on" && action !== "off") {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "action must be on or off for all scope.",
          request_id: requestId
        });
        return;
      }
      command = {
        scope: "all",
        action
      };
    } else {
      const relayIndex =
        typeof message.relay_index === "number"
          ? message.relay_index
          : Number.NaN;
      if (!Number.isInteger(relayIndex)) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "relay_index must be an integer.",
          request_id: requestId
        });
        return;
      }
      if (action !== "on" && action !== "off" && action !== "toggle") {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "action must be on, off, or toggle.",
          request_id: requestId
        });
        return;
      }
      command = {
        scope: "single",
        action,
        relayIndex
      };
    }

    const actorUserId = authedUserId;
    const accepted = enqueueDeviceCommand(deviceId, async () => {
      try {
        const permitted = await isDeviceOwner(actorUserId, deviceId);
        if (!permitted) {
          sendJson(socket, {
            type: "cmd_ack",
            ok: false,
            code: "forbidden",
            request_id: requestId
          });
          return;
        }

        if (command.scope === "wifi") {
          const wifiCommandResult = await sendWifiConfigCommand({
            userId: actorUserId,
            deviceId,
            command,
            timeoutMs: timeoutMs ?? WIFI_CONFIG_COMMAND_TIMEOUT_MS
          });
          if (!wifiCommandResult.ok) {
            sendJson(socket, {
              type: "cmd_ack",
              ok: false,
              code: wifiCommandResult.code,
              message: wifiCommandResult.message,
              details: wifiCommandResult.details ?? null,
              request_id: requestId
            });
            return;
          }
          sendJson(socket, {
            type: "cmd_ack",
            ok: true,
            request_id: requestId,
            result: {
              device_id: deviceId,
              device_uid: wifiCommandResult.deviceUid,
              scope: "wifi",
              operation: command.operation,
              reboot: command.reboot,
              latency_ms: wifiCommandResult.latencyMs
            }
          });
          return;
        }

        if (command.scope === "all") {
          const result = await relayService.setAllRelays({
            deviceId,
            action: command.action,
            timeoutMs,
            source: {
              actorUserId,
              source: "ws_client"
            }
          });

          sendJson(socket, {
            type: "cmd_ack",
            ok: true,
            request_id: requestId,
            result
          });
          return;
        }

        const result = await relayService.setRelay({
          deviceId,
          relayIndex: command.relayIndex,
          action: command.action,
          timeoutMs,
          source: {
            actorUserId,
            source: "ws_client"
          }
        });

        sendJson(socket, {
          type: "cmd_ack",
          ok: true,
          request_id: requestId,
          result
        });
      } catch (error) {
        if (error instanceof RelayServiceError) {
          sendJson(socket, {
            type: "cmd_ack",
            ok: false,
            code: error.code,
            message: error.message,
            details: error.details ?? null,
            request_id: requestId
          });
          return;
        }

        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "command_failed",
          message: "Command failed.",
          request_id: requestId
        });
      }
    });

    if (!accepted) {
      sendJson(socket, {
        type: "cmd_ack",
        ok: false,
        code: "queue_overloaded",
        message: "Too many queued commands for this device. Retry shortly.",
        request_id: requestId
      });
    }
  });
}

export function registerRealtimeGateway(server: FastifyInstance): void {
  const wsServer = new wsPackage.WebSocketServer({
    noServer: true,
    maxPayload: 16_384
  });

  server.server.on("upgrade", (req, socket, head) => {
    if (env.NODE_ENV === "production" && env.ENFORCE_HTTPS) {
      const forwardedProto = req.headers["x-forwarded-proto"];
      const forwardedProtoValue = Array.isArray(forwardedProto)
        ? forwardedProto[0]
        : forwardedProto;
      const firstForwardedProto = (forwardedProtoValue ?? "")
        .split(",")[0]
        ?.trim()
        .toLowerCase();

      const isEncryptedSocket = Boolean(
        (req.socket as { encrypted?: boolean } | undefined)?.encrypted
      );
      const isSecureUpgrade =
        firstForwardedProto === "https" || firstForwardedProto === "wss" || isEncryptedSocket;
      if (!isSecureUpgrade) {
        socket.destroy();
        return;
      }
    }

    const host = req.headers.host ?? "localhost";
    const url = new URL(req.url ?? "/", `http://${host}`);
    const pathname = url.pathname;
    if (pathname !== "/ws/device" && pathname !== "/ws/client") {
      socket.destroy();
      return;
    }

    wsServer.handleUpgrade(req, socket, head, (wsSocket) => {
      wsServer.emit("connection", wsSocket, req, url);
    });
  });

  wsServer.on("connection", (socket: unknown, req: unknown, url: unknown) => {
    const wsSocket = socket as RawWebSocket;
    const request = req as IncomingMessage;
    const parsedUrl = (url as URL | undefined) ?? new URL("http://localhost/");

    if (parsedUrl.pathname === "/ws/device") {
      handleDeviceSocket(wsSocket, request, parsedUrl);
      return;
    }

    if (parsedUrl.pathname === "/ws/client") {
      handleClientSocket(wsSocket, server);
      return;
    }

    wsSocket.close(1008, "unsupported_path");
  });

  server.addHook("onClose", async () => {
    for (const client of wsServer.clients) {
      client.terminate();
    }

    await new Promise<void>((resolve) => {
      wsServer.close(() => resolve());
    });
  });
}
