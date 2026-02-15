import assert from "node:assert/strict";
import test from "node:test";
import { AddressInfo } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import WebSocket from "ws";
import { env } from "../../src/config/env";
import { closeDb, query } from "../../src/db/connection";
import { runMigrations } from "../../src/db/migrate";
import { buildApp } from "../../src/app";
import { canonicalManifestPayload, signManifestPayload } from "../../src/services/ota-manifest-signer";
import { newId, randomToken, sha256 } from "../../src/utils/crypto";
import { nowIso } from "../../src/utils/time";

type JsonObject = Record<string, unknown>;

type HttpResult = {
  status: number;
  body: JsonObject;
  headers: Headers;
};

type ConnectedDevice = {
  ws: WebSocket;
  relays: boolean[];
  receivedConfigUpdates: JsonObject[];
  commandCount: number;
  waitForMessages: (predicate: (msg: JsonObject) => boolean, timeoutMs?: number) => Promise<JsonObject>;
};

type ConnectedClient = {
  ws: WebSocket;
  waitForMessages: (predicate: (msg: JsonObject) => boolean, timeoutMs?: number) => Promise<JsonObject>;
};

async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function waitUntil(
  check: () => Promise<boolean>,
  timeoutMs: number,
  pollMs = 300
): Promise<void> {
  const started = Date.now();
  while (Date.now() - started <= timeoutMs) {
    if (await check()) {
      return;
    }
    await sleep(pollMs);
  }
  throw new Error(`Timed out after ${timeoutMs}ms.`);
}

async function requestJson(
  url: string,
  init?: RequestInit
): Promise<HttpResult> {
  const response = await fetch(url, init);
  const text = await response.text();
  const body = text.length > 0 ? (JSON.parse(text) as JsonObject) : {};
  return {
    status: response.status,
    body,
    headers: response.headers
  };
}

async function connectDeviceWs(
  wsBase: string,
  deviceUid: string,
  deviceToken: string,
  options?: {
    ackMode?: "normal" | "disconnect_on_command" | "drop_ack_keep_state" | "drop_ack_no_state" | "ota_reject";
  }
): Promise<ConnectedDevice> {
  const relays = [false, false, false];
  const receivedConfigUpdates: JsonObject[] = [];
  const inboundMessages: JsonObject[] = [];
  let commandCount = 0;
  const ackMode = options?.ackMode ?? "normal";

  const ws = new WebSocket(
    `${wsBase}/ws/device?uid=${encodeURIComponent(deviceUid)}&token=${encodeURIComponent(deviceToken)}`
  );

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Device websocket connect timeout."));
    }, 8_000);

    ws.once("open", () => {
      clearTimeout(timeout);
      resolve();
    });
    ws.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });

  ws.on("message", (raw) => {
    const parsed = JSON.parse(raw.toString("utf8")) as JsonObject;
    inboundMessages.push(parsed);

    if (parsed.type === "set_all_relays") {
      commandCount += 1;
      if (ackMode === "disconnect_on_command") {
        ws.close(1011, "intentional_disconnect_before_ack");
        return;
      }
      const action = parsed.action;
      if (action === "on") {
        relays.fill(true);
      } else if (action === "off") {
        relays.fill(false);
      }

      if (ackMode !== "drop_ack_keep_state" && ackMode !== "drop_ack_no_state") {
        ws.send(
          JSON.stringify({
            type: "ack",
            command_id: parsed.command_id,
            ok: true,
            ts: nowIso()
          })
        );
      }

      if (ackMode !== "drop_ack_no_state") {
        ws.send(
          JSON.stringify({
            type: "state_report",
            relays,
            ts: nowIso()
          })
        );
      }
      return;
    }

    if (parsed.type === "set_relay") {
      commandCount += 1;
      if (ackMode === "disconnect_on_command") {
        ws.close(1011, "intentional_disconnect_before_ack");
        return;
      }
      const relayIndex = Number(parsed.relay_index);
      const action = parsed.action;
      if (Number.isInteger(relayIndex) && relayIndex >= 0 && relayIndex < relays.length) {
        if (action === "on") {
          relays[relayIndex] = true;
        } else if (action === "off") {
          relays[relayIndex] = false;
        } else if (action === "toggle") {
          relays[relayIndex] = !relays[relayIndex];
        }
      }

      if (ackMode !== "drop_ack_keep_state" && ackMode !== "drop_ack_no_state") {
        ws.send(
          JSON.stringify({
            type: "ack",
            command_id: parsed.command_id,
            ok: true,
            ts: nowIso()
          })
        );
      }

      if (ackMode !== "drop_ack_no_state") {
        ws.send(
          JSON.stringify({
            type: "state_report",
            relays,
            ts: nowIso()
          })
        );
      }
      return;
    }

    if (parsed.type === "config_update") {
      receivedConfigUpdates.push(parsed);
      if (ackMode === "disconnect_on_command") {
        ws.close(1011, "intentional_disconnect_before_ack");
        return;
      }
      if (ackMode !== "drop_ack_keep_state" && ackMode !== "drop_ack_no_state") {
        const commandId = typeof parsed.command_id === "string" ? parsed.command_id : "";
        if (commandId.length > 0) {
          ws.send(
            JSON.stringify({
              type: "ack",
              command_id: commandId,
              ok: true,
              ts: nowIso()
            })
          );
        }
      }
      return;
    }

    if (parsed.type === "device_control") {
      if (ackMode === "disconnect_on_command") {
        ws.close(1011, "intentional_disconnect_before_ack");
        return;
      }
      if (ackMode !== "drop_ack_keep_state" && ackMode !== "drop_ack_no_state") {
        ws.send(
          JSON.stringify({
            type: "ack",
            command_id: parsed.command_id,
            ok: true,
            ts: nowIso()
          })
        );
      }
    }

    if (parsed.type === "ota_control") {
      commandCount += 1;
      if (ackMode === "disconnect_on_command") {
        ws.close(1011, "intentional_disconnect_before_ack");
        return;
      }
      if (ackMode === "drop_ack_keep_state" || ackMode === "drop_ack_no_state") {
        return;
      }
      if (ackMode === "ota_reject") {
        ws.send(
          JSON.stringify({
            type: "ack",
            command_id: parsed.command_id,
            ok: false,
            error: "ota_rejected_for_test",
            ts: nowIso()
          })
        );
        return;
      }
      ws.send(
        JSON.stringify({
          type: "ack",
          command_id: parsed.command_id,
          ok: true,
          ts: nowIso()
        })
      );
    }
  });

  ws.send(
    JSON.stringify({
      type: "state_report",
      relays,
      telemetry: {
        heap: 40_000,
        rssi: -50,
        uptime: 1,
        firmware: "integration-test-fw"
      },
      ts: nowIso()
    })
  );

  return {
    ws,
    relays,
    receivedConfigUpdates,
    get commandCount() {
      return commandCount;
    },
    waitForMessages: async (
      predicate: (msg: JsonObject) => boolean,
      timeoutMs = 10_000
    ) => {
      const started = Date.now();
      while (Date.now() - started <= timeoutMs) {
        const match = inboundMessages.find(predicate);
        if (match) {
          return match;
        }
        await sleep(150);
      }
      throw new Error("Timed out waiting for websocket message.");
    }
  };
}

async function connectClientWs(
  wsBase: string,
  accessToken: string
): Promise<ConnectedClient> {
  const inboundMessages: JsonObject[] = [];
  const ws = new WebSocket(`${wsBase}/ws/client`);

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Client websocket connect timeout."));
    }, 8_000);

    ws.once("open", () => {
      clearTimeout(timeout);
      resolve();
    });
    ws.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });

  ws.on("message", (raw) => {
    const parsed = JSON.parse(raw.toString("utf8")) as JsonObject;
    inboundMessages.push(parsed);
  });

  ws.send(
    JSON.stringify({
      type: "auth",
      access_token: accessToken
    })
  );

  const started = Date.now();
  while (Date.now() - started <= 10_000) {
    const authOk = inboundMessages.find((msg) => msg.type === "auth_ok");
    if (authOk) {
      return {
        ws,
        waitForMessages: async (
          predicate: (msg: JsonObject) => boolean,
          timeoutMs = 10_000
        ) => {
          const innerStarted = Date.now();
          while (Date.now() - innerStarted <= timeoutMs) {
            const match = inboundMessages.find(predicate);
            if (match) {
              return match;
            }
            await sleep(100);
          }
          throw new Error("Timed out waiting for websocket message.");
        }
      };
    }
    await sleep(100);
  }

  throw new Error("Client websocket auth timeout.");
}

test("integration: schedule + automation + config sync + ota flow", async () => {
  await runMigrations();
  const app = buildApp();

  await app.listen({
    host: "127.0.0.1",
    port: 0
  });

  const address = app.server.address() as AddressInfo;
  const httpBase = `http://127.0.0.1:${address.port}`;
  const wsBase = `ws://127.0.0.1:${address.port}`;

  let deviceWs: ConnectedDevice | null = null;
  let clientWs: ConnectedClient | null = null;
  let timeoutDeviceWs: ConnectedDevice | null = null;
  let fallbackAckDeviceWs: ConnectedDevice | null = null;
  let rejectOtaDeviceWs: ConnectedDevice | null = null;

  try {
    const provisioned = await requestJson(`${httpBase}/api/v1/provision/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        provision_key: env.DEVICE_PROVISION_KEY,
        chip_id: `it-chip-${newId()}`,
        model: "hexa-mini-switch-v1",
        firmware_version: "0.0.1"
      })
    });
    assert.equal(provisioned.status, 200);

    const deviceId = String(provisioned.body.device_id);
    const deviceUid = String(provisioned.body.device_uid);
    const deviceToken = String(provisioned.body.device_token);
    const claimCode = String(provisioned.body.claim_code);

    const register = await requestJson(`${httpBase}/api/v1/auth/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        email: `integration-${newId()}@example.com`,
        password: "integration-pass-123",
        name: "Integration User",
        claim_code: claimCode
      })
    });
    assert.equal(register.status, 201);

    const accessToken = String(register.body.access_token);
    assert.ok(accessToken.length > 20);

    deviceWs = await connectDeviceWs(wsBase, deviceUid, deviceToken);
    clientWs = await connectClientWs(wsBase, accessToken);

    await waitUntil(async () => {
      const row = await query<{ last_seen_at: Date | null }>(
        "SELECT last_seen_at FROM devices WHERE id = $1 LIMIT 1",
        [deviceId]
      );
      return Boolean(row.rows[0]?.last_seen_at);
    }, 7_000);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-single-on",
        device_id: deviceId,
        scope: "single",
        relay_index: 1,
        action: "on"
      })
    );

    const singleCmdAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-single-on"
    );
    assert.equal(singleCmdAck.ok, true);

    await waitUntil(async () => {
      const relay = await query<{ is_on: boolean }>(
        `SELECT is_on
         FROM relay_states
         WHERE device_id = $1
           AND relay_index = 1
         LIMIT 1`,
        [deviceId]
      );
      return relay.rows[0]?.is_on === true;
    }, 7_000);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-all-off",
        device_id: deviceId,
        scope: "all",
        action: "off"
      })
    );

    const allOffAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-all-off"
    );
    assert.equal(allOffAck.ok, true);

    await waitUntil(async () => {
      const relays = await query<{ relay_index: number; is_on: boolean }>(
        `SELECT relay_index, is_on
         FROM relay_states
         WHERE device_id = $1
         ORDER BY relay_index ASC`,
        [deviceId]
      );
      return relays.rows.length === 3 && relays.rows.every((row) => row.is_on === false);
    }, 10_000);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-all-on",
        device_id: deviceId,
        scope: "all",
        action: "on"
      })
    );

    const allOnAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-all-on"
    );
    assert.equal(allOnAck.ok, true);

    await waitUntil(async () => {
      const relays = await query<{ relay_index: number; is_on: boolean }>(
        `SELECT relay_index, is_on
         FROM relay_states
         WHERE device_id = $1
         ORDER BY relay_index ASC`,
        [deviceId]
      );
      return relays.rows.length === 3 && relays.rows.every((row) => row.is_on === true);
    }, 10_000);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-device-reboot",
        device_id: deviceId,
        scope: "device",
        operation: "reboot"
      })
    );

    const rebootAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-device-reboot"
    );
    assert.equal(rebootAck.ok, true);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-device-factory-reset",
        device_id: deviceId,
        scope: "device",
        operation: "factory_reset"
      })
    );

    const factoryResetAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-device-factory-reset"
    );
    assert.equal(factoryResetAck.ok, true);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-ota-check",
        device_id: deviceId,
        scope: "ota",
        operation: "check"
      })
    );

    const otaCheckCmdAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-ota-check"
    );
    assert.equal(otaCheckCmdAck.ok, true);
    assert.equal((otaCheckCmdAck.result as JsonObject).scope, "ota");
    assert.equal((otaCheckCmdAck.result as JsonObject).operation, "check");

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-ota-invalid-operation",
        device_id: deviceId,
        scope: "ota",
        operation: "ship_it"
      })
    );

    const otaInvalidOperationAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-ota-invalid-operation"
    );
    assert.equal(otaInvalidOperationAck.ok, false);
    assert.equal(otaInvalidOperationAck.code, "validation_error");

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-ota-invalid-channel",
        device_id: deviceId,
        scope: "ota",
        operation: "install",
        channel: "gold"
      })
    );

    const otaInvalidChannelAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-ota-invalid-channel"
    );
    assert.equal(otaInvalidChannelAck.ok, false);
    assert.equal(otaInvalidChannelAck.code, "validation_error");

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-button-mode-follow",
        device_id: deviceId,
        scope: "button_mode",
        button_index: 1,
        mode: "rocker_switch_follow"
      })
    );
    const buttonModeAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-button-mode-follow"
    );
    assert.equal(buttonModeAck.ok, true);
    assert.equal((buttonModeAck.result as JsonObject).scope, "button_mode");

    await waitUntil(async () => {
      const configUpdate = deviceWs?.receivedConfigUpdates.find((msg) => {
        const ioConfig = msg.io_config as JsonObject[] | undefined;
        return Array.isArray(ioConfig) && ioConfig.some((row) => row.input_index === 1);
      });
      return Boolean(configUpdate);
    }, 7_000);

    const inputConfigAfterMode = await query<{ input_config: JsonObject[] }>(
      `SELECT input_config
       FROM devices
       WHERE id = $1
       LIMIT 1`,
      [deviceId]
    );
    assert.equal(Array.isArray(inputConfigAfterMode.rows[0]?.input_config), true);
    const rowAfterMode = inputConfigAfterMode.rows[0]?.input_config.find((row) => row.input_index === 1);
    assert.equal(rowAfterMode?.input_type, "rocker_switch");
    assert.equal(rowAfterMode?.rocker_mode, "follow_position");

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-button-link-off",
        device_id: deviceId,
        scope: "button_link",
        button_index: 1,
        linked: false
      })
    );
    const buttonLinkAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-button-link-off"
    );
    assert.equal(buttonLinkAck.ok, true);
    assert.equal((buttonLinkAck.result as JsonObject).scope, "button_link");

    const inputConfigAfterLink = await query<{ input_config: JsonObject[] }>(
      `SELECT input_config
       FROM devices
       WHERE id = $1
       LIMIT 1`,
      [deviceId]
    );
    const rowAfterLink = inputConfigAfterLink.rows[0]?.input_config.find((row) => row.input_index === 1);
    assert.equal(rowAfterLink?.linked, false);
    assert.equal(rowAfterLink?.target_relay_index, null);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-ha-config-on",
        device_id: deviceId,
        scope: "ha_config",
        show_config: true
      })
    );
    const haConfigAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-ha-config-on"
    );
    assert.equal(haConfigAck.ok, true);
    assert.equal((haConfigAck.result as JsonObject).scope, "ha_config");
    assert.equal((haConfigAck.result as JsonObject).show_config, true);

    const configAfterHaToggle = await query<{ config: JsonObject }>(
      `SELECT config
       FROM devices
       WHERE id = $1
       LIMIT 1`,
      [deviceId]
    );
    const connectivityAfterHaToggle = (configAfterHaToggle.rows[0]?.config?.connectivity ?? {}) as JsonObject;
    const mqttAfterHaToggle = (connectivityAfterHaToggle.mqtt ?? {}) as JsonObject;
    assert.equal(mqttAfterHaToggle.show_config, true);

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-connectivity-local",
        device_id: deviceId,
        scope: "connectivity_mode",
        mode: "local_mqtt"
      })
    );
    const connectivityModeAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-connectivity-local"
    );
    assert.equal(connectivityModeAck.ok, true);
    assert.equal((connectivityModeAck.result as JsonObject).scope, "connectivity_mode");
    assert.equal((connectivityModeAck.result as JsonObject).mode, "local_mqtt");

    const configAfterModeSwitch = await query<{ config: JsonObject }>(
      `SELECT config
       FROM devices
       WHERE id = $1
       LIMIT 1`,
      [deviceId]
    );
    const connectivityAfterModeSwitch = (configAfterModeSwitch.rows[0]?.config?.connectivity ?? {}) as JsonObject;
    assert.equal(connectivityAfterModeSwitch.mode, "local_mqtt");

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-button-mode-invalid",
        device_id: deviceId,
        scope: "button_mode",
        button_index: 0,
        mode: "invalid_mode_name"
      })
    );
    const buttonModeInvalidAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-button-mode-invalid"
    );
    assert.equal(buttonModeInvalidAck.ok, false);
    assert.equal(buttonModeInvalidAck.code, "validation_error");

    const scheduleOnAt = new Date(Date.now() + 3_000).toISOString();
    const createdOn = await requestJson(`${httpBase}/api/v1/schedules`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        device_id: deviceId,
        target_scope: "all",
        schedule_type: "once",
        execute_at: scheduleOnAt,
        timezone: "UTC",
        action: "on"
      })
    });
    assert.equal(createdOn.status, 201);
    const scheduleOnId = String(createdOn.body.id);

    await waitUntil(async () => {
      const relays = await query<{ relay_index: number; is_on: boolean }>(
        `SELECT relay_index, is_on
         FROM relay_states
         WHERE device_id = $1
         ORDER BY relay_index ASC`,
        [deviceId]
      );
      return relays.rows.length === 3 && relays.rows.every((row) => row.is_on === true);
    }, 22_000);

    const scheduleOffAt = new Date(Date.now() + 3_000).toISOString();
    const createdOff = await requestJson(`${httpBase}/api/v1/schedules`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        device_id: deviceId,
        target_scope: "all",
        schedule_type: "once",
        execute_at: scheduleOffAt,
        timezone: "UTC",
        action: "off"
      })
    });
    assert.equal(createdOff.status, 201);
    const scheduleOffId = String(createdOff.body.id);

    await waitUntil(async () => {
      const relays = await query<{ relay_index: number; is_on: boolean }>(
        `SELECT relay_index, is_on
         FROM relay_states
         WHERE device_id = $1
         ORDER BY relay_index ASC`,
        [deviceId]
      );
      return relays.rows.length === 3 && relays.rows.every((row) => row.is_on === false);
    }, 22_000);

    const scheduleAudit = await query<{ schedule_id: string; source: string }>(
      `SELECT schedule_id, source
       FROM audit_log
       WHERE schedule_id IN ($1, $2)
       ORDER BY created_at ASC`,
      [scheduleOnId, scheduleOffId]
    );
    assert.ok(
      scheduleAudit.rows.some((row) => row.schedule_id === scheduleOnId && row.source === "schedule")
    );
    assert.ok(
      scheduleAudit.rows.some((row) => row.schedule_id === scheduleOffId && row.source === "schedule")
    );

    const automation = await requestJson(`${httpBase}/api/v1/automations`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        device_id: deviceId,
        name: "Integration hold 10s all off",
        trigger_type: "button_hold",
        trigger_config: {
          input_index: 0,
          hold_seconds: 10
        },
        action_type: "set_all_relays",
        action_config: {
          action: "off"
        },
        cooldown_seconds: 10,
        is_enabled: true
      })
    });
    assert.equal(automation.status, 201);
    const automationId = String(automation.body.id);

    const turnOnAll = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/relays/all`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({ action: "on" })
    });
    assert.equal(turnOnAll.status, 200);

    const eventTs = nowIso();
    const holdEvent = JSON.stringify({
      type: "input_event",
      input_index: 0,
      input_type: "push_button",
      event: "hold",
      duration_ms: 10_050,
      ts: eventTs
    });

    deviceWs.ws.send(holdEvent);
    deviceWs.ws.send(holdEvent);

    await waitUntil(async () => {
      const relays = await query<{ is_on: boolean }>(
        `SELECT is_on
         FROM relay_states
         WHERE device_id = $1`,
        [deviceId]
      );
      return relays.rows.length === 3 && relays.rows.every((row) => row.is_on === false);
    }, 10_000);

    const automationAudit = await query<{ total: string }>(
      `SELECT COUNT(*)::text AS total
       FROM audit_log
       WHERE automation_id = $1
         AND action = 'set_all_relays'`,
      [automationId]
    );
    assert.equal(Number(automationAudit.rows[0]?.total ?? "0"), 1);

    const invalidConfig = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/io-config`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        input_config: [
          {
            input_index: 0,
            input_type: "rocker_switch",
            linked: true,
            target_relay_index: 0,
            rocker_mode: "follow_position",
            invert_input: false,
            hold_seconds: 10
          },
          {
            input_index: 1,
            input_type: "push_button",
            linked: true,
            target_relay_index: 1,
            rocker_mode: null,
            invert_input: false,
            hold_seconds: 8
          },
          {
            input_index: 2,
            input_type: "push_button",
            linked: false,
            target_relay_index: null,
            rocker_mode: null,
            invert_input: false,
            hold_seconds: 8
          }
        ]
      })
    });
    assert.equal(invalidConfig.status, 400);

    const ioConfig = [
      {
        input_index: 0,
        input_type: "push_button",
        linked: true,
        target_relay_index: 0,
        rocker_mode: null,
        invert_input: false,
        hold_seconds: 10
      },
      {
        input_index: 1,
        input_type: "rocker_switch",
        linked: true,
        target_relay_index: 1,
        rocker_mode: "follow_position",
        invert_input: false,
        hold_seconds: null
      },
      {
        input_index: 2,
        input_type: "push_button",
        linked: false,
        target_relay_index: null,
        rocker_mode: null,
        invert_input: true,
        hold_seconds: 8
      }
    ];

    const patchedIo = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/io-config`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        input_config: ioConfig
      })
    });
    assert.equal(patchedIo.status, 200);

    await waitUntil(async () => {
      return deviceWs?.receivedConfigUpdates.some((msg) => Array.isArray(msg.io_config)) ?? false;
    }, 7_000);

    const patchedRestore = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/power-restore-mode`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        power_restore_mode: "all_off"
      })
    });
    assert.equal(patchedRestore.status, 200);

    const idempotencyKey = `it-${newId()}`;
    const idempotentFirst = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/power-restore-mode`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`,
        "idempotency-key": idempotencyKey
      },
      body: JSON.stringify({
        power_restore_mode: "all_off"
      })
    });
    assert.equal(idempotentFirst.status, 200);

    const idempotentSecond = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/power-restore-mode`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`,
        "idempotency-key": idempotencyKey
      },
      body: JSON.stringify({
        power_restore_mode: "all_off"
      })
    });
    assert.equal(idempotentSecond.status, 200);
    assert.equal(idempotentSecond.headers.get("idempotency-replayed"), "true");
    assert.deepEqual(idempotentSecond.body, idempotentFirst.body);

    await waitUntil(async () => {
      return (
        deviceWs?.receivedConfigUpdates.some(
          (msg) => msg.power_restore_mode === "all_off"
        ) ?? false
      );
    }, 7_000);

    const getDevice = await requestJson(`${httpBase}/api/v1/devices/${deviceId}`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(getDevice.status, 200);
    assert.equal(getDevice.body.relay_count, 3);
    assert.equal(getDevice.body.button_count, 3);
    assert.deepEqual(getDevice.body.input_config, ioConfig);
    assert.equal(getDevice.body.power_restore_mode, "all_off");

    const initialPreferences = await requestJson(`${httpBase}/api/v1/preferences`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(initialPreferences.status, 200);

    const updatedPreferences = await requestJson(`${httpBase}/api/v1/preferences`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        merge: true,
        dashboard_layout: {
          pinned_sections: ["overview", "devices", "ota"]
        },
        dashboard_settings: {
          auto_refresh_seconds: 30
        },
        device_view_state: {
          [deviceUid]: {
            last_selected_tab: "relays"
          }
        }
      })
    });
    assert.equal(updatedPreferences.status, 200);
    assert.equal(updatedPreferences.body.dashboard_settings.auto_refresh_seconds, 30);

    const upsertCapability = await requestJson(
      `${httpBase}/api/v1/devices/${deviceId}/capabilities/ir_rx`,
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${accessToken}`
        },
        body: JSON.stringify({
          capability_kind: "infrared",
          config: {
            mode: "learning"
          },
          metadata: {
            note: "integration"
          },
          is_enabled: true
        })
      }
    );
    assert.equal(upsertCapability.status, 200);
    assert.equal(upsertCapability.body.capability_key, "ir_rx");

    const capabilities = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/capabilities`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(capabilities.status, 200);
    assert.equal(Array.isArray(capabilities.body.capabilities), true);
    assert.equal(
      (capabilities.body.capabilities as JsonObject[]).some((item) => item.capability_key === "ir_rx"),
      true
    );

    const createdIrCode = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/ir-codes`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        code_name: `TV_POWER_${Date.now()}`,
        protocol: "nec",
        frequency_hz: 38000,
        payload: "AA55FF00EE11",
        metadata: {
          room: "living"
        }
      })
    });
    assert.equal(createdIrCode.status, 201);
    assert.equal(createdIrCode.body.protocol, "nec");

    const sensorStateUpsert = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/sensor-state`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        sensor_key: "hall_motion",
        sensor_type: "motion",
        source: "api",
        state: {
          detected: true
        }
      })
    });
    assert.equal(sensorStateUpsert.status, 201);

    const sensorEventsIngest = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/sensor-events`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        events: [
          {
            sensor_key: "hall_motion",
            sensor_type: "motion",
            event_kind: "motion_start",
            source: "api",
            value: {
              detected: true
            }
          },
          {
            sensor_key: "hall_mmwave",
            sensor_type: "mmwave",
            event_kind: "presence_update",
            source: "api",
            value: {
              presence: true,
              distance_cm: 174
            }
          }
        ]
      })
    });
    assert.equal(sensorEventsIngest.status, 201);
    assert.equal(sensorEventsIngest.body.ingested, 2);

    const deviceSensorReport = await requestJson(`${httpBase}/api/v1/devices/sensor-report`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        device_uid: deviceUid,
        device_token: deviceToken,
        events: [
          {
            sensor_key: "hall_motion",
            sensor_type: "motion",
            event_kind: "motion_end",
            source: "device",
            value: {
              detected: false
            }
          }
        ]
      })
    });
    assert.equal(deviceSensorReport.status, 200);
    assert.equal(deviceSensorReport.body.ingested, 1);

    const sensorStateRows = await requestJson(`${httpBase}/api/v1/devices/${deviceId}/sensor-state`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(sensorStateRows.status, 200);
    assert.equal(
      (sensorStateRows.body as JsonObject[]).some((row) => row.sensor_key === "hall_motion"),
      true
    );

    const releaseVersion = `99.${Math.floor(Date.now() / 1000)}.0`;
    const releaseHost = env.OTA_ALLOWED_HOSTS[0] ?? "updates.integration.local";
    const releaseUrl = `https://${releaseHost}/firmware/${releaseVersion}.bin`;
    const signingKeyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const signingPrivatePem = signingKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const signingPublicPem = signingKeyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const signingKeyId = `it-signing-${newId()}`;

    await query(
      `UPDATE ota_signing_keys
       SET status = 'retired',
           rotated_at = $1,
           updated_at = $1
       WHERE status = 'active'`,
      [nowIso()]
    );

    await query(
      `INSERT INTO ota_signing_keys (
         id, key_id, public_key_pem, private_key_secret_ref,
         status, created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4,
         'active', $5, $6
       )`,
      [newId(), signingKeyId, signingPublicPem, "env:IT_UNUSED_PRIVATE", nowIso(), nowIso()]
    );

    const manifestPayload = canonicalManifestPayload({
      version: releaseVersion,
      security_version: 1,
      channel: "stable",
      url: releaseUrl,
      size_bytes: 123_456,
      sha256: sha256(`firmware-${releaseVersion}`),
      signature_alg: "ecdsa-p256-sha256",
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });
    const manifestSignature = signManifestPayload(manifestPayload, signingPrivatePem);

    await query(
      `INSERT INTO ota_releases (
         id, model, version, security_version, channel, url, size_bytes,
         sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
         manifest_payload, expires_at, is_active, metadata,
         created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7,
         $8, $9, $10, $11, $12,
         $13::jsonb, $14, $15, $16::jsonb,
         $17, $18
       )`,
      [
        newId(),
        "hexa-mini-switch-v1",
        releaseVersion,
        1,
        "stable",
        releaseUrl,
        123_456,
        manifestPayload.sha256,
        "ecdsa-p256-sha256",
        manifestSignature,
        signingKeyId,
        null,
        JSON.stringify(manifestPayload),
        manifestPayload.expires_at,
        true,
        JSON.stringify({
          build: "integration"
        }),
        nowIso(),
        nowIso()
      ]
    );

    const otaCheck = await requestJson(
      `${httpBase}/api/v1/ota/check?device_uid=${encodeURIComponent(deviceUid)}&current=0.0.1&channel=stable&token=${encodeURIComponent(deviceToken)}`,
      {
        method: "GET"
      }
    );
    assert.equal(otaCheck.status, 410);
    assert.equal(otaCheck.body.code, "ota_ws_only");

    const otaManifest = await requestJson(
      `${httpBase}/api/v1/ota/manifest/${encodeURIComponent(deviceUid)}?current=0.0.1&channel=stable&token=${encodeURIComponent(deviceToken)}`,
      {
        method: "GET"
      }
    );
    assert.equal(otaManifest.status, 410);
    assert.equal(otaManifest.body.code, "ota_ws_only");

    const otaReport = await requestJson(`${httpBase}/api/v1/ota/report`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        device_uid: deviceUid,
        device_token: deviceToken,
        event_type: "success",
        status: "ok",
        from_version: "0.0.1",
        to_version: releaseVersion,
        security_version: 1,
        details: {
          verify: "ok"
        }
      })
    });
    assert.equal(otaReport.status, 410);
    assert.equal(otaReport.body.code, "ota_ws_only");

    const timeoutProvisioned = await requestJson(`${httpBase}/api/v1/provision/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        provision_key: env.DEVICE_PROVISION_KEY,
        chip_id: `it-timeout-chip-${newId()}`,
        model: "hexa-mini-switch-v1"
      })
    });
    assert.equal(timeoutProvisioned.status, 200);

    const timeoutDeviceId = String(timeoutProvisioned.body.device_id);
    const timeoutDeviceUid = String(timeoutProvisioned.body.device_uid);
    const timeoutDeviceToken = String(timeoutProvisioned.body.device_token);
    const timeoutClaimCode = String(timeoutProvisioned.body.claim_code);

    const claimTimeoutDevice = await requestJson(`${httpBase}/api/v1/devices/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        claim_code: timeoutClaimCode
      })
    });
    assert.equal(claimTimeoutDevice.status, 200);

    timeoutDeviceWs = await connectDeviceWs(wsBase, timeoutDeviceUid, timeoutDeviceToken, {
      ackMode: "drop_ack_no_state"
    });

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-ota-timeout",
        device_id: timeoutDeviceId,
        scope: "ota",
        operation: "install"
      })
    );

    const otaTimeoutAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-ota-timeout"
    );
    assert.equal(otaTimeoutAck.ok, false);
    assert.equal(otaTimeoutAck.code, "manifest_not_found");

    const timeoutCommand = await requestJson(`${httpBase}/api/v1/devices/${timeoutDeviceId}/relays/0`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        action: "on"
      })
    });
    assert.equal(timeoutCommand.status, 409);
    assert.equal(timeoutCommand.body.code, "device_unreachable");

    await waitUntil(async () => {
      return (timeoutDeviceWs?.commandCount ?? 0) > 0;
    }, 5_000);

    const fallbackProvisioned = await requestJson(`${httpBase}/api/v1/provision/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        provision_key: env.DEVICE_PROVISION_KEY,
        chip_id: `it-fallback-chip-${newId()}`,
        model: "hexa-mini-switch-v1"
      })
    });
    assert.equal(fallbackProvisioned.status, 200);

    const fallbackDeviceId = String(fallbackProvisioned.body.device_id);
    const fallbackDeviceUid = String(fallbackProvisioned.body.device_uid);
    const fallbackDeviceToken = String(fallbackProvisioned.body.device_token);
    const fallbackClaimCode = String(fallbackProvisioned.body.claim_code);

    const claimFallbackDevice = await requestJson(`${httpBase}/api/v1/devices/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        claim_code: fallbackClaimCode
      })
    });
    assert.equal(claimFallbackDevice.status, 200);

    fallbackAckDeviceWs = await connectDeviceWs(wsBase, fallbackDeviceUid, fallbackDeviceToken, {
      ackMode: "drop_ack_keep_state"
    });

    const rejectProvisioned = await requestJson(`${httpBase}/api/v1/provision/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        provision_key: env.DEVICE_PROVISION_KEY,
        chip_id: `it-ota-reject-chip-${newId()}`,
        model: "hexa-mini-switch-v1"
      })
    });
    assert.equal(rejectProvisioned.status, 200);

    const rejectDeviceId = String(rejectProvisioned.body.device_id);
    const rejectDeviceUid = String(rejectProvisioned.body.device_uid);
    const rejectDeviceToken = String(rejectProvisioned.body.device_token);
    const rejectClaimCode = String(rejectProvisioned.body.claim_code);

    const rejectClaim = await requestJson(`${httpBase}/api/v1/devices/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        claim_code: rejectClaimCode
      })
    });
    assert.equal(rejectClaim.status, 200);

    rejectOtaDeviceWs = await connectDeviceWs(wsBase, rejectDeviceUid, rejectDeviceToken, {
      ackMode: "ota_reject"
    });

    clientWs.ws.send(
      JSON.stringify({
        type: "cmd",
        request_id: "it-cmd-ota-reject",
        device_id: rejectDeviceId,
        scope: "ota",
        operation: "check"
      })
    );

    const otaRejectAck = await clientWs.waitForMessages(
      (msg) => msg.type === "cmd_ack" && msg.request_id === "it-cmd-ota-reject"
    );
    assert.equal(otaRejectAck.ok, false);
    assert.equal(otaRejectAck.code, "ota_rejected_for_test");

    const fallbackAckCommand = await requestJson(`${httpBase}/api/v1/devices/${fallbackDeviceId}/relays/0`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        action: "on"
      })
    });
    assert.equal(fallbackAckCommand.status, 200);

    await waitUntil(async () => {
      const relay = await query<{ is_on: boolean }>(
        `SELECT is_on
         FROM relay_states
         WHERE device_id = $1
           AND relay_index = 0
         LIMIT 1`,
        [fallbackDeviceId]
      );
      return relay.rows[0]?.is_on === true;
    }, 7_000);

    const metricsResponse = await fetch(`${httpBase}/metrics`);
    const metricsText = await metricsResponse.text();
    assert.equal(metricsResponse.status, 200);
    assert.ok(
      /hexa_command_total\{source="ws_client",scope="single",result="success"\}\s+[1-9]\d*/.test(metricsText)
    );
    assert.ok(
      /hexa_command_total\{source="api",scope="single",result="timeout"\}\s+[1-9]\d*/.test(metricsText)
    );
    assert.ok(
      /hexa_command_latency_ms_count\{source="ws_client",scope="single"\}\s+[1-9]\d*/.test(metricsText)
    );
    assert.ok(
      /hexa_command_latency_ms_count\{source="api",scope="single"\}\s+[1-9]\d*/.test(metricsText)
    );
  } finally {
    if (deviceWs?.ws.readyState === WebSocket.OPEN) {
      deviceWs.ws.close(1000, "test_done");
    }
    if (timeoutDeviceWs?.ws.readyState === WebSocket.OPEN) {
      timeoutDeviceWs.ws.close(1000, "test_done");
    }
    if (fallbackAckDeviceWs?.ws.readyState === WebSocket.OPEN) {
      fallbackAckDeviceWs.ws.close(1000, "test_done");
    }
    if (rejectOtaDeviceWs?.ws.readyState === WebSocket.OPEN) {
      rejectOtaDeviceWs.ws.close(1000, "test_done");
    }
    if (clientWs?.ws.readyState === WebSocket.OPEN) {
      clientWs.ws.close(1000, "test_done");
    }
    await app.close();
    await closeDb();
  }
});
