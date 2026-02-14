import "dotenv/config";
import WebSocket from "ws";

type FetchJsonOptions = {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
};

type ProvisionedDevice = {
  index: number;
  chipId: string;
  deviceId: string;
  deviceUid: string;
  deviceToken: string;
  claimCode: string | null;
};

type DeviceSocket = {
  deviceUid: string;
  ws: WebSocket;
  relays: boolean[];
  open: boolean;
};

type ClientSocket = {
  id: number;
  ws: WebSocket;
  pending: Map<
    string,
    {
      resolve: (value: Record<string, unknown>) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
    }
  >;
};

type Summary = {
  started_at: string;
  completed_at: string;
  duration_ms: number;
  api_base_url: string;
  client_base_url: string;
  admin_base_url: string | null;
  admin_dashboard_checked: boolean;
  device_target: number;
  client_target: number;
  devices_online: number;
  clients_online: number;
  command_total: number;
  command_success: number;
  command_failed: number;
  command_failure_samples: Array<Record<string, unknown>>;
  metrics_timeout_line: string | null;
  metrics_success_line: string | null;
};

function parseIntEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed)) {
    return fallback;
  }
  return Math.min(Math.max(parsed, min), max);
}

function parseBoolEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  return raw.trim().toLowerCase() === "true";
}

function normalizeBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  const url = new URL(trimmed);
  url.hash = "";
  url.search = "";
  url.pathname = "";
  return url.toString().replace(/\/$/, "");
}

function toWsBaseUrl(httpBaseUrl: string): string {
  const url = new URL(httpBaseUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.hash = "";
  url.search = "";
  url.pathname = "";
  return url.toString().replace(/\/$/, "");
}

function nowIso(): string {
  return new Date().toISOString();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function parseSafeJson(raw: string): unknown {
  if (!raw) {
    return {};
  }
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function buildCfAccessHeaders(prefix: string): Record<string, string> {
  const scopedId = process.env[`${prefix}_CF_ACCESS_CLIENT_ID`]?.trim();
  const scopedSecret = process.env[`${prefix}_CF_ACCESS_CLIENT_SECRET`]?.trim();
  const globalId = process.env.CF_ACCESS_CLIENT_ID?.trim();
  const globalSecret = process.env.CF_ACCESS_CLIENT_SECRET?.trim();

  const clientId = scopedId || globalId;
  const clientSecret = scopedSecret || globalSecret;

  if (!clientId || !clientSecret) {
    return {};
  }

  return {
    "CF-Access-Client-Id": clientId,
    "CF-Access-Client-Secret": clientSecret
  };
}

async function fetchJson(url: string, options: FetchJsonOptions = {}): Promise<{
  status: number;
  headers: Headers;
  body: unknown;
}> {
  const timeoutMs = options.timeoutMs ?? 15000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: options.method ?? "GET",
      headers: options.body
        ? {
            "content-type": "application/json",
            ...(options.headers ?? {})
          }
        : (options.headers ?? {}),
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal
    });

    const text = await response.text();

    return {
      status: response.status,
      headers: response.headers,
      body: parseSafeJson(text)
    };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJsonOk(url: string, options: FetchJsonOptions = {}): Promise<unknown> {
  const response = await fetchJson(url, options);
  if (response.status < 200 || response.status >= 300) {
    const body = asRecord(response.body);
    const message = typeof body.message === "string" ? body.message : "request_failed";
    throw new Error(`HTTP ${response.status} ${url} ${message}`);
  }
  return response.body;
}

async function runInBatches<T>(
  items: T[],
  batchSize: number,
  worker: (item: T, index: number) => Promise<void>
): Promise<void> {
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    await Promise.all(
      batch.map((item, offset) => worker(item, i + offset))
    );
  }
}

function logStep(message: string): void {
  // eslint-disable-next-line no-console
  console.log(`[${nowIso()}] ${message}`);
}

async function ensureUser(params: {
  apiBaseUrl: string;
  apiHeaders: Record<string, string>;
  email: string;
  password: string;
  name: string;
}): Promise<{
  accessToken: string;
}> {
  const login = await fetchJson(`${params.apiBaseUrl}/api/v1/auth/login`, {
    method: "POST",
    headers: params.apiHeaders,
    body: {
      email: params.email,
      password: params.password
    }
  });
  if (login.status >= 200 && login.status < 300) {
    const body = asRecord(login.body);
    const token = typeof body.access_token === "string" ? body.access_token : "";
    if (!token) {
      throw new Error("login_missing_access_token");
    }
    return {
      accessToken: token
    };
  }

  const register = await fetchJson(`${params.apiBaseUrl}/api/v1/auth/register`, {
    method: "POST",
    headers: params.apiHeaders,
    body: {
      email: params.email,
      password: params.password,
      name: params.name
    }
  });

  if (register.status >= 200 && register.status < 300) {
    const body = asRecord(register.body);
    const token = typeof body.access_token === "string" ? body.access_token : "";
    if (!token) {
      throw new Error("register_missing_access_token");
    }
    return {
      accessToken: token
    };
  }

  const registerBody = asRecord(register.body);
  const registerMessage = typeof registerBody.message === "string" ? registerBody.message : "register_failed";
  throw new Error(`user_setup_failed login_status=${login.status} register_status=${register.status} message=${registerMessage}`);
}

function readOwnedDeviceMap(items: Array<Record<string, unknown>>): Map<string, string> {
  const out = new Map<string, string>();
  for (const item of items) {
    const deviceUid = typeof item.device_uid === "string" ? item.device_uid : "";
    const id = typeof item.id === "string" ? item.id : "";
    if (!deviceUid || !id) {
      continue;
    }
    out.set(deviceUid, id);
  }
  return out;
}

function parseWsRawToObject(raw: WebSocket.RawData): Record<string, unknown> | null {
  const text = typeof raw === "string" ? raw : Buffer.isBuffer(raw) ? raw.toString("utf8") : "";
  if (!text) {
    return null;
  }
  const parsed = parseSafeJson(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

function openDeviceSocket(params: {
  wsBaseUrl: string;
  headers: Record<string, string>;
  deviceUid: string;
  deviceToken: string;
}): Promise<DeviceSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(
      `${params.wsBaseUrl}/ws/device?uid=${encodeURIComponent(params.deviceUid)}&token=${encodeURIComponent(params.deviceToken)}`,
      {
        headers: params.headers
      }
    );

    const state: DeviceSocket = {
      deviceUid: params.deviceUid,
      ws,
      relays: [false, false, false],
      open: false
    };

    const timer = setTimeout(() => {
      try {
        ws.terminate();
      } catch {
        // noop
      }
      reject(new Error(`device_ws_open_timeout ${params.deviceUid}`));
    }, 20000);

    ws.on("open", () => {
      clearTimeout(timer);
      state.open = true;
      ws.send(
        JSON.stringify({
          type: "state_report",
          relays: state.relays,
          telemetry: {
            heap: 64000,
            rssi: -50,
            uptime: 1
          }
        })
      );
      resolve(state);
    });

    ws.on("error", (error) => {
      if (!state.open) {
        clearTimeout(timer);
        reject(new Error(`device_ws_error ${params.deviceUid} ${error instanceof Error ? error.message : "unknown"}`));
      }
    });

    ws.on("message", (raw) => {
      const message = parseWsRawToObject(raw);
      if (!message) {
        return;
      }

      if (message.type === "set_relay") {
        const relayIndex = typeof message.relay_index === "number" ? message.relay_index : Number.NaN;
        const action = typeof message.action === "string" ? message.action : "";
        if (Number.isInteger(relayIndex) && relayIndex >= 0 && relayIndex < state.relays.length) {
          if (action === "on") {
            state.relays[relayIndex] = true;
          } else if (action === "off") {
            state.relays[relayIndex] = false;
          } else if (action === "toggle") {
            state.relays[relayIndex] = !state.relays[relayIndex];
          }
        }

        ws.send(
          JSON.stringify({
            type: "ack",
            command_id: message.command_id,
            ok: true
          })
        );
        ws.send(
          JSON.stringify({
            type: "state_report",
            relays: state.relays,
            telemetry: {
              heap: 63000,
              rssi: -51,
              uptime: 2
            }
          })
        );
        return;
      }

      if (message.type === "set_all_relays") {
        const action = typeof message.action === "string" ? message.action : "";
        if (action === "on") {
          state.relays = state.relays.map(() => true);
        } else if (action === "off") {
          state.relays = state.relays.map(() => false);
        }

        ws.send(
          JSON.stringify({
            type: "ack",
            command_id: message.command_id,
            ok: true
          })
        );
        ws.send(
          JSON.stringify({
            type: "state_report",
            relays: state.relays,
            telemetry: {
              heap: 62000,
              rssi: -52,
              uptime: 3
            }
          })
        );
      }
    });
  });
}

function openClientSocket(params: {
  id: number;
  wsBaseUrl: string;
  headers: Record<string, string>;
  accessToken: string;
}): Promise<ClientSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${params.wsBaseUrl}/ws/client`, {
      headers: params.headers
    });

    const client: ClientSocket = {
      id: params.id,
      ws,
      pending: new Map()
    };

    const timer = setTimeout(() => {
      try {
        ws.terminate();
      } catch {
        // noop
      }
      reject(new Error(`client_ws_auth_timeout ${params.id}`));
    }, 20000);

    ws.on("open", () => {
      ws.send(
        JSON.stringify({
          type: "auth",
          access_token: params.accessToken
        })
      );
    });

    ws.on("error", (error) => {
      if (!client.pending.size) {
        // Only reject early when handshake/auth is not complete.
        // Once open/authenticated, per-request handlers own errors.
        if (ws.readyState !== ws.OPEN) {
          clearTimeout(timer);
          reject(new Error(`client_ws_error ${params.id} ${error instanceof Error ? error.message : "unknown"}`));
        }
      }
    });

    ws.on("message", (raw) => {
      const message = parseWsRawToObject(raw);
      if (!message) {
        return;
      }

      if (message.type === "auth_ok") {
        clearTimeout(timer);
        resolve(client);
        return;
      }

      if (message.type === "auth_error") {
        clearTimeout(timer);
        reject(new Error(`client_auth_error ${params.id} code=${String(message.code ?? "unknown")}`));
        return;
      }

      if (message.type === "cmd_ack") {
        const requestId = typeof message.request_id === "string" ? message.request_id : "";
        if (!requestId) {
          return;
        }
        const pending = client.pending.get(requestId);
        if (!pending) {
          return;
        }
        clearTimeout(pending.timer);
        client.pending.delete(requestId);
        pending.resolve(message);
      }
    });

    ws.on("close", () => {
      for (const [, pending] of client.pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error(`client_socket_closed ${params.id}`));
      }
      client.pending.clear();
    });
  });
}

function sendClientCommand(
  client: ClientSocket,
  payload: Record<string, unknown>,
  timeoutMs: number
): Promise<Record<string, unknown>> {
  const requestId = typeof payload.request_id === "string" ? payload.request_id : "";
  if (!requestId) {
    return Promise.reject(new Error("missing_request_id"));
  }

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      client.pending.delete(requestId);
      reject(new Error(`command_timeout ${requestId}`));
    }, timeoutMs);

    client.pending.set(requestId, {
      resolve,
      reject,
      timer
    });

    try {
      client.ws.send(JSON.stringify(payload));
    } catch (error) {
      clearTimeout(timer);
      client.pending.delete(requestId);
      reject(error instanceof Error ? error : new Error("command_send_failed"));
    }
  });
}

async function checkStatusOk(params: {
  url: string;
  path: string;
  headers: Record<string, string>;
  name: string;
}): Promise<void> {
  const response = await fetchJson(`${params.url}${params.path}`, {
    headers: params.headers,
    timeoutMs: 15000
  });
  if (response.status < 200 || response.status >= 300) {
    const body = asRecord(response.body);
    const message = typeof body.message === "string" ? body.message : "unhealthy";
    throw new Error(`${params.name}_check_failed status=${response.status} message=${message}`);
  }
}

async function main(): Promise<void> {
  const startedAt = Date.now();
  const startedAtIso = nowIso();

  const apiBaseUrl = normalizeBaseUrl(process.env.LOAD_API_BASE_URL || "https://api.vistfiy.store");
  const clientBaseUrl = normalizeBaseUrl(process.env.LOAD_CLIENT_BASE_URL || apiBaseUrl);
  const adminBaseUrlRaw = process.env.LOAD_ADMIN_BASE_URL?.trim() || "https://admin.vistfiy.store";
  const adminBaseUrl = adminBaseUrlRaw.length > 0 ? normalizeBaseUrl(adminBaseUrlRaw) : null;

  if (clientBaseUrl !== apiBaseUrl) {
    throw new Error(
      "LOAD_CLIENT_BASE_URL must match LOAD_API_BASE_URL. admin.vistfiy.store is dashboard-only."
    );
  }

  const apiWsBaseUrl = toWsBaseUrl(apiBaseUrl);
  const clientWsBaseUrl = toWsBaseUrl(clientBaseUrl);

  const deviceCount = parseIntEnv("LOAD_DEVICE_COUNT", 150, 1, 2000);
  const clientCount = parseIntEnv("LOAD_CLIENT_COUNT", 150, 1, 2000);
  const batchSize = parseIntEnv("LOAD_BATCH_SIZE", 20, 1, 200);
  const commandRounds = parseIntEnv("LOAD_COMMAND_ROUNDS", 2, 1, 20);
  const commandTimeoutMs = parseIntEnv("LOAD_COMMAND_TIMEOUT_MS", 10000, 1000, 60000);
  const requireAdminDashboard = parseBoolEnv(
    "LOAD_REQUIRE_ADMIN_DASHBOARD",
    parseBoolEnv("LOAD_REQUIRE_ADMIN_HEALTH", true)
  );

  const runTag = (process.env.LOAD_RUN_TAG || "t530-load").trim().toLowerCase();
  const userEmail = (process.env.LOAD_USER_EMAIL || `loadtest-${runTag}@vistfiy.store`).trim().toLowerCase();
  const userPassword = process.env.LOAD_USER_PASSWORD || "LoadTest#12345";
  const provisionKey = process.env.LOAD_PROVISION_KEY || process.env.DEVICE_PROVISION_KEY;

  if (!provisionKey) {
    throw new Error("missing LOAD_PROVISION_KEY or DEVICE_PROVISION_KEY");
  }

  const apiHttpHeaders = buildCfAccessHeaders("LOAD_API");
  const apiWsHeaders = buildCfAccessHeaders("LOAD_API_WS");
  const clientWsHeaders = buildCfAccessHeaders("LOAD_CLIENT_WS");
  const adminHttpHeaders = buildCfAccessHeaders("LOAD_ADMIN");

  const allDeviceSockets: DeviceSocket[] = [];
  const allClientSockets: ClientSocket[] = [];

  try {
    logStep(`checking api health ${apiBaseUrl}`);
    await checkStatusOk({
      url: apiBaseUrl,
      path: "/health",
      headers: apiHttpHeaders,
      name: "api_health"
    });

    if (adminBaseUrl) {
      logStep(`checking admin dashboard ${adminBaseUrl}/dashboard`);
      try {
        await checkStatusOk({
          url: adminBaseUrl,
          path: "/dashboard",
          headers: adminHttpHeaders,
          name: "admin_dashboard"
        });
      } catch (error) {
        if (requireAdminDashboard) {
          throw error;
        }
        logStep(`admin dashboard warning: ${error instanceof Error ? error.message : "unknown_error"}`);
      }
    }

    logStep(`ensuring load user ${userEmail}`);
    const user = await ensureUser({
      apiBaseUrl,
      apiHeaders: apiHttpHeaders,
      email: userEmail,
      password: userPassword,
      name: "Load Test User"
    });
    const authHeaders = {
      ...apiHttpHeaders,
      authorization: `Bearer ${user.accessToken}`
    };

    logStep(`provisioning/reusing ${deviceCount} devices`);
    const indexes = Array.from({ length: deviceCount }, (_, i) => i);
    const provisioned: ProvisionedDevice[] = new Array(deviceCount);
    await runInBatches(indexes, batchSize, async (index) => {
      const chipId = `${runTag}-${index.toString().padStart(4, "0")}`;
      const body = asRecord(
        await fetchJsonOk(`${apiBaseUrl}/api/v1/provision/register`, {
          method: "POST",
          headers: apiHttpHeaders,
          body: {
            provision_key: provisionKey,
            chip_id: chipId,
            model: "hexa-mini-switch-v1",
            relay_count: 3,
            button_count: 3
          },
          timeoutMs: 20000
        })
      );

      provisioned[index] = {
        index,
        chipId,
        deviceId: String(body.device_id || ""),
        deviceUid: String(body.device_uid || ""),
        deviceToken: String(body.device_token || ""),
        claimCode: typeof body.claim_code === "string" ? body.claim_code : null
      };
    });

    const invalidProvisioned = provisioned.filter((item) => !item || !item.deviceId || !item.deviceUid || !item.deviceToken);
    if (invalidProvisioned.length > 0) {
      throw new Error("provisioning_returned_invalid_device_payload");
    }

    logStep("loading current owned devices");
    const ownedBeforeRaw = await fetchJsonOk(`${apiBaseUrl}/api/v1/devices`, {
      headers: authHeaders
    });
    const ownedBefore = Array.isArray(ownedBeforeRaw) ? (ownedBeforeRaw as Array<Record<string, unknown>>) : [];
    const ownedBeforeMap = readOwnedDeviceMap(ownedBefore);

    const devicesToClaim = provisioned.filter((device) => !ownedBeforeMap.has(device.deviceUid));
    if (devicesToClaim.length > 0) {
      logStep(`claiming ${devicesToClaim.length} devices`);
    } else {
      logStep("all devices already owned by load user");
    }

    await runInBatches(devicesToClaim, batchSize, async (device) => {
      if (!device.claimCode) {
        throw new Error(`device_not_claimable device_uid=${device.deviceUid}`);
      }
      await fetchJsonOk(`${apiBaseUrl}/api/v1/devices/claim`, {
        method: "POST",
        headers: authHeaders,
        body: {
          claim_code: device.claimCode
        }
      });
    });

    const ownedAfterRaw = await fetchJsonOk(`${apiBaseUrl}/api/v1/devices`, {
      headers: authHeaders
    });
    const ownedAfter = Array.isArray(ownedAfterRaw) ? (ownedAfterRaw as Array<Record<string, unknown>>) : [];
    const ownedAfterMap = readOwnedDeviceMap(ownedAfter);

    for (const device of provisioned) {
      if (!ownedAfterMap.has(device.deviceUid)) {
        throw new Error(`owned_device_missing_after_claim device_uid=${device.deviceUid}`);
      }
    }

    logStep(`opening ${deviceCount} device sockets on ${apiWsBaseUrl}`);
    const openedDeviceSockets = await Promise.all(
      provisioned.map((device) =>
        openDeviceSocket({
          wsBaseUrl: apiWsBaseUrl,
          headers: apiWsHeaders,
          deviceUid: device.deviceUid,
          deviceToken: device.deviceToken
        })
      )
    );
    allDeviceSockets.push(...openedDeviceSockets);

    logStep(`opening ${clientCount} client sockets on ${clientWsBaseUrl}`);
    const openedClientSockets = await Promise.all(
      Array.from({ length: clientCount }, (_, i) =>
        openClientSocket({
          id: i,
          wsBaseUrl: clientWsBaseUrl,
          headers: clientWsHeaders,
          accessToken: user.accessToken
        })
      )
    );
    allClientSockets.push(...openedClientSockets);

    await sleep(1200);

    const commandResults: Array<Record<string, unknown>> = [];
    logStep(`running ${commandRounds} command rounds (${clientCount * commandRounds} commands)`);

    for (let round = 0; round < commandRounds; round += 1) {
      const roundResults = await Promise.all(
        openedClientSockets.map(async (client, idx) => {
          const target = provisioned[idx % provisioned.length];
          const targetDeviceId = ownedAfterMap.get(target.deviceUid);
          if (!targetDeviceId) {
            return {
              ok: false,
              code: "missing_device_id",
              device_uid: target.deviceUid
            };
          }

          const requestId = `round${round}-client${client.id}-${Date.now()}-${idx}`;
          try {
            const ack = await sendClientCommand(
              client,
              {
                type: "cmd",
                request_id: requestId,
                device_id: targetDeviceId,
                scope: "single",
                relay_index: idx % 3,
                action: "toggle"
              },
              commandTimeoutMs
            );
            return {
              ok: ack.ok === true,
              code: typeof ack.code === "string" ? ack.code : null,
              request_id: requestId
            };
          } catch (error) {
            return {
              ok: false,
              code: "command_exception",
              message: error instanceof Error ? error.message : "unknown_error",
              request_id: requestId
            };
          }
        })
      );
      commandResults.push(...roundResults);
      await sleep(500);
    }

    const metricsResponse = await fetch(`${apiBaseUrl}/metrics`, {
      headers: apiHttpHeaders,
      signal: AbortSignal.timeout(15000)
    });
    if (!metricsResponse.ok) {
      throw new Error(`metrics_fetch_failed status=${metricsResponse.status}`);
    }
    const metricsRaw = await metricsResponse.text();

    const timeoutMetricLine =
      metricsRaw
        .split("\n")
        .find((line) => line.includes("hexa_command_total") && line.includes("result=\"timeout\"")) ?? null;
    const successMetricLine =
      metricsRaw
        .split("\n")
        .find(
          (line) =>
            line.includes("hexa_command_total") &&
            line.includes("source=\"ws_client\"") &&
            line.includes("result=\"success\"")
        ) ?? null;

    const commandTotal = commandResults.length;
    const commandSuccess = commandResults.filter((item) => item.ok === true).length;
    const commandFailed = commandTotal - commandSuccess;

    const summary: Summary = {
      started_at: startedAtIso,
      completed_at: nowIso(),
      duration_ms: Date.now() - startedAt,
      api_base_url: apiBaseUrl,
      client_base_url: clientBaseUrl,
      admin_base_url: adminBaseUrl,
      admin_dashboard_checked: Boolean(adminBaseUrl),
      device_target: deviceCount,
      client_target: clientCount,
      devices_online: openedDeviceSockets.filter((item) => item.open).length,
      clients_online: openedClientSockets.length,
      command_total: commandTotal,
      command_success: commandSuccess,
      command_failed: commandFailed,
      command_failure_samples: commandResults.filter((item) => item.ok !== true).slice(0, 10),
      metrics_timeout_line: timeoutMetricLine,
      metrics_success_line: successMetricLine
    };

    // eslint-disable-next-line no-console
    console.log(JSON.stringify(summary, null, 2));

    if (
      summary.devices_online < deviceCount ||
      summary.clients_online < clientCount ||
      summary.command_failed > 0
    ) {
      throw new Error("load_test_failed_thresholds");
    }
  } finally {
    for (const client of allClientSockets) {
      try {
        client.ws.close();
      } catch {
        // noop
      }
    }
    for (const device of allDeviceSockets) {
      try {
        device.ws.close();
      } catch {
        // noop
      }
    }
    await sleep(500);
  }
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
