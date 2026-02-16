import { FastifyInstance } from "fastify";
import { IncomingMessage } from "node:http";
import { createReadStream } from "node:fs";
import { access, stat } from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import { env } from "../../config/env";
import { query } from "../../db/connection";
import { realtimeHub } from "../../realtime/hub";
import { automationService } from "../../services/automation-service";
import { deviceStateCache } from "../../services/device-state-cache";
import { deviceFallbackSyncService } from "../../services/device-fallback-sync-service";
import { type OtaManifestPayload, verifyManifestSignature } from "../../services/ota-manifest-signer";
import { RelayServiceError, relayService } from "../../services/relay-service";
import { smartHomeService } from "../../services/smart-home-service";
import {
  normalizeIrPayload,
  rankIrMatches,
  type IrRankableRecord
} from "../../services/ir-code-utils";
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

type ClientDeviceControlCommand = {
  scope: "device";
  operation: "reboot" | "factory_reset";
};

type OtaChannel = "dev" | "beta" | "stable";

type ClientOtaCommand = {
  scope: "ota";
  operation: "check" | "install";
  channel?: OtaChannel;
};

type ButtonMode = "push_button" | "rocker_switch" | "rocker_switch_follow";

type ClientButtonModeCommand = {
  scope: "button_mode";
  buttonIndex: number;
  mode: ButtonMode;
};

type ClientButtonLinkCommand = {
  scope: "button_link";
  buttonIndex: number;
  linked: boolean;
};

type ClientHaConfigCommand = {
  scope: "ha_config";
  showConfig: boolean;
};

type ConnectivityMode = "cloud_ws" | "local_mqtt";

type ClientConnectivityModeCommand = {
  scope: "connectivity_mode";
  mode: ConnectivityMode;
};

type IrLearnType = "button" | "ac";

type ClientIrCommand = {
  scope: "ir";
  operation:
  | "learn_start"
  | "learn_test"
  | "learn_save"
  | "learn_discard"
  | "send_code"
  | "delete_code"
  | "recognize_candidate";
  learnType?: IrLearnType;
  codeId?: string;
  codeName?: string;
  candidate?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  topN?: number;
};

type ClientCommand =
  | ClientRelayCommand
  | ClientWifiCommand
  | ClientDeviceControlCommand
  | ClientOtaCommand
  | ClientButtonModeCommand
  | ClientButtonLinkCommand
  | ClientHaConfigCommand
  | ClientConnectivityModeCommand
  | ClientIrCommand;

type ClientConfigCommand =
  | ClientButtonModeCommand
  | ClientButtonLinkCommand
  | ClientHaConfigCommand
  | ClientConnectivityModeCommand;

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
  mode?: ConnectivityMode;
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

type DeviceOtaLookupRow = {
  id: string;
  device_uid: string;
  is_active: boolean;
  model: string;
  firmware_version: string | null;
  ota_channel: OtaChannel;
  ota_security_version: number;
};

type OtaReleaseRow = {
  id: string;
  model: string;
  version: string;
  security_version: number | string;
  channel: OtaChannel;
  url: string;
  size_bytes: number | string;
  sha256: string;
  signature_alg: string;
  signature: string;
  verification_key_id: string;
  next_verification_key_id: string | null;
  manifest_payload: unknown;
  metadata: unknown;
};

type OtaResolvedRelease = {
  manifest: OtaManifestPayload & {
    signature: string;
    verification_key_id: string;
    next_verification_key_id: string | null;
  };
  artifactPath: string;
};

type DeviceConfigLookupRow = {
  id: string;
  device_uid: string;
  is_active: boolean;
  relay_count: number;
  button_count: number;
  input_config: unknown;
  config: unknown;
};

type DeviceIrControlLookupRow = {
  id: string;
  device_uid: string;
  owner_user_id: string | null;
  is_active: boolean;
  device_class: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid";
  capabilities: unknown;
};

type DeviceIrCodeRow = {
  id: string;
  device_id: string;
  owner_user_id: string | null;
  code_name: string;
  protocol: string;
  protocol_norm: string | null;
  frequency_hz: number | null;
  frequency_norm_hz: number | null;
  payload: string;
  payload_format: string | null;
  payload_fingerprint: string | null;
  source_type: string | null;
  source_ref: string | null;
  normalized_payload: unknown;
  metadata: unknown;
  learned_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

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

const DEVICE_WS_HEARTBEAT_INTERVAL_MS = 5_000;
const DEVICE_WS_HEARTBEAT_MISS_LIMIT = 3;
const DEVICE_OFFLINE_GRACE_MS = 20_000;
const DEVICE_COMMAND_QUEUE_MAX = 40;
const WIFI_CONFIG_COMMAND_TIMEOUT_MS = 12_000;
const DEVICE_CONTROL_COMMAND_TIMEOUT_MS = 8_000;
const OTA_CONTROL_COMMAND_TIMEOUT_MS = 12_000;
const IR_CONTROL_COMMAND_TIMEOUT_MS = 12_000;
const OTA_WS_CHUNK_BYTES = 768;
const OTA_WS_CHUNK_ACK_TIMEOUT_MS = 8_000;
const WIFI_SSID_MAX_LEN = 32;
const WIFI_PASSWORD_MAX_LEN = 63;
const pendingOfflineTimers = new Map<string, NodeJS.Timeout>();
const deviceCommandQueues = new Map<string, DeviceCommandQueue>();
const activeOtaStreams = new Set<string>();

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

function asBooleanLike(value: unknown): boolean | null {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value === 1) {
      return true;
    }
    if (value === 0) {
      return false;
    }
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "on" || normalized === "1") {
      return true;
    }
    if (normalized === "false" || normalized === "off" || normalized === "0") {
      return false;
    }
  }
  return null;
}

function parseButtonMode(raw: unknown): ButtonMode | null {
  if (typeof raw !== "string") {
    return null;
  }
  const normalized = raw.trim().toLowerCase();
  if (
    normalized === "push_button" ||
    normalized === "rocker_switch" ||
    normalized === "rocker_switch_follow"
  ) {
    return normalized;
  }
  return null;
}

function parseConnectivityMode(raw: unknown): ConnectivityMode | null {
  if (typeof raw !== "string") {
    return null;
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === "cloud_ws" || normalized === "cloud" || normalized === "app") {
    return "cloud_ws";
  }
  if (normalized === "local_mqtt" || normalized === "ha" || normalized === "mqtt") {
    return "local_mqtt";
  }
  return null;
}

function parseIrLearnType(raw: unknown): IrLearnType | undefined {
  if (typeof raw !== "string") {
    return undefined;
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === "button" || normalized === "generic") {
    return "button";
  }
  if (normalized === "ac" || normalized === "climate") {
    return "ac";
  }
  return undefined;
}

function parseIrOperation(raw: unknown): ClientIrCommand["operation"] | null {
  if (typeof raw !== "string") {
    return null;
  }
  const normalized = raw.trim().toLowerCase();
  switch (normalized) {
    case "learn_start":
    case "learn":
    case "start":
      return "learn_start";
    case "learn_test":
    case "test":
      return "learn_test";
    case "learn_save":
    case "save":
      return "learn_save";
    case "learn_discard":
    case "discard":
    case "cancel":
      return "learn_discard";
    case "send_code":
    case "send":
      return "send_code";
    case "delete_code":
    case "delete":
    case "remove":
      return "delete_code";
    case "recognize_candidate":
    case "recognize":
      return "recognize_candidate";
    default:
      return null;
  }
}

function defaultInputConfigRows(buttonCount: number, relayCount: number): InputConfigRow[] {
  const out: InputConfigRow[] = [];
  for (let i = 0; i < buttonCount; i += 1) {
    const linked = relayCount > 0 && i < relayCount;
    out.push({
      input_index: i,
      input_type: "push_button",
      linked,
      target_relay_index: linked ? i : null,
      rocker_mode: null,
      invert_input: false,
      hold_seconds: null
    });
  }
  return out;
}

function parseInputConfigRow(raw: unknown): InputConfigRow | null {
  const row = asRecord(raw);
  if (!row) {
    return null;
  }
  const inputIndex = typeof row.input_index === "number" ? row.input_index : Number.NaN;
  const inputTypeRaw = typeof row.input_type === "string" ? row.input_type.trim().toLowerCase() : "";
  const linked = typeof row.linked === "boolean" ? row.linked : false;
  const targetRelayIndex =
    row.target_relay_index === null
      ? null
      : typeof row.target_relay_index === "number"
        ? row.target_relay_index
        : Number.NaN;
  const rockerMode =
    row.rocker_mode === null
      ? null
      : row.rocker_mode === "edge_toggle" || row.rocker_mode === "follow_position"
        ? row.rocker_mode
        : null;
  const invertInput = typeof row.invert_input === "boolean" ? row.invert_input : false;
  const holdSeconds =
    row.hold_seconds === null
      ? null
      : typeof row.hold_seconds === "number" && Number.isInteger(row.hold_seconds)
        ? row.hold_seconds
        : null;

  if (!Number.isInteger(inputIndex) || inputIndex < 0) {
    return null;
  }
  if (inputTypeRaw !== "push_button" && inputTypeRaw !== "rocker_switch") {
    return null;
  }

  return {
    input_index: inputIndex,
    input_type: inputTypeRaw,
    linked,
    target_relay_index: targetRelayIndex,
    rocker_mode: rockerMode,
    invert_input: invertInput,
    hold_seconds: holdSeconds
  };
}

function normalizeInputConfigRows(value: unknown, buttonCount: number, relayCount: number): InputConfigRow[] {
  if (!Array.isArray(value)) {
    return defaultInputConfigRows(buttonCount, relayCount);
  }

  const parsedRows: InputConfigRow[] = [];
  for (const raw of value) {
    const parsed = parseInputConfigRow(raw);
    if (!parsed) {
      return defaultInputConfigRows(buttonCount, relayCount);
    }
    parsedRows.push(parsed);
  }

  if (parsedRows.length !== buttonCount) {
    return defaultInputConfigRows(buttonCount, relayCount);
  }

  try {
    return validateInputConfigMatrix({
      buttonCount,
      relayCount
    }, parsedRows);
  } catch {
    return defaultInputConfigRows(buttonCount, relayCount);
  }
}

function validateInputConfigMatrix(
  shape: { buttonCount: number; relayCount: number },
  inputConfig: InputConfigRow[]
): InputConfigRow[] {
  if (inputConfig.length !== shape.buttonCount) {
    throw new Error("input_config_size_mismatch");
  }

  const seen = new Set<number>();
  for (const cfg of inputConfig) {
    if (cfg.input_index >= shape.buttonCount) {
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
        (cfg.target_relay_index as number) >= shape.relayCount
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

  for (let i = 0; i < shape.buttonCount; i += 1) {
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

function cloneConfig(value: unknown): Record<string, unknown> {
  const record = asRecord(value) ?? {};
  try {
    return JSON.parse(JSON.stringify(record)) as Record<string, unknown>;
  } catch {
    return { ...record };
  }
}

function asNonNegativeInt(value: number | string): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value));
  }
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return Math.max(0, Math.trunc(parsed));
    }
  }
  return 0;
}

function asOtaManifestPayload(value: unknown): OtaManifestPayload | null {
  const obj = asRecord(value);
  if (!obj) {
    return null;
  }

  const version = typeof obj.version === "string" ? obj.version.trim() : "";
  const channelRaw = typeof obj.channel === "string" ? obj.channel.trim().toLowerCase() : "";
  const url = typeof obj.url === "string" ? obj.url.trim() : "";
  const sha256Raw = typeof obj.sha256 === "string" ? obj.sha256.trim().toLowerCase() : "";
  const signatureAlg = typeof obj.signature_alg === "string" ? obj.signature_alg.trim() : "";
  const expiresAt = typeof obj.expires_at === "string" ? obj.expires_at.trim() : "";
  const securityVersion = asNonNegativeInt(
    typeof obj.security_version === "number" || typeof obj.security_version === "string"
      ? (obj.security_version as number | string)
      : -1
  );
  const sizeBytes = asNonNegativeInt(
    typeof obj.size_bytes === "number" || typeof obj.size_bytes === "string"
      ? (obj.size_bytes as number | string)
      : -1
  );

  if (!version || !url || !expiresAt) {
    return null;
  }
  if (channelRaw !== "dev" && channelRaw !== "beta" && channelRaw !== "stable") {
    return null;
  }
  if (signatureAlg !== "ecdsa-p256-sha256") {
    return null;
  }
  if (!/^[a-f0-9]{64}$/.test(sha256Raw)) {
    return null;
  }
  if (sizeBytes <= 0) {
    return null;
  }

  return {
    version,
    security_version: securityVersion,
    channel: channelRaw as OtaChannel,
    url,
    size_bytes: sizeBytes,
    sha256: sha256Raw,
    signature_alg: "ecdsa-p256-sha256",
    expires_at: expiresAt
  };
}

function releaseMatchesManifest(row: OtaReleaseRow, manifest: OtaManifestPayload): boolean {
  const releaseSize = asNonNegativeInt(row.size_bytes);
  const releaseSecurityVersion = asNonNegativeInt(row.security_version);
  return (
    row.version === manifest.version &&
    row.channel === manifest.channel &&
    row.url === manifest.url &&
    releaseSize === manifest.size_bytes &&
    row.sha256.toLowerCase() === manifest.sha256.toLowerCase() &&
    row.signature_alg === manifest.signature_alg &&
    releaseSecurityVersion === manifest.security_version
  );
}

async function loadSigningPublicKeyMap(): Promise<Map<string, string>> {
  const result = await query<{ key_id: string; public_key_pem: string }>(
    `SELECT key_id, public_key_pem
     FROM ota_signing_keys`
  );
  const map = new Map<string, string>();
  for (const row of result.rows) {
    map.set(row.key_id, row.public_key_pem);
  }
  return map;
}

function normalizeArtifactKey(rawKey: string): string | null {
  const decoded = rawKey.replace(/\\/g, "/");
  const segments = decoded.split("/").filter((segment) => segment.length > 0 && segment !== ".");
  if (segments.length === 0 || segments.some((segment) => segment === "..")) {
    return null;
  }
  return segments.join("/");
}

function resolveArtifactAbsolutePath(rootDir: string, key: string): string | null {
  const normalized = normalizeArtifactKey(key);
  if (!normalized) {
    return null;
  }
  const absolute = path.resolve(rootDir, ...normalized.split("/"));
  const normalizedRoot = path.resolve(rootDir);
  if (absolute !== normalizedRoot && !absolute.startsWith(`${normalizedRoot}${path.sep}`)) {
    return null;
  }
  return absolute;
}

function artifactRootDir(): string {
  return path.resolve(process.cwd(), env.OTA_ARTIFACTS_DIR);
}

function decodeUriComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function artifactKeyFromManifestUrl(manifestUrl: string): string | null {
  try {
    const parsed = new URL(manifestUrl);
    const marker = "/api/v1/ota/artifacts/";
    const index = parsed.pathname.indexOf(marker);
    if (index < 0) {
      return null;
    }
    const encodedKey = parsed.pathname.slice(index + marker.length);
    const decodedSegments = encodedKey
      .split("/")
      .map((segment) => decodeUriComponentSafe(segment))
      .filter((segment) => segment.length > 0);
    if (decodedSegments.length === 0) {
      return null;
    }
    return normalizeArtifactKey(decodedSegments.join("/"));
  } catch {
    return null;
  }
}

function artifactKeyFromMetadata(metadata: unknown): string | null {
  const metadataObj = asRecord(metadata);
  const artifactObj = asRecord(metadataObj?.artifact);
  const artifactKey = typeof artifactObj?.key === "string" ? artifactObj.key : "";
  if (!artifactKey) {
    return null;
  }
  return normalizeArtifactKey(artifactKey);
}

async function resolveOtaReleaseForDevice(params: {
  model: string;
  channel: OtaChannel;
  currentVersion: string | null;
  minimumSecurityVersion: number;
}): Promise<OtaResolvedRelease | null> {
  const releases = await query<OtaReleaseRow>(
    `SELECT
       id, model, version, security_version, channel, url, size_bytes,
       sha256, signature_alg, signature, verification_key_id, next_verification_key_id,
       manifest_payload, metadata
     FROM ota_releases
     WHERE model = $1
       AND channel = $2
       AND is_active = TRUE
       AND expires_at > now()
       AND security_version >= $3`,
    [params.model, params.channel, params.minimumSecurityVersion]
  );

  const candidates = releases.rows
    .filter((row) => semver.valid(row.version))
    .sort((a, b) => semver.rcompare(a.version, b.version));

  const keyMap = await loadSigningPublicKeyMap();
  const currentVersion = semver.valid(params.currentVersion ?? "")
    ? (params.currentVersion as string)
    : "0.0.0";

  for (const candidate of candidates) {
    const manifest = asOtaManifestPayload(candidate.manifest_payload);
    if (!manifest) {
      continue;
    }
    if (!releaseMatchesManifest(candidate, manifest)) {
      continue;
    }
    if (!semver.gt(candidate.version, currentVersion)) {
      continue;
    }

    const verificationKey = keyMap.get(candidate.verification_key_id);
    if (!verificationKey) {
      continue;
    }
    if (candidate.next_verification_key_id && !keyMap.has(candidate.next_verification_key_id)) {
      continue;
    }
    if (!verifyManifestSignature(manifest, candidate.signature, verificationKey)) {
      continue;
    }

    const artifactKey = artifactKeyFromMetadata(candidate.metadata) ?? artifactKeyFromManifestUrl(manifest.url);
    if (!artifactKey) {
      continue;
    }
    const artifactPath = resolveArtifactAbsolutePath(artifactRootDir(), artifactKey);
    if (!artifactPath) {
      continue;
    }

    try {
      await access(artifactPath);
      const info = await stat(artifactPath);
      if (!info.isFile()) {
        continue;
      }
      if (info.size !== manifest.size_bytes) {
        continue;
      }
    } catch {
      continue;
    }

    return {
      manifest: {
        ...manifest,
        signature: candidate.signature,
        verification_key_id: candidate.verification_key_id,
        next_verification_key_id: candidate.next_verification_key_id
      },
      artifactPath
    };
  }

  return null;
}

async function sendOtaAbort(deviceUid: string, transferId: string, reason: string): Promise<void> {
  const commandId = newId();
  realtimeHub.sendToDevice(deviceUid, {
    type: "ota_abort",
    command_id: commandId,
    transfer_id: transferId,
    reason,
    ts: nowIso()
  });
}

async function streamOtaArtifactOverWs(params: {
  deviceUid: string;
  transferId: string;
  artifactPath: string;
  timeoutMs: number;
}): Promise<void> {
  const artifactInfo = await stat(params.artifactPath);
  if (!artifactInfo.isFile() || artifactInfo.size <= 0) {
    throw new Error("artifact_not_found");
  }

  const stream = createReadStream(params.artifactPath, {
    highWaterMark: OTA_WS_CHUNK_BYTES
  });
  const totalBytes = artifactInfo.size;

  let offset = 0;
  let chunkIndex = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    const isLast = offset + buffer.length >= totalBytes;
    const commandId = newId();
    const pendingAck = realtimeHub.createPendingAck(commandId, params.deviceUid, params.timeoutMs);
    const sent = realtimeHub.sendToDevice(params.deviceUid, {
      type: "ota_chunk",
      command_id: commandId,
      transfer_id: params.transferId,
      chunk_index: chunkIndex,
      offset,
      data_b64: buffer.toString("base64url"),
      is_last: isLast,
      ts: nowIso()
    });

    if (!sent) {
      realtimeHub.resolveAck(commandId, {
        ok: false,
        error: "device_disconnected"
      });
      throw new Error("device_disconnected");
    }

    const ack = await pendingAck;
    if (!ack.ok) {
      throw new Error(typeof ack.error === "string" && ack.error.length > 0 ? ack.error : "chunk_rejected");
    }

    offset += buffer.length;
    chunkIndex += 1;
  }
}

async function persistOtaStatusFromWs(params: {
  deviceId: string;
  message: Record<string, unknown>;
}): Promise<void> {
  const eventType =
    typeof params.message.event_type === "string" && params.message.event_type.trim().length > 0
      ? params.message.event_type.trim()
      : "unknown";
  const status =
    typeof params.message.status === "string" && params.message.status.trim().length > 0
      ? params.message.status.trim()
      : "unknown";
  const fromVersion = typeof params.message.from_version === "string" ? params.message.from_version : null;
  const toVersion = typeof params.message.to_version === "string" ? params.message.to_version : null;
  const securityVersion =
    typeof params.message.security_version === "number" && Number.isInteger(params.message.security_version)
      ? params.message.security_version
      : null;
  const reasonFromRoot = typeof params.message.reason === "string" ? params.message.reason : null;
  const details = asRecord(params.message.details) ?? {};
  const reasonFromDetails = typeof details.reason === "string" ? details.reason : null;
  const reason = reasonFromRoot ?? reasonFromDetails;
  const now = nowIso();

  await query(
    `INSERT INTO ota_reports (
       id, device_id, event_type, status, from_version, to_version,
       security_version, details, created_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7, $8::jsonb, $9
     )`,
    [
      newId(),
      params.deviceId,
      eventType,
      status,
      fromVersion,
      toVersion,
      securityVersion,
      JSON.stringify({
        ...details,
        command_id: typeof params.message.command_id === "string" ? params.message.command_id : null,
        reason
      }),
      now
    ]
  );

  const completed = status === "ok" && (eventType === "success" || eventType === "boot_ok");
  await query(
    `UPDATE devices
     SET last_ota_status = $1,
         last_ota_reason = $2,
         last_ota_check_at = $3,
         firmware_version = CASE
           WHEN $4 = TRUE AND $5 IS NOT NULL THEN $5
           ELSE firmware_version
         END,
         ota_security_version = CASE
           WHEN $4 = TRUE AND $6 IS NOT NULL THEN GREATEST(ota_security_version, $6)
           ELSE ota_security_version
         END,
         updated_at = $3
     WHERE id = $7`,
    [status, reason, now, completed, toVersion, securityVersion, params.deviceId]
  );
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

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function asCapabilitySummary(value: unknown): Array<{
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
    const record = asRecord(item);
    if (!record) {
      continue;
    }
    const key = typeof record.key === "string" ? record.key : "";
    const kind = typeof record.kind === "string" ? record.kind : "";
    if (!key || !kind) {
      continue;
    }
    out.push({
      key,
      kind,
      enabled: record.enabled !== false
    });
  }
  return out;
}

function isIrCapableDevice(row: DeviceIrControlLookupRow): boolean {
  if (row.device_class === "ir_hub" || row.device_class === "hybrid") {
    return true;
  }
  const capabilities = asCapabilitySummary(row.capabilities);
  return capabilities.some(
    (item) =>
      item.enabled &&
      (item.key === "ir_tx" || item.key === "ir_rx" || item.kind === "infrared")
  );
}

async function writeAuditLog(params: {
  deviceId: string;
  userId?: string | null;
  action: string;
  source: string;
  details: Record<string, unknown>;
}): Promise<void> {
  await query(
    `INSERT INTO audit_log (
       id, device_id, user_id, action, details, source, created_at
     ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
    [
      newId(),
      params.deviceId,
      params.userId ?? null,
      params.action,
      JSON.stringify(params.details),
      params.source,
      nowIso()
    ]
  );
}

async function upsertDeviceIrCode(params: {
  deviceId: string;
  ownerUserId: string | null;
  codeName: string;
  protocol: string;
  frequencyHz: number | null;
  payload: string;
  payloadFormat?: string | null;
  sourceType: "device" | "migration" | "library" | "user";
  sourceRef?: string | null;
  metadata: Record<string, unknown>;
  normalizedPayloadOverride?: Record<string, unknown> | null;
}): Promise<DeviceIrCodeRow> {
  const normalized = normalizeIrPayload({
    protocol: params.protocol,
    frequencyHz: params.frequencyHz,
    payload: params.payload,
    payloadFormat: params.payloadFormat
  });
  const normalizedPayloadMerged =
    params.normalizedPayloadOverride && Object.keys(params.normalizedPayloadOverride).length > 0
      ? {
        ...normalized.normalizedPayload,
        ...params.normalizedPayloadOverride
      }
      : normalized.normalizedPayload;

  const saved = await query<DeviceIrCodeRow>(
    `INSERT INTO device_ir_codes (
       id, device_id, owner_user_id, code_name, protocol, protocol_norm,
       frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
       source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7, $8, $9, $10, $11,
       $12, $13, $14::jsonb, $15::jsonb, $16, $17, $18
     )
     ON CONFLICT (device_id, code_name)
     DO UPDATE SET
       owner_user_id = EXCLUDED.owner_user_id,
       protocol = EXCLUDED.protocol,
       protocol_norm = EXCLUDED.protocol_norm,
       frequency_hz = EXCLUDED.frequency_hz,
       frequency_norm_hz = EXCLUDED.frequency_norm_hz,
       payload = EXCLUDED.payload,
       payload_format = EXCLUDED.payload_format,
       payload_fingerprint = EXCLUDED.payload_fingerprint,
       source_type = EXCLUDED.source_type,
       source_ref = EXCLUDED.source_ref,
       normalized_payload = EXCLUDED.normalized_payload,
       metadata = EXCLUDED.metadata,
       learned_at = EXCLUDED.learned_at,
       updated_at = EXCLUDED.updated_at
     RETURNING
       id, device_id, owner_user_id, code_name, protocol, protocol_norm,
       frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
       source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at`,
    [
      newId(),
      params.deviceId,
      params.ownerUserId,
      params.codeName.trim(),
      params.protocol.trim(),
      normalized.protocolNorm,
      params.frequencyHz,
      normalized.frequencyNormHz,
      params.payload,
      normalized.payloadFormat,
      normalized.payloadFingerprint,
      params.sourceType,
      params.sourceRef ?? null,
      JSON.stringify(normalizedPayloadMerged),
      JSON.stringify(params.metadata),
      nowIso(),
      nowIso(),
      nowIso()
    ]
  );

  return saved.rows[0];
}

async function loadIrRankRecords(deviceId: string): Promise<IrRankableRecord[]> {
  const deviceRows = await query<{
    id: string;
    code_name: string;
    protocol_norm: string | null;
    frequency_norm_hz: number | null;
    payload_fingerprint: string | null;
    payload: string;
    brand: string | null;
    model: string | null;
    metadata: unknown;
  }>(
    `SELECT
       id,
       code_name,
       protocol_norm,
       frequency_norm_hz,
       payload_fingerprint,
       payload,
       metadata->>'brand' AS brand,
       metadata->>'model' AS model,
       metadata
     FROM device_ir_codes
     WHERE device_id = $1`,
    [deviceId]
  );

  const libraryRows = await query<{
    id: string;
    protocol_norm: string;
    frequency_norm_hz: number | null;
    payload_fingerprint: string;
    payload: string;
    brand: string | null;
    model: string | null;
    metadata: unknown;
  }>(
    `SELECT
       r.id,
       r.protocol_norm,
       r.frequency_norm_hz,
       r.payload_fingerprint,
       r.payload,
       r.brand,
       r.model,
       r.metadata
     FROM ir_library_records r
     INNER JOIN ir_library_sources s ON s.id = r.source_id
     WHERE s.is_active = TRUE`
  );

  const out: IrRankableRecord[] = [];
  for (const row of deviceRows.rows) {
    const fingerprint = row.payload_fingerprint ?? "";
    if (!fingerprint) {
      continue;
    }
    out.push({
      source: "device",
      codeId: row.id,
      codeName: row.code_name,
      libraryRecordId: null,
      protocolNorm: row.protocol_norm ?? "UNKNOWN",
      frequencyNormHz: row.frequency_norm_hz,
      payloadFingerprint: fingerprint,
      payloadCanonical: row.payload,
      brand: row.brand,
      model: row.model,
      metadata: asObject(row.metadata)
    });
  }

  for (const row of libraryRows.rows) {
    out.push({
      source: "library",
      codeId: row.id,
      codeName: null,
      libraryRecordId: row.id,
      protocolNorm: row.protocol_norm,
      frequencyNormHz: row.frequency_norm_hz,
      payloadFingerprint: row.payload_fingerprint,
      payloadCanonical: row.payload,
      brand: row.brand,
      model: row.model,
      metadata: asObject(row.metadata)
    });
  }

  return out;
}

async function sendIrControlCommand(params: {
  userId: string;
  role: string;
  deviceId: string;
  command: ClientIrCommand;
  timeoutMs: number;
}): Promise<
  | {
    ok: true;
    deviceUid: string;
    latencyMs: number;
    result?: Record<string, unknown>;
    commandId?: string;
  }
  | {
    ok: false;
    code: string;
    message: string;
    details?: Record<string, unknown>;
  }
> {
  if (!env.IR_CLOUD_FEATURE_ENABLED) {
    return {
      ok: false,
      code: "feature_disabled",
      message: "Cloud IR control is disabled."
    };
  }

  const isAdminActor = params.role === "admin";
  const lookup = isAdminActor
    ? await query<DeviceIrControlLookupRow>(
      `SELECT
           id, device_uid, owner_user_id, is_active, device_class, capabilities
         FROM devices
         WHERE id = $1
         LIMIT 1`,
      [params.deviceId]
    )
    : await query<DeviceIrControlLookupRow>(
      `SELECT
           id, device_uid, owner_user_id, is_active, device_class, capabilities
         FROM devices
         WHERE id = $1
           AND owner_user_id = $2
         LIMIT 1`,
      [params.deviceId, params.userId]
    );
  const row = lookup.rows[0];
  if (!row) {
    return isAdminActor
      ? {
        ok: false,
        code: "not_found",
        message: "Device not found."
      }
      : {
        ok: false,
        code: "forbidden",
        message: "Only the device owner can control this device."
      };
  }
  if (!row.is_active) {
    return {
      ok: false,
      code: "device_inactive",
      message: "Device is inactive."
    };
  }
  if (!isIrCapableDevice(row)) {
    return {
      ok: false,
      code: "device_not_ir_capable",
      message: "Device does not expose IR capability."
    };
  }

  if (params.command.operation === "recognize_candidate") {
    if (!env.IR_AUTOREC_ENABLED) {
      return {
        ok: false,
        code: "feature_disabled",
        message: "IR auto-recognition is disabled."
      };
    }

    const candidate = params.command.candidate ?? {};
    const protocol = typeof candidate.protocol === "string" ? candidate.protocol.trim() : "";
    const payload = typeof candidate.payload === "string" ? candidate.payload : "";
    if (!protocol || !payload) {
      return {
        ok: false,
        code: "validation_error",
        message: "candidate.protocol and candidate.payload are required."
      };
    }
    const candidateFrequency =
      typeof candidate.frequency_hz === "number" && Number.isInteger(candidate.frequency_hz)
        ? candidate.frequency_hz
        : null;
    const payloadFormat =
      typeof candidate.payload_format === "string" ? candidate.payload_format : null;
    const brandHint =
      typeof candidate.brand_hint === "string"
        ? candidate.brand_hint
        : typeof params.command.metadata?.brand_hint === "string"
          ? params.command.metadata.brand_hint
          : null;
    const modelHint =
      typeof candidate.model_hint === "string"
        ? candidate.model_hint
        : typeof params.command.metadata?.model_hint === "string"
          ? params.command.metadata.model_hint
          : null;
    const normalizedCandidate = normalizeIrPayload({
      protocol,
      frequencyHz: candidateFrequency,
      payload,
      payloadFormat
    });
    const rankRecords = await loadIrRankRecords(params.deviceId);
    const matches = rankIrMatches(normalizedCandidate, rankRecords, {
      brandHint,
      modelHint,
      topN: params.command.topN ?? 5
    });

    await writeAuditLog({
      deviceId: params.deviceId,
      userId: params.userId,
      action: "ws_ir_recognize_candidate",
      source: "ws_client",
      details: {
        candidate_fingerprint: normalizedCandidate.payloadFingerprint,
        top_n: params.command.topN ?? 5,
        result_count: matches.length
      }
    });

    return {
      ok: true,
      deviceUid: row.device_uid,
      latencyMs: 0,
      result: {
        candidate: {
          protocol_norm: normalizedCandidate.protocolNorm,
          frequency_norm_hz: normalizedCandidate.frequencyNormHz,
          payload_format: normalizedCandidate.payloadFormat,
          payload_fingerprint: normalizedCandidate.payloadFingerprint
        },
        matches
      }
    };
  }

  if (params.command.operation === "delete_code") {
    const codeId = params.command.codeId?.trim() ?? "";
    const codeName = params.command.codeName?.trim() ?? "";
    if (!codeId && !codeName) {
      return {
        ok: false,
        code: "validation_error",
        message: "code_id or code_name is required for delete_code."
      };
    }
    const removed = codeId
      ? await query(
        `DELETE FROM device_ir_codes
           WHERE device_id = $1
             AND id = $2`,
        [params.deviceId, codeId]
      )
      : await query(
        `DELETE FROM device_ir_codes
           WHERE device_id = $1
             AND code_name = $2`,
        [params.deviceId, codeName]
      );
    if (!removed.rowCount || removed.rowCount === 0) {
      return {
        ok: false,
        code: "not_found",
        message: "IR code not found."
      };
    }

    await writeAuditLog({
      deviceId: params.deviceId,
      userId: params.userId,
      action: "ws_ir_delete_code",
      source: "ws_client",
      details: {
        code_id: codeId || null,
        code_name: codeName || null
      }
    });

    void realtimeHub.sendToDevice(row.device_uid, {
      type: "ir_cache_sync",
      action: "delete",
      code_id: codeId || null,
      code_name: codeName || null,
      ts: nowIso()
    });

    return {
      ok: true,
      deviceUid: row.device_uid,
      latencyMs: 0
    };
  }

  let selectedCode: DeviceIrCodeRow | null = null;
  if (params.command.operation === "send_code") {
    const codeId = params.command.codeId?.trim() ?? "";
    const codeName = params.command.codeName?.trim() ?? "";
    if (!codeId && !codeName) {
      return {
        ok: false,
        code: "validation_error",
        message: "code_id or code_name is required for send_code."
      };
    }
    const loaded = codeId
      ? await query<DeviceIrCodeRow>(
        `SELECT
             id, device_id, owner_user_id, code_name, protocol, protocol_norm,
             frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
             source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
           FROM device_ir_codes
           WHERE device_id = $1
             AND id = $2
           LIMIT 1`,
        [params.deviceId, codeId]
      )
      : await query<DeviceIrCodeRow>(
        `SELECT
             id, device_id, owner_user_id, code_name, protocol, protocol_norm,
             frequency_hz, frequency_norm_hz, payload, payload_format, payload_fingerprint,
             source_type, source_ref, normalized_payload, metadata, learned_at, created_at, updated_at
           FROM device_ir_codes
           WHERE device_id = $1
             AND code_name = $2
           LIMIT 1`,
        [params.deviceId, codeName]
      );
    selectedCode = loaded.rows[0] ?? null;
    if (!selectedCode) {
      return {
        ok: false,
        code: "not_found",
        message: "IR code not found."
      };
    }
  }

  let learnedCode: DeviceIrCodeRow | null = null;
  if (params.command.operation === "learn_save" && params.command.candidate) {
    const candidate = params.command.candidate;
    const protocol = typeof candidate.protocol === "string" ? candidate.protocol.trim() : "";
    const payload = typeof candidate.payload === "string" ? candidate.payload : "";
    if (!protocol || !payload) {
      return {
        ok: false,
        code: "validation_error",
        message: "candidate.protocol and candidate.payload are required for learn_save."
      };
    }
    const frequency =
      typeof candidate.frequency_hz === "number" && Number.isInteger(candidate.frequency_hz)
        ? candidate.frequency_hz
        : null;
    const learnType =
      params.command.learnType ??
      parseIrLearnType((params.command.metadata as Record<string, unknown> | undefined)?.learn_type);
    const isAcLearn = learnType === "ac";
    const codeName = params.command.codeName?.trim() || `${isAcLearn ? "ac" : "learned"}-${nowIso()}`;
    learnedCode = await upsertDeviceIrCode({
      deviceId: params.deviceId,
      ownerUserId: row.owner_user_id,
      codeName,
      protocol,
      frequencyHz: frequency,
      payload,
      payloadFormat:
        typeof candidate.payload_format === "string" ? candidate.payload_format : "raw",
      sourceType: "device",
      sourceRef: isAcLearn ? "ws_learn_save_ac" : "ws_learn_save",
      metadata: {
        ...(asObject(candidate.metadata)),
        ...(params.command.metadata ?? {}),
        ...(learnType ? { learn_type: learnType } : {}),
        ...(isAcLearn ? { entity_kind: "ac_remote" } : {})
      }
    });
  }

  const commandId = newId();
  const pendingAck = realtimeHub.createPendingAck(commandId, row.device_uid, params.timeoutMs);
  const payload: Record<string, unknown> = {
    command_id: commandId,
    ts: nowIso()
  };

  if (params.command.operation === "learn_start") {
    payload.type = "ir_learn_start";
    payload.learn_type = params.command.learnType ?? "button";
    if (params.command.codeName) {
      payload.code_name = params.command.codeName;
    }
  } else if (params.command.operation === "learn_test") {
    payload.type = "ir_learn_test";
  } else if (params.command.operation === "learn_save") {
    payload.type = "ir_learn_save";
    if (learnedCode) {
      payload.code_id = learnedCode.id;
      payload.code_name = learnedCode.code_name;
    } else if (params.command.codeName) {
      payload.code_name = params.command.codeName;
    }
  } else if (params.command.operation === "learn_discard") {
    payload.type = "ir_learn_discard";
  } else if (params.command.operation === "send_code") {
    payload.type = "ir_send";
    payload.code_id = selectedCode?.id ?? params.command.codeId ?? null;
    payload.code_name = selectedCode?.code_name ?? params.command.codeName ?? null;
    payload.protocol = selectedCode?.protocol ?? null;
    payload.frequency_hz = selectedCode?.frequency_hz ?? null;
    payload.payload = selectedCode?.payload ?? null;
    payload.payload_format = selectedCode?.payload_format ?? null;
    payload.payload_fingerprint = selectedCode?.payload_fingerprint ?? null;
    payload.normalized_payload = selectedCode ? asObject(selectedCode.normalized_payload) : null;
    payload.metadata = selectedCode ? asObject(selectedCode.metadata) : null;
  } else {
    return {
      ok: false,
      code: "validation_error",
      message: "Unsupported IR operation."
    };
  }

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
        message: "Device rejected IR command.",
        details: {
          command_id: commandId,
          operation: params.command.operation
        }
      };
    }

    await writeAuditLog({
      deviceId: params.deviceId,
      userId: params.userId,
      action: `ws_ir_${params.command.operation}`,
      source: "ws_client",
      details: {
        command_id: commandId,
        code_id: selectedCode?.id ?? learnedCode?.id ?? null,
        code_name: selectedCode?.code_name ?? learnedCode?.code_name ?? params.command.codeName ?? null
      }
    });

    if (learnedCode) {
      void realtimeHub.sendToDevice(row.device_uid, {
        type: "ir_cache_sync",
        action: "upsert",
        code_id: learnedCode.id,
        code_name: learnedCode.code_name,
        payload_fingerprint: learnedCode.payload_fingerprint ?? null,
        ts: nowIso()
      });
    }

    return {
      ok: true,
      deviceUid: row.device_uid,
      latencyMs: ack.latencyMs,
      commandId,
      result: {
        code_id: selectedCode?.id ?? learnedCode?.id ?? null,
        code_name: selectedCode?.code_name ?? learnedCode?.code_name ?? params.command.codeName ?? null
      }
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

async function sendWifiConfigCommand(params: {
  userId: string;
  role: string;
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
  const isAdminActor = params.role === "admin";
  const lookup = isAdminActor
    ? await query<{ device_uid: string }>(
      `SELECT device_uid
         FROM devices
         WHERE id = $1
           AND is_active = TRUE
         LIMIT 1`,
      [params.deviceId]
    )
    : await query<{ device_uid: string }>(
      `SELECT device_uid
         FROM devices
         WHERE id = $1
           AND owner_user_id = $2
           AND is_active = TRUE
         LIMIT 1`,
      [params.deviceId, params.userId]
    );
  const row = lookup.rows[0];
  if (!row) {
    return isAdminActor
      ? {
        ok: false,
        code: "not_found",
        message: "Device not found or inactive."
      }
      : {
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

async function loadDeviceForConfigCommand(params: {
  userId: string;
  role: string;
  deviceId: string;
}): Promise<
  | { ok: true; row: DeviceConfigLookupRow }
  | {
    ok: false;
    code: string;
    message: string;
  }
> {
  const isAdminActor = params.role === "admin";
  const lookup = isAdminActor
    ? await query<DeviceConfigLookupRow>(
      `SELECT
           id, device_uid, is_active, relay_count, button_count, input_config, config
         FROM devices
         WHERE id = $1
         LIMIT 1`,
      [params.deviceId]
    )
    : await query<DeviceConfigLookupRow>(
      `SELECT
           id, device_uid, is_active, relay_count, button_count, input_config, config
         FROM devices
         WHERE id = $1
           AND owner_user_id = $2
         LIMIT 1`,
      [params.deviceId, params.userId]
    );
  const row = lookup.rows[0];
  if (!row) {
    return isAdminActor
      ? {
        ok: false,
        code: "not_found",
        message: "Device not found."
      }
      : {
        ok: false,
        code: "forbidden",
        message: "Only the device owner can control this device."
      };
  }
  if (!row.is_active) {
    return {
      ok: false,
      code: "device_inactive",
      message: "Device is inactive."
    };
  }
  return {
    ok: true,
    row
  };
}

async function sendConfigUpdateWithAck(params: {
  deviceUid: string;
  timeoutMs: number;
  payload: {
    io_config?: InputConfigRow[];
    connectivity?: ConnectivityUpdatePayload;
  };
}): Promise<
  | { ok: true; commandId: string; latencyMs: number }
  | { ok: false; code: string; message: string; details?: Record<string, unknown> }
> {
  const commandId = newId();
  const pendingAck = realtimeHub.createPendingAck(commandId, params.deviceUid, params.timeoutMs);
  const sent = realtimeHub.sendToDevice(params.deviceUid, {
    type: "config_update",
    command_id: commandId,
    ...params.payload,
    ts: nowIso()
  });
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
        message: "Device rejected configuration update.",
        details: {
          command_id: commandId
        }
      };
    }
    return {
      ok: true,
      commandId,
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

async function sendDeviceConfigCommand(params: {
  userId: string;
  role: string;
  deviceId: string;
  command: ClientConfigCommand;
  timeoutMs: number;
}): Promise<
  | {
    ok: true;
    deviceUid: string;
    latencyMs: number;
    commandId: string;
    inputConfig?: InputConfigRow[];
    config?: Record<string, unknown>;
  }
  | {
    ok: false;
    code: string;
    message: string;
    details?: Record<string, unknown>;
  }
> {
  const loaded = await loadDeviceForConfigCommand(params);
  if (!loaded.ok) {
    return loaded;
  }
  const row = loaded.row;

  let nextInputConfig: InputConfigRow[] | undefined;
  let nextConfig: Record<string, unknown> | undefined;
  let outboundPayload: {
    io_config?: InputConfigRow[];
    connectivity?: ConnectivityUpdatePayload;
  } = {};

  if (params.command.scope === "button_mode") {
    const current = normalizeInputConfigRows(row.input_config, row.button_count, row.relay_count);
    const currentRow = current[params.command.buttonIndex];
    if (!currentRow) {
      return {
        ok: false,
        code: "validation_error",
        message: "button_index is outside device button range."
      };
    }

    const mode = params.command.mode;
    currentRow.input_type = mode === "push_button" ? "push_button" : "rocker_switch";
    if (mode === "push_button") {
      currentRow.rocker_mode = null;
    } else if (mode === "rocker_switch_follow") {
      currentRow.rocker_mode = "follow_position";
      currentRow.hold_seconds = null;
    } else {
      currentRow.rocker_mode = "edge_toggle";
      currentRow.hold_seconds = null;
    }

    if (currentRow.linked) {
      if (!Number.isInteger(currentRow.target_relay_index)) {
        currentRow.target_relay_index =
          row.relay_count > 0 ? Math.min(params.command.buttonIndex, row.relay_count - 1) : null;
      }
    }

    try {
      nextInputConfig = validateInputConfigMatrix(
        {
          buttonCount: row.button_count,
          relayCount: row.relay_count
        },
        current
      );
    } catch (error) {
      return {
        ok: false,
        code: "validation_error",
        message: normalizeInputConfigError(error as Error)
      };
    }
    outboundPayload = {
      io_config: nextInputConfig
    };
  } else if (params.command.scope === "button_link") {
    const current = normalizeInputConfigRows(row.input_config, row.button_count, row.relay_count);
    const currentRow = current[params.command.buttonIndex];
    if (!currentRow) {
      return {
        ok: false,
        code: "validation_error",
        message: "button_index is outside device button range."
      };
    }

    currentRow.linked = params.command.linked;
    if (!params.command.linked) {
      currentRow.target_relay_index = null;
    } else if (!Number.isInteger(currentRow.target_relay_index)) {
      currentRow.target_relay_index =
        row.relay_count > 0 ? Math.min(params.command.buttonIndex, row.relay_count - 1) : null;
    }

    try {
      nextInputConfig = validateInputConfigMatrix(
        {
          buttonCount: row.button_count,
          relayCount: row.relay_count
        },
        current
      );
    } catch (error) {
      return {
        ok: false,
        code: "validation_error",
        message: normalizeInputConfigError(error as Error)
      };
    }
    outboundPayload = {
      io_config: nextInputConfig
    };
  } else if (params.command.scope === "ha_config") {
    nextConfig = cloneConfig(row.config);
    const connectivity = asRecord(nextConfig.connectivity) ?? {};
    const mqtt = asRecord(connectivity.mqtt) ?? {};
    mqtt.show_config = params.command.showConfig;
    connectivity.mqtt = mqtt;
    nextConfig.connectivity = connectivity;
    outboundPayload = {
      connectivity: {
        mqtt: {
          show_config: params.command.showConfig
        }
      }
    };
  } else {
    nextConfig = cloneConfig(row.config);
    const connectivity = asRecord(nextConfig.connectivity) ?? {};
    connectivity.mode = params.command.mode;
    nextConfig.connectivity = connectivity;
    outboundPayload = {
      connectivity: {
        mode: params.command.mode
      }
    };
  }

  const ackResult = await sendConfigUpdateWithAck({
    deviceUid: row.device_uid,
    timeoutMs: params.timeoutMs,
    payload: outboundPayload
  });
  if (!ackResult.ok) {
    return ackResult;
  }

  const updates: string[] = [];
  const values: unknown[] = [];
  if (nextInputConfig) {
    values.push(JSON.stringify(nextInputConfig));
    updates.push(`input_config = $${values.length}::jsonb`);
  }
  if (nextConfig) {
    values.push(JSON.stringify(nextConfig));
    updates.push(`config = $${values.length}::jsonb`);
  }
  values.push(nowIso());
  updates.push(`updated_at = $${values.length}`);
  values.push(row.id);
  const idPos = values.length;

  await query(
    `UPDATE devices
     SET ${updates.join(", ")}
     WHERE id = $${idPos}`,
    values
  );

  return {
    ok: true,
    deviceUid: row.device_uid,
    latencyMs: ackResult.latencyMs,
    commandId: ackResult.commandId,
    inputConfig: nextInputConfig,
    config: nextConfig
  };
}

async function sendDeviceControlCommand(params: {
  userId: string;
  role: string;
  deviceId: string;
  operation: "reboot" | "factory_reset";
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
  const isAdminActor = params.role === "admin";
  const lookup = isAdminActor
    ? await query<{ device_uid: string; is_active: boolean }>(
      `SELECT device_uid, is_active
         FROM devices
         WHERE id = $1
         LIMIT 1`,
      [params.deviceId]
    )
    : await query<{ device_uid: string; is_active: boolean }>(
      `SELECT device_uid, is_active
         FROM devices
         WHERE id = $1
           AND owner_user_id = $2
         LIMIT 1`,
      [params.deviceId, params.userId]
    );
  const row = lookup.rows[0];
  if (!row) {
    return isAdminActor
      ? {
        ok: false,
        code: "not_found",
        message: "Device not found."
      }
      : {
        ok: false,
        code: "forbidden",
        message: "Only the device owner can control this device."
      };
  }
  if (!row.is_active) {
    return {
      ok: false,
      code: "device_inactive",
      message: "Device is inactive."
    };
  }

  const commandId = newId();
  const pendingAck = realtimeHub.createPendingAck(commandId, row.device_uid, params.timeoutMs);
  const payload = {
    type: "device_control",
    command_id: commandId,
    operation: params.operation,
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
        message: "Device rejected control command.",
        details: {
          command_id: commandId,
          operation: params.operation
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

async function sendOtaControlCommand(params: {
  userId: string;
  role: string;
  deviceId: string;
  operation: "check" | "install";
  channel?: OtaChannel;
  timeoutMs: number;
}): Promise<
  | {
    ok: true;
    deviceUid: string;
    latencyMs: number;
    updateAvailable: boolean;
    transferId?: string;
    targetVersion?: string;
  }
  | {
    ok: false;
    code: string;
    message: string;
    details?: Record<string, unknown>;
  }
> {
  const isAdminActor = params.role === "admin";
  const lookup = isAdminActor
    ? await query<DeviceOtaLookupRow>(
      `SELECT device_uid, is_active
                , id, model, firmware_version, ota_channel, ota_security_version
         FROM devices
         WHERE id = $1
         LIMIT 1`,
      [params.deviceId]
    )
    : await query<DeviceOtaLookupRow>(
      `SELECT device_uid, is_active
                , id, model, firmware_version, ota_channel, ota_security_version
         FROM devices
         WHERE id = $1
           AND owner_user_id = $2
         LIMIT 1`,
      [params.deviceId, params.userId]
    );
  const row = lookup.rows[0];
  if (!row) {
    return isAdminActor
      ? {
        ok: false,
        code: "not_found",
        message: "Device not found."
      }
      : {
        ok: false,
        code: "forbidden",
        message: "Only the device owner can control this device."
      };
  }
  if (!row.is_active) {
    return {
      ok: false,
      code: "device_inactive",
      message: "Device is inactive."
    };
  }

  if (params.operation === "install" && activeOtaStreams.has(row.device_uid)) {
    return {
      ok: false,
      code: "ota_in_progress",
      message: "An OTA transfer is already active for this device."
    };
  }

  const channel = params.channel ?? row.ota_channel;
  const resolved = await resolveOtaReleaseForDevice({
    model: row.model,
    channel,
    currentVersion: row.firmware_version,
    minimumSecurityVersion: asNonNegativeInt(row.ota_security_version)
  });

  if (!resolved) {
    if (params.operation === "check") {
      return {
        ok: true,
        deviceUid: row.device_uid,
        latencyMs: 0,
        updateAvailable: false
      };
    }
    return {
      ok: false,
      code: "manifest_not_found",
      message: "No eligible OTA release for this device/channel."
    };
  }

  const commandId = newId();
  const transferId = params.operation === "install" ? newId() : undefined;
  const pendingAck = realtimeHub.createPendingAck(commandId, row.device_uid, params.timeoutMs);
  const payload = {
    type: "ota_control",
    command_id: commandId,
    operation: params.operation,
    channel,
    transfer_id: transferId,
    manifest: resolved.manifest,
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
        message: "Device rejected OTA command.",
        details: {
          command_id: commandId,
          operation: params.operation,
          channel: params.channel ?? null
        }
      };
    }

    if (params.operation === "install" && transferId) {
      activeOtaStreams.add(row.device_uid);
      void streamOtaArtifactOverWs({
        deviceUid: row.device_uid,
        transferId,
        artifactPath: resolved.artifactPath,
        timeoutMs: OTA_WS_CHUNK_ACK_TIMEOUT_MS
      })
        .catch(async (error) => {
          const reason =
            error instanceof Error && error.message.trim().length > 0
              ? error.message.trim()
              : "ws_transfer_failed";
          await sendOtaAbort(row.device_uid, transferId, reason);
        })
        .finally(() => {
          activeOtaStreams.delete(row.device_uid);
        });
    }

    return {
      ok: true,
      deviceUid: row.device_uid,
      latencyMs: ack.latencyMs,
      updateAvailable: true,
      transferId,
      targetVersion: resolved.manifest.version
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
    if (
      error instanceof Error &&
      (error.message === "device_disconnected" || error.message === "device_offline")
    ) {
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

function normalizeReportedFirmwareVersion(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  return semver.valid(trimmed);
}

async function updateLastSeenAndFirmware(deviceId: string, ip: string, firmwareVersion: string | null): Promise<void> {
  if (!firmwareVersion) {
    await updateLastSeen(deviceId, ip);
    return;
  }

  try {
    await query(
      `UPDATE devices
       SET last_seen_at = $1,
           last_ip = $2,
           firmware_version = $4,
           updated_at = $1
       WHERE id = $3`,
      [nowIso(), ip, deviceId, firmwareVersion]
    );
  } catch {
    // Keep WS session healthy even if firmware_version column is unavailable.
    await updateLastSeen(deviceId, ip);
  }
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
  let token = url.searchParams.get("token")?.trim();
  if (!token) {
    const rawAuthHeader = req.headers.authorization;
    const authHeader = Array.isArray(rawAuthHeader) ? rawAuthHeader[0] : rawAuthHeader;
    if (typeof authHeader === "string") {
      const match = authHeader.match(/^Bearer\s+(.+)$/i);
      if (match && match[1]) {
        token = match[1].trim();
      }
    }
  }

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

  const markAlive = () => {
    alive = true;
    missedPongs = 0;
  };

  socket.on("pong", () => {
    markAlive();
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
    void deviceFallbackSyncService.syncDeviceFallback(row.id).catch(() => undefined);

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
          socket.close(1011, "heartbeat_timeout");
          return;
        }
      } else {
        missedPongs = 0;
      }

      alive = false;
      try {
        socket.ping();
      } catch {
        socket.close(1011, "heartbeat_ping_failed");
      }
    }, DEVICE_WS_HEARTBEAT_INTERVAL_MS);
  })().catch(() => {
    socket.close(1011, "auth_error");
  });

  socket.on("message", (raw: unknown) => {
    // Treat any inbound message as socket liveness to avoid false
    // disconnects when control ping/pong is delayed by transient jitter.
    markAlive();

    if (!authenticated || !deviceUid || !deviceId) {
      return;
    }

    const parsed = parseMessage(raw);
    if (!parsed || typeof parsed !== "object") {
      return;
    }

    const message = parsed as Record<string, unknown>;
    const type = typeof message.type === "string" ? message.type : "";

    if (type === "state_report") {
      void (async () => {
        const reportedFirmwareVersion = normalizeReportedFirmwareVersion(message.firmware_version);
        await updateLastSeenAndFirmware(deviceId, req.socket.remoteAddress ?? "", reportedFirmwareVersion);

        const relays = Array.isArray(message.relays)
          ? message.relays
            .map((item) => asBooleanLike(item))
            .filter((item): item is boolean => item !== null)
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

    if (
      type === "ir_learn_state" ||
      type === "ir_learn_candidate" ||
      type === "ir_send_result" ||
      type === "ir_cache_status"
    ) {
      void updateLastSeen(deviceId, req.socket.remoteAddress ?? "").catch(() => undefined);

      void (async () => {
        const owner = await readOwnerUserId(deviceId);
        ownerUserId = owner;
        const outbound: Record<string, unknown> = {
          ...message,
          device_uid: deviceUid
        };

        const messageMeta = asObject(message.metadata);
        const candidateRaw = asRecord(message.candidate) ?? asRecord(message);
        const candidateProtocol =
          typeof candidateRaw?.protocol === "string" ? candidateRaw.protocol.trim() : "";
        const candidatePayload =
          typeof candidateRaw?.payload === "string" ? candidateRaw.payload : "";
        const candidateFrequency =
          typeof candidateRaw?.frequency_hz === "number" && Number.isInteger(candidateRaw.frequency_hz)
            ? candidateRaw.frequency_hz
            : null;
        const candidatePayloadFormat =
          typeof candidateRaw?.payload_format === "string" ? candidateRaw.payload_format : "raw";

        if (type === "ir_learn_candidate" && candidateProtocol && candidatePayload && env.IR_AUTOREC_ENABLED) {
          const normalizedCandidate = normalizeIrPayload({
            protocol: candidateProtocol,
            frequencyHz: candidateFrequency,
            payload: candidatePayload,
            payloadFormat: candidatePayloadFormat
          });
          const records = await loadIrRankRecords(deviceId);
          const matches = rankIrMatches(normalizedCandidate, records, {
            brandHint:
              typeof candidateRaw?.brand_hint === "string"
                ? candidateRaw.brand_hint
                : typeof messageMeta.brand_hint === "string"
                  ? messageMeta.brand_hint
                  : null,
            modelHint:
              typeof candidateRaw?.model_hint === "string"
                ? candidateRaw.model_hint
                : typeof messageMeta.model_hint === "string"
                  ? messageMeta.model_hint
                  : null,
            topN:
              typeof message.top_n === "number" && Number.isInteger(message.top_n)
                ? Math.min(Math.max(message.top_n, 1), 20)
                : 5
          });
          outbound.candidate = {
            protocol_norm: normalizedCandidate.protocolNorm,
            frequency_norm_hz: normalizedCandidate.frequencyNormHz,
            payload_format: normalizedCandidate.payloadFormat,
            payload_fingerprint: normalizedCandidate.payloadFingerprint
          };
          outbound.recognition = {
            matches
          };
        }

        if (type === "ir_learn_state") {
          const learnState =
            typeof message.state === "string"
              ? message.state.trim().toLowerCase()
              : "";
          if (learnState === "saved" && candidateProtocol && candidatePayload) {
            const codeNameRaw =
              typeof message.code_name === "string"
                ? message.code_name
                : typeof candidateRaw?.code_name === "string"
                  ? candidateRaw.code_name
                  : `learned-${nowIso()}`;

            const savedCode = await upsertDeviceIrCode({
              deviceId,
              ownerUserId: owner,
              codeName: codeNameRaw,
              protocol: candidateProtocol,
              frequencyHz: candidateFrequency,
              payload: candidatePayload,
              payloadFormat: candidatePayloadFormat,
              sourceType: "device",
              sourceRef: "device_learn_state_saved",
              metadata: {
                ...asObject(candidateRaw?.metadata),
                ...messageMeta
              }
            });
            outbound.saved_code = {
              id: savedCode.id,
              code_name: savedCode.code_name,
              payload_fingerprint: savedCode.payload_fingerprint
            };
          }
        }

        await writeAuditLog({
          deviceId,
          action: `${type}_report`,
          source: "device",
          details: outbound
        });

        broadcastDeviceEvent(owner, outbound);
      })().catch(() => undefined);
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

        void persistOtaStatusFromWs({
          deviceId,
          message
        }).catch(() => undefined);
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
  let authedUserRole: string | null = null;

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
          authedUserRole = payload.role;
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
    } else if (scope === "button_mode") {
      const buttonIndex =
        typeof message.button_index === "number"
          ? message.button_index
          : typeof message.input_index === "number"
            ? message.input_index
            : Number.NaN;
      if (!Number.isInteger(buttonIndex) || buttonIndex < 0) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "button_index must be a non-negative integer.",
          request_id: requestId
        });
        return;
      }
      const modeRaw =
        (typeof message.mode === "string" ? message.mode : null) ??
        (typeof message.action === "string" ? message.action : null) ??
        "";
      const mode = parseButtonMode(modeRaw);
      if (!mode) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "mode must be one of: push_button, rocker_switch, rocker_switch_follow.",
          request_id: requestId
        });
        return;
      }
      command = {
        scope: "button_mode",
        buttonIndex,
        mode
      };
    } else if (scope === "button_link") {
      const buttonIndex =
        typeof message.button_index === "number"
          ? message.button_index
          : typeof message.input_index === "number"
            ? message.input_index
            : Number.NaN;
      if (!Number.isInteger(buttonIndex) || buttonIndex < 0) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "button_index must be a non-negative integer.",
          request_id: requestId
        });
        return;
      }
      const linked =
        asBooleanLike(message.linked) ??
        asBooleanLike(message.state) ??
        asBooleanLike(message.action);
      if (linked === null) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "linked must be a boolean or on/off value.",
          request_id: requestId
        });
        return;
      }
      command = {
        scope: "button_link",
        buttonIndex,
        linked
      };
    } else if (scope === "ha_config") {
      const showConfig =
        asBooleanLike(message.show_config) ??
        asBooleanLike(message.showConfig) ??
        asBooleanLike(message.state) ??
        asBooleanLike(message.action);
      if (showConfig === null) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "show_config must be a boolean or on/off value.",
          request_id: requestId
        });
        return;
      }
      command = {
        scope: "ha_config",
        showConfig
      };
    } else if (scope === "connectivity_mode") {
      const modeFromField = parseConnectivityMode(message.mode);
      const modeFromAction = (() => {
        const boolAction = asBooleanLike(message.action);
        if (boolAction === null) {
          return null;
        }
        return boolAction ? "cloud_ws" : "local_mqtt";
      })();
      const mode = modeFromField ?? modeFromAction;
      if (!mode) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "mode must be cloud_ws|local_mqtt or action on/off.",
          request_id: requestId
        });
        return;
      }
      command = {
        scope: "connectivity_mode",
        mode
      };
    } else if (scope === "ir") {
      const operation = parseIrOperation(
        (typeof message.operation === "string" ? message.operation : null) ??
        (typeof message.action === "string" ? message.action : null) ??
        ""
      );
      if (!operation) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message:
            "operation must be learn_start|learn_test|learn_save|learn_discard|send_code|delete_code|recognize_candidate.",
          request_id: requestId
        });
        return;
      }

      const codeId =
        typeof message.code_id === "string"
          ? message.code_id.trim()
          : typeof message.ir_code_id === "string"
            ? message.ir_code_id.trim()
            : "";
      const codeName =
        typeof message.code_name === "string"
          ? message.code_name.trim()
          : typeof message.name === "string"
            ? message.name.trim()
            : "";
      const candidate = asRecord(message.candidate);
      const metadata = asRecord(message.metadata) ?? {};
      const learnType =
        parseIrLearnType(message.learn_type) ??
        parseIrLearnType(message.learnType) ??
        parseIrLearnType(message.mode);
      const topN =
        typeof message.top_n === "number" && Number.isInteger(message.top_n)
          ? Math.min(Math.max(message.top_n, 1), 20)
          : undefined;

      if ((operation === "send_code" || operation === "delete_code") && !codeId && !codeName) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "code_id or code_name is required.",
          request_id: requestId
        });
        return;
      }

      if (operation === "recognize_candidate" && !candidate) {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "candidate is required for recognize_candidate.",
          request_id: requestId
        });
        return;
      }

      command = {
        scope: "ir",
        operation,
        learnType,
        codeId: codeId || undefined,
        codeName: codeName || undefined,
        candidate: candidate ?? undefined,
        metadata,
        topN
      };
    } else if (scope === "ota") {
      const operationRaw =
        (typeof message.operation === "string" ? message.operation : null) ??
        (typeof message.action === "string" ? message.action : null) ??
        "";
      const operation = operationRaw.trim().toLowerCase();
      if (operation !== "check" && operation !== "install") {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "operation must be check or install for ota scope.",
          request_id: requestId
        });
        return;
      }

      const channelRaw = typeof message.channel === "string" ? message.channel.trim().toLowerCase() : "";
      if (channelRaw && channelRaw !== "dev" && channelRaw !== "beta" && channelRaw !== "stable") {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "channel must be one of: dev, beta, stable.",
          request_id: requestId
        });
        return;
      }

      command = {
        scope: "ota",
        operation,
        channel: channelRaw ? (channelRaw as OtaChannel) : undefined
      };
    } else if (scope === "device") {
      const operationRaw =
        (typeof message.operation === "string" ? message.operation : null) ??
        (typeof message.action === "string" ? message.action : null) ??
        "";
      const operation = operationRaw.trim().toLowerCase();
      if (operation === "reboot" || operation === "restart") {
        command = {
          scope: "device",
          operation: "reboot"
        };
      } else if (
        operation === "factory_reset" ||
        operation === "factory-reset" ||
        operation === "factory" ||
        operation === "reset_factory"
      ) {
        command = {
          scope: "device",
          operation: "factory_reset"
        };
      } else {
        sendJson(socket, {
          type: "cmd_ack",
          ok: false,
          code: "validation_error",
          message: "operation must be reboot or factory_reset for device scope.",
          request_id: requestId
        });
        return;
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
    const actorRole = authedUserRole ?? "user";
    const accepted = enqueueDeviceCommand(deviceId, async () => {
      try {
        const permitted = actorRole === "admin"
          ? true
          : await isDeviceOwner(actorUserId, deviceId);
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
            role: actorRole,
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

        if (command.scope === "device") {
          const deviceControlResult = await sendDeviceControlCommand({
            userId: actorUserId,
            role: actorRole,
            deviceId,
            operation: command.operation,
            timeoutMs: timeoutMs ?? DEVICE_CONTROL_COMMAND_TIMEOUT_MS
          });
          if (!deviceControlResult.ok) {
            sendJson(socket, {
              type: "cmd_ack",
              ok: false,
              code: deviceControlResult.code,
              message: deviceControlResult.message,
              details: deviceControlResult.details ?? null,
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
              device_uid: deviceControlResult.deviceUid,
              scope: "device",
              operation: command.operation,
              latency_ms: deviceControlResult.latencyMs
            }
          });
          return;
        }

        if (command.scope === "ota") {
          const otaControlResult = await sendOtaControlCommand({
            userId: actorUserId,
            role: actorRole,
            deviceId,
            operation: command.operation,
            channel: command.channel,
            timeoutMs: timeoutMs ?? OTA_CONTROL_COMMAND_TIMEOUT_MS
          });
          if (!otaControlResult.ok) {
            sendJson(socket, {
              type: "cmd_ack",
              ok: false,
              code: otaControlResult.code,
              message: otaControlResult.message,
              details: otaControlResult.details ?? null,
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
              device_uid: otaControlResult.deviceUid,
              scope: "ota",
              operation: command.operation,
              channel: command.channel ?? null,
              latency_ms: otaControlResult.latencyMs,
              update_available: otaControlResult.updateAvailable,
              transfer_id: otaControlResult.transferId ?? null,
              target_version: otaControlResult.targetVersion ?? null
            }
          });
          return;
        }

        if (command.scope === "ir") {
          const irControlResult = await sendIrControlCommand({
            userId: actorUserId,
            role: actorRole,
            deviceId,
            command,
            timeoutMs: timeoutMs ?? IR_CONTROL_COMMAND_TIMEOUT_MS
          });
          if (!irControlResult.ok) {
            sendJson(socket, {
              type: "cmd_ack",
              ok: false,
              code: irControlResult.code,
              message: irControlResult.message,
              details: irControlResult.details ?? null,
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
              device_uid: irControlResult.deviceUid,
              scope: "ir",
              operation: command.operation,
              command_id: irControlResult.commandId ?? null,
              latency_ms: irControlResult.latencyMs,
              ...(irControlResult.result ?? {})
            }
          });
          return;
        }

        if (
          command.scope === "button_mode" ||
          command.scope === "button_link" ||
          command.scope === "ha_config" ||
          command.scope === "connectivity_mode"
        ) {
          const configCommandResult = await sendDeviceConfigCommand({
            userId: actorUserId,
            role: actorRole,
            deviceId,
            command,
            timeoutMs: timeoutMs ?? WIFI_CONFIG_COMMAND_TIMEOUT_MS
          });
          if (!configCommandResult.ok) {
            sendJson(socket, {
              type: "cmd_ack",
              ok: false,
              code: configCommandResult.code,
              message: configCommandResult.message,
              details: configCommandResult.details ?? null,
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
              device_uid: configCommandResult.deviceUid,
              scope: command.scope,
              command_id: configCommandResult.commandId,
              latency_ms: configCommandResult.latencyMs,
              button_index:
                command.scope === "button_mode" || command.scope === "button_link"
                  ? command.buttonIndex
                  : null,
              mode:
                command.scope === "button_mode"
                  ? command.mode
                  : command.scope === "connectivity_mode"
                    ? command.mode
                    : null,
              linked: command.scope === "button_link" ? command.linked : null,
              show_config: command.scope === "ha_config" ? command.showConfig : null
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
