import { readFileSync } from "node:fs";
import { query } from "../db/connection";
import { env } from "../config/env";
import { deviceStateCache } from "./device-state-cache";

type LoggerLike = {
  info: (obj: unknown, msg?: string) => void;
  warn: (obj: unknown, msg?: string) => void;
  error: (obj: unknown, msg?: string) => void;
};

type DeviceRelayRow = {
  device_id: string;
  device_uid: string;
  device_name: string;
  owner_user_id: string | null;
  model: string;
  relay_count: number;
  relay_index: number;
  relay_name: string;
  is_on: boolean;
};

type DeviceDescriptor = {
  id: string;
  uid: string;
  name: string;
  ownerUserId: string | null;
  model: string;
  relayCount: number;
};

type CommandRequest = {
  deviceId: string;
  scope: "single" | "all";
  relayIndex?: number;
  action: "on" | "off" | "toggle";
  source: "homekit" | "ha";
  actorUserId?: string;
};

type CommandExecutor = (request: CommandRequest) => Promise<void>;

type MqttClientLike = {
  connected: boolean;
  on: (event: string, listener: (...args: unknown[]) => void) => void;
  publish: (
    topic: string,
    payload: string,
    options?: { retain?: boolean; qos?: 0 | 1 | 2 }
  ) => void;
  subscribe: (
    topic: string,
    options?: { qos?: 0 | 1 | 2 },
    callback?: (error: Error | null) => void
  ) => void;
  end: (force?: boolean, callback?: () => void) => void;
};

type MqttConnectOptions = {
  clientId: string;
  username?: string;
  password?: string;
  clean: boolean;
  reconnectPeriod: number;
  keepalive: number;
  connectTimeout: number;
  rejectUnauthorized: boolean;
  ca?: Buffer;
  cert?: Buffer;
  key?: Buffer;
  passphrase?: string;
  servername?: string;
};

type MqttModuleLike = {
  connect: (url: string, options: MqttConnectOptions) => MqttClientLike;
};

type HapModule = {
  uuid: {
    generate: (input: string) => string;
  };
  HAPStorage: {
    setCustomStoragePath: (path: string) => void;
  };
  Categories: {
    BRIDGE: number;
    SWITCH: number;
  };
  Characteristic: {
    On: unknown;
    Name: unknown;
    Manufacturer: unknown;
    Model: unknown;
    SerialNumber: unknown;
    FirmwareRevision: unknown;
  };
  Service: {
    AccessoryInformation: new (...args: unknown[]) => unknown;
    Switch: new (...args: unknown[]) => unknown;
  };
  Accessory: new (...args: unknown[]) => {
    category: number;
    addService: (service: unknown, name?: string, subtype?: string) => {
      setCharacteristic: (characteristic: unknown, value: unknown) => unknown;
      getCharacteristic: (characteristic: unknown) => {
        onGet: (handler: () => unknown) => void;
        onSet: (handler: (value: unknown) => Promise<void>) => void;
        updateValue: (value: unknown) => void;
      };
    };
    getService: (service: unknown) => {
      setCharacteristic: (characteristic: unknown, value: unknown) => unknown;
    } | undefined;
  };
  Bridge: new (...args: unknown[]) => {
    addBridgedAccessory: (accessory: unknown) => void;
    removeBridgedAccessory: (accessory: unknown, deferUpdate?: boolean) => void;
    publish: (payload: {
      username: string;
      port: number;
      pincode: string;
      category: number;
      setupID: string;
    }) => void;
    unpublish: () => void;
  };
};

type HomekitRelayMapping = {
  key: string;
  deviceId: string;
  deviceUid: string;
  relayIndex: number;
  relayName: string;
  ownerUserId: string | null;
  accessory: unknown;
  characteristic: {
    updateValue: (value: unknown) => void;
  };
};

function relayKey(deviceId: string, relayIndex: number): string {
  return `${deviceId}:${relayIndex}`;
}

function parseMqttBool(payload: string): "on" | "off" | "toggle" | null {
  const normalized = payload.trim().toUpperCase();
  if (normalized === "ON" || normalized === "1" || normalized === "TRUE") {
    return "on";
  }
  if (normalized === "OFF" || normalized === "0" || normalized === "FALSE") {
    return "off";
  }
  if (normalized === "TOGGLE") {
    return "toggle";
  }
  return null;
}

class SmartHomeService {
  private logger: LoggerLike | null = null;
  private commandExecutor: CommandExecutor | null = null;
  private readonly descriptorsById = new Map<string, DeviceDescriptor>();
  private readonly descriptorsByUid = new Map<string, DeviceDescriptor>();
  private readonly relayNameByKey = new Map<string, string>();

  private homekitLoaded = false;
  private hap: HapModule | null = null;
  private homekitBridge: InstanceType<HapModule["Bridge"]> | null = null;
  private readonly homekitByKey = new Map<string, HomekitRelayMapping>();

  private mqttLoaded = false;
  private mqttClient: MqttClientLike | null = null;

  setCommandExecutor(executor: CommandExecutor): void {
    this.commandExecutor = executor;
  }

  async start(logger: LoggerLike): Promise<void> {
    this.logger = logger;
    await this.primeDeviceStateCache();
    await this.startHomekit();
    await this.startMqtt();
  }

  async stop(): Promise<void> {
    if (this.homekitBridge) {
      try {
        this.homekitBridge.unpublish();
      } catch {
        // Ignore shutdown unpublish errors.
      }
      this.homekitBridge = null;
      this.homekitByKey.clear();
    }

    if (this.mqttClient) {
      await new Promise<void>((resolve) => {
        this.mqttClient?.end(false, () => resolve());
      });
      this.mqttClient = null;
    }
  }

  async setDeviceAvailability(deviceUid: string, online: boolean): Promise<void> {
    const descriptor = this.descriptorsByUid.get(deviceUid) ?? (await this.loadDeviceDescriptorByUid(deviceUid));
    if (!descriptor) {
      return;
    }
    this.publishMqttAvailability(descriptor.uid, online);
  }

  async syncRelayChanges(params: {
    deviceId: string;
    deviceUid: string;
    ownerUserId: string | null;
    relayCount: number;
    relays: Array<{ relayIndex: number; isOn: boolean }>;
    updatedAt: string;
  }): Promise<void> {
    const current = deviceStateCache.patchRelayStates({
      deviceId: params.deviceId,
      deviceUid: params.deviceUid,
      ownerUserId: params.ownerUserId,
      relayCount: params.relayCount,
      relays: params.relays,
      updatedAt: params.updatedAt
    });

    await this.ensureDeviceRegistered(params.deviceId);

    for (const relay of params.relays) {
      this.updateHomekitRelayState(params.deviceId, relay.relayIndex, relay.isOn);
      this.publishMqttRelayState(params.deviceUid, relay.relayIndex, relay.isOn);
    }
    this.publishMqttAvailability(params.deviceUid, true);

    // Keep full state cached for integrations that require full snapshot reads.
    deviceStateCache.setAllRelayStates({
      deviceId: params.deviceId,
      deviceUid: params.deviceUid,
      ownerUserId: params.ownerUserId,
      relays: current,
      updatedAt: params.updatedAt
    });
  }

  async syncRelaySnapshot(params: {
    deviceId: string;
    deviceUid: string;
    ownerUserId: string | null;
    relays: boolean[];
    updatedAt: string;
  }): Promise<void> {
    deviceStateCache.setAllRelayStates({
      deviceId: params.deviceId,
      deviceUid: params.deviceUid,
      ownerUserId: params.ownerUserId,
      relays: params.relays,
      updatedAt: params.updatedAt
    });

    await this.ensureDeviceRegistered(params.deviceId);

    for (let i = 0; i < params.relays.length; i += 1) {
      this.updateHomekitRelayState(params.deviceId, i, params.relays[i]);
      this.publishMqttRelayState(params.deviceUid, i, params.relays[i]);
    }
    this.publishMqttAvailability(params.deviceUid, true);
  }

  getRelayState(deviceUid: string, relayIndex: number): boolean | null {
    return deviceStateCache.getRelayState(deviceUid, relayIndex);
  }

  private async primeDeviceStateCache(): Promise<void> {
    const rows = await this.fetchDeviceRelayRows();
    const grouped = new Map<string, DeviceRelayRow[]>();

    for (const row of rows) {
      const key = row.device_id;
      const list = grouped.get(key) ?? [];
      list.push(row);
      grouped.set(key, list);
    }

    for (const [, list] of grouped) {
      list.sort((a, b) => a.relay_index - b.relay_index);
      const first = list[0];
      const relays = list.map((item) => item.is_on);
      const updatedAt = new Date().toISOString();
      deviceStateCache.setAllRelayStates({
        deviceId: first.device_id,
        deviceUid: first.device_uid,
        ownerUserId: first.owner_user_id,
        relays,
        updatedAt
      });
      this.indexDescriptor(first);
      for (const row of list) {
        this.relayNameByKey.set(relayKey(row.device_id, row.relay_index), row.relay_name);
      }
    }
  }

  private indexDescriptor(row: {
    device_id: string;
    device_uid: string;
    device_name: string;
    owner_user_id: string | null;
    model: string;
    relay_count: number;
  }): void {
    const descriptor: DeviceDescriptor = {
      id: row.device_id,
      uid: row.device_uid,
      name: row.device_name,
      ownerUserId: row.owner_user_id,
      model: row.model,
      relayCount: row.relay_count
    };
    this.descriptorsById.set(descriptor.id, descriptor);
    this.descriptorsByUid.set(descriptor.uid, descriptor);
  }

  private async ensureDeviceRegistered(deviceId: string): Promise<void> {
    if (this.descriptorsById.has(deviceId)) {
      return;
    }

    const rows = await this.fetchDeviceRelayRows(deviceId);
    for (const row of rows) {
      this.indexDescriptor(row);
      this.relayNameByKey.set(relayKey(row.device_id, row.relay_index), row.relay_name);
      this.ensureHomekitRelay(row);
      this.publishMqttDiscovery(row);
    }
  }

  private async loadDeviceDescriptorByUid(deviceUid: string): Promise<DeviceDescriptor | null> {
    const rows = await this.fetchDeviceRelayRows(undefined, deviceUid);
    const row = rows[0];
    if (!row) {
      return null;
    }

    this.indexDescriptor(row);
    for (const entry of rows) {
      this.relayNameByKey.set(relayKey(entry.device_id, entry.relay_index), entry.relay_name);
      this.ensureHomekitRelay(entry);
      this.publishMqttDiscovery(entry);
    }
    return this.descriptorsById.get(row.device_id) ?? null;
  }

  private async fetchDeviceRelayRows(deviceId?: string, deviceUid?: string): Promise<DeviceRelayRow[]> {
    const clauses = ["d.is_active = TRUE", "d.owner_user_id IS NOT NULL"];
    const values: unknown[] = [];

    if (deviceId) {
      values.push(deviceId);
      clauses.push(`d.id = $${values.length}`);
    }
    if (deviceUid) {
      values.push(deviceUid);
      clauses.push(`d.device_uid = $${values.length}`);
    }

    const result = await query<DeviceRelayRow>(
      `SELECT
         d.id AS device_id,
         d.device_uid,
         d.name AS device_name,
         d.owner_user_id,
         d.model,
         d.relay_count,
         rs.relay_index,
         COALESCE(NULLIF(rs.relay_name, ''), 'Relay ' || (rs.relay_index + 1)::text) AS relay_name,
         rs.is_on
       FROM devices d
       JOIN relay_states rs ON rs.device_id = d.id
       WHERE ${clauses.join(" AND ")}
       ORDER BY d.created_at ASC, rs.relay_index ASC`,
      values
    );
    return result.rows;
  }

  private async startHomekit(): Promise<void> {
    if (!env.HOMEKIT_ENABLED) {
      return;
    }

    if (!this.homekitLoaded) {
      try {
        this.hap = require("hap-nodejs") as HapModule;
        this.homekitLoaded = true;
      } catch (error) {
        this.logger?.warn({ err: error }, "homekit_module_load_failed");
        return;
      }
    }
    if (!this.hap) {
      return;
    }

    this.hap.HAPStorage.setCustomStoragePath(env.HOMEKIT_STORAGE_PATH);
    const bridgeUuid = this.hap.uuid.generate("hexa-homekit-bridge");
    const bridge = new this.hap.Bridge(env.HOMEKIT_BRIDGE_NAME, bridgeUuid);
    this.homekitBridge = bridge;

    const rows = await this.fetchDeviceRelayRows();
    for (const row of rows) {
      this.ensureHomekitRelay(row);
    }

    bridge.publish({
      username: env.HOMEKIT_BRIDGE_USERNAME,
      port: env.HOMEKIT_BRIDGE_PORT,
      pincode: env.HOMEKIT_BRIDGE_PIN,
      category: this.hap.Categories.BRIDGE,
      setupID: env.HOMEKIT_SETUP_ID
    });

    this.logger?.info(
      {
        relay_count: this.homekitByKey.size,
        port: env.HOMEKIT_BRIDGE_PORT
      },
      "homekit_bridge_started"
    );
  }

  private ensureHomekitRelay(row: DeviceRelayRow): void {
    if (!env.HOMEKIT_ENABLED) {
      return;
    }
    if (!this.hap || !this.homekitBridge) {
      return;
    }

    const key = relayKey(row.device_id, row.relay_index);
    if (this.homekitByKey.has(key)) {
      return;
    }

    const accessoryUuid = this.hap.uuid.generate(`hexa:${row.device_uid}:${row.relay_index}`);
    const accessoryName = `${row.device_name} ${row.relay_name}`;
    const accessory = new this.hap.Accessory(accessoryName, accessoryUuid);
    accessory.category = this.hap.Categories.SWITCH;

    const infoService = accessory.getService(this.hap.Service.AccessoryInformation);
    infoService?.setCharacteristic(this.hap.Characteristic.Manufacturer, "Hexa Tech");
    infoService?.setCharacteristic(this.hap.Characteristic.Model, row.model);
    infoService?.setCharacteristic(this.hap.Characteristic.SerialNumber, row.device_uid);
    infoService?.setCharacteristic(this.hap.Characteristic.FirmwareRevision, "server-bridge");

    const switchService = accessory.addService(
      this.hap.Service.Switch,
      accessoryName,
      key
    );
    switchService.setCharacteristic(this.hap.Characteristic.Name, row.relay_name);

    const characteristic = switchService.getCharacteristic(this.hap.Characteristic.On);
    characteristic.onGet(() => {
      const cached = deviceStateCache.getRelayState(row.device_uid, row.relay_index);
      return cached ?? row.is_on;
    });
    characteristic.onSet(async (value) => {
      const boolValue = value === true || value === 1;
      if (!this.commandExecutor) {
        throw new Error("homekit_command_executor_unavailable");
      }
      await this.commandExecutor({
        deviceId: row.device_id,
        scope: "single",
        relayIndex: row.relay_index,
        action: boolValue ? "on" : "off",
        source: "homekit",
        actorUserId: row.owner_user_id ?? undefined
      });
    });
    characteristic.updateValue(row.is_on);

    this.homekitBridge.addBridgedAccessory(accessory);
    this.homekitByKey.set(key, {
      key,
      deviceId: row.device_id,
      deviceUid: row.device_uid,
      relayIndex: row.relay_index,
      relayName: row.relay_name,
      ownerUserId: row.owner_user_id,
      accessory,
      characteristic
    });
  }

  private updateHomekitRelayState(deviceId: string, relayIndex: number, isOn: boolean): void {
    const key = relayKey(deviceId, relayIndex);
    const mapped = this.homekitByKey.get(key);
    if (!mapped) {
      return;
    }
    mapped.characteristic.updateValue(isOn);
  }

  private async startMqtt(): Promise<void> {
    if (!env.HA_MQTT_ENABLED || !env.HA_MQTT_URL) {
      return;
    }

    if (!this.mqttLoaded) {
      try {
        require("mqtt");
        this.mqttLoaded = true;
      } catch (error) {
        this.logger?.warn({ err: error }, "mqtt_module_load_failed");
        return;
      }
    }

    const mqtt = require("mqtt") as MqttModuleLike;
    const urlProtocol = this.parseUrlProtocol(env.HA_MQTT_URL);
    if (env.NODE_ENV === "production" && urlProtocol === "mqtt") {
      this.logger?.warn(
        {
          mqtt_url: env.HA_MQTT_URL
        },
        "mqtt_insecure_remote_transport"
      );
    }

    const connectOptions: MqttConnectOptions = {
      clientId: env.HA_MQTT_CLIENT_ID,
      username: env.HA_MQTT_USERNAME || undefined,
      password: env.HA_MQTT_PASSWORD || undefined,
      clean: true,
      reconnectPeriod: 5000,
      keepalive: env.HA_MQTT_KEEPALIVE_SECONDS,
      connectTimeout: env.HA_MQTT_CONNECT_TIMEOUT_MS,
      rejectUnauthorized: env.HA_MQTT_REJECT_UNAUTHORIZED,
      ca: this.readMqttTlsFile(env.HA_MQTT_CA_FILE, "ca"),
      cert: this.readMqttTlsFile(env.HA_MQTT_CERT_FILE, "cert"),
      key: this.readMqttTlsFile(env.HA_MQTT_KEY_FILE, "key"),
      passphrase: env.HA_MQTT_KEY_PASSPHRASE || undefined,
      servername: env.HA_MQTT_SNI_SERVERNAME || undefined
    };

    const client = mqtt.connect(env.HA_MQTT_URL, connectOptions);
    this.mqttClient = client;

    client.on("connect", () => {
      const commandTopic = `${env.HA_MQTT_BASE_TOPIC}/+/relay/+/set`;
      client.subscribe(commandTopic, { qos: 1 }, (error) => {
        if (error) {
          this.logger?.warn({ err: error }, "mqtt_subscribe_failed");
          return;
        }
        this.logger?.info({ command_topic: commandTopic }, "mqtt_subscribed");
      });

      void this.publishMqttDiscoveryForAll();
      this.logger?.info(
        {
          mqtt_url: env.HA_MQTT_URL,
          discovery_prefix: env.HA_MQTT_DISCOVERY_PREFIX,
          base_topic: env.HA_MQTT_BASE_TOPIC
        },
        "mqtt_connected"
      );
    });

    client.on("message", (topicRaw, payloadRaw) => {
      const topic = String(topicRaw);
      const payload = Buffer.isBuffer(payloadRaw)
        ? payloadRaw.toString("utf8")
        : String(payloadRaw);
      void this.handleMqttCommand(topic, payload);
    });

    client.on("error", (error) => {
      this.logger?.warn({ err: error }, "mqtt_client_error");
    });
  }

  private parseUrlProtocol(url: string): string | null {
    try {
      return new URL(url).protocol.replace(":", "").toLowerCase();
    } catch {
      return null;
    }
  }

  private readMqttTlsFile(filePath: string | undefined, field: "ca" | "cert" | "key"): Buffer | undefined {
    if (!filePath) {
      return undefined;
    }
    try {
      return readFileSync(filePath);
    } catch (error) {
      this.logger?.error(
        {
          err: error,
          field,
          file_path: filePath
        },
        "mqtt_tls_file_read_failed"
      );
      throw error;
    }
  }

  private async publishMqttDiscoveryForAll(): Promise<void> {
    const rows = await this.fetchDeviceRelayRows();
    for (const row of rows) {
      this.publishMqttDiscovery(row);
      this.publishMqttRelayState(row.device_uid, row.relay_index, row.is_on);
    }
  }

  private publishMqttDiscovery(row: DeviceRelayRow): void {
    if (!this.mqttClient || !this.mqttClient.connected) {
      return;
    }

    const discoveryTopic = `${env.HA_MQTT_DISCOVERY_PREFIX}/switch/hexa_${row.device_uid}_${row.relay_index}/config`;
    const relayStateTopic = `${env.HA_MQTT_BASE_TOPIC}/${row.device_uid}/relay/${row.relay_index}/state`;
    const relayCommandTopic = `${env.HA_MQTT_BASE_TOPIC}/${row.device_uid}/relay/${row.relay_index}/set`;
    const availabilityTopic = `${env.HA_MQTT_BASE_TOPIC}/${row.device_uid}/availability`;

    const payload = {
      name: `${row.device_name} ${row.relay_name}`,
      uniq_id: `hexa_${row.device_uid}_${row.relay_index}`,
      stat_t: relayStateTopic,
      cmd_t: relayCommandTopic,
      avty_t: availabilityTopic,
      pl_avail: "online",
      pl_not_avail: "offline",
      pl_on: "ON",
      pl_off: "OFF",
      stat_on: "ON",
      stat_off: "OFF",
      dev: {
        ids: [`hexa_${row.device_uid}`],
        name: row.device_name,
        mdl: row.model,
        mf: "Hexa Tech"
      }
    };

    this.mqttClient.publish(discoveryTopic, JSON.stringify(payload), {
      retain: true,
      qos: 1
    });
  }

  private publishMqttRelayState(deviceUid: string, relayIndex: number, isOn: boolean): void {
    if (!this.mqttClient || !this.mqttClient.connected) {
      return;
    }
    const stateTopic = `${env.HA_MQTT_BASE_TOPIC}/${deviceUid}/relay/${relayIndex}/state`;
    this.mqttClient.publish(stateTopic, isOn ? "ON" : "OFF", {
      retain: true,
      qos: 1
    });
  }

  private publishMqttAvailability(deviceUid: string, online: boolean): void {
    if (!this.mqttClient || !this.mqttClient.connected) {
      return;
    }
    const availabilityTopic = `${env.HA_MQTT_BASE_TOPIC}/${deviceUid}/availability`;
    this.mqttClient.publish(availabilityTopic, online ? "online" : "offline", {
      retain: true,
      qos: 1
    });
  }

  private async handleMqttCommand(topic: string, payload: string): Promise<void> {
    if (!this.commandExecutor) {
      return;
    }

    const prefix = `${env.HA_MQTT_BASE_TOPIC}/`;
    if (!topic.startsWith(prefix)) {
      return;
    }
    const segments = topic.slice(prefix.length).split("/");
    if (segments.length !== 4) {
      return;
    }
    const [deviceUid, relayWord, relayPart, setWord] = segments;
    if (relayWord !== "relay" || setWord !== "set") {
      return;
    }

    const descriptor = this.descriptorsByUid.get(deviceUid) ?? (await this.loadDeviceDescriptorByUid(deviceUid));
    if (!descriptor) {
      return;
    }

    const action = parseMqttBool(payload);
    if (!action) {
      return;
    }

    if (relayPart === "all") {
      if (action === "toggle") {
        return;
      }
      await this.commandExecutor({
        deviceId: descriptor.id,
        scope: "all",
        action,
        source: "ha",
        actorUserId: descriptor.ownerUserId ?? undefined
      });
      return;
    }

    const relayIndex = Number.parseInt(relayPart, 10);
    if (!Number.isInteger(relayIndex) || relayIndex < 0 || relayIndex >= descriptor.relayCount) {
      return;
    }

    await this.commandExecutor({
      deviceId: descriptor.id,
      scope: "single",
      relayIndex,
      action,
      source: "ha",
      actorUserId: descriptor.ownerUserId ?? undefined
    });
  }
}

export const smartHomeService = new SmartHomeService();
