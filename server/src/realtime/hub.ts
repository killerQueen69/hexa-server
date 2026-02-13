import { newId } from "../utils/crypto";

export type DeviceSession = {
  id: string;
  deviceId: string;
  deviceUid: string;
  sendJson: (payload: unknown) => boolean;
  close: () => void;
};

export type ClientSession = {
  id: string;
  userId: string;
  role: string;
  sendJson: (payload: unknown) => boolean;
  close: () => void;
};

type PendingAck = {
  commandId: string;
  deviceUid: string;
  createdAtMs: number;
  resolve: (value: CommandAckResult) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
};

export type CommandAckResult = {
  commandId: string;
  ok: boolean;
  error?: string;
  latencyMs: number;
  payload?: unknown;
};

class RealtimeHub {
  private readonly devices = new Map<string, DeviceSession>();
  private readonly clients = new Map<string, ClientSession>();
  private readonly pendingAcks = new Map<string, PendingAck>();

  registerDevice(session: Omit<DeviceSession, "id">): DeviceSession {
    const existing = this.devices.get(session.deviceUid);
    if (existing) {
      existing.close();
    }

    const fullSession: DeviceSession = {
      id: newId(),
      ...session
    };
    this.devices.set(fullSession.deviceUid, fullSession);

    return fullSession;
  }

  unregisterDevice(deviceUid: string): void {
    const session = this.devices.get(deviceUid);
    if (!session) {
      return;
    }

    this.devices.delete(deviceUid);
    this.rejectPendingForDevice(deviceUid, "device_disconnected");
  }

  getDevice(deviceUid: string): DeviceSession | undefined {
    return this.devices.get(deviceUid);
  }

  registerClient(session: Omit<ClientSession, "id">): ClientSession {
    const fullSession: ClientSession = {
      id: newId(),
      ...session
    };
    this.clients.set(fullSession.id, fullSession);
    return fullSession;
  }

  unregisterClient(clientId: string): void {
    this.clients.delete(clientId);
  }

  sendToDevice(deviceUid: string, payload: unknown): boolean {
    const session = this.devices.get(deviceUid);
    if (!session) {
      return false;
    }
    return session.sendJson(payload);
  }

  broadcast(payload: unknown): void {
    for (const [, session] of this.clients) {
      session.sendJson(payload);
    }
  }

  broadcastToUser(userId: string, payload: unknown): void {
    for (const [, session] of this.clients) {
      if (session.userId !== userId) {
        continue;
      }
      session.sendJson(payload);
    }
  }

  listOnlineDeviceUids(): string[] {
    return [...this.devices.keys()];
  }

  createPendingAck(commandId: string, deviceUid: string, timeoutMs: number): Promise<CommandAckResult> {
    return new Promise<CommandAckResult>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingAcks.delete(commandId);
        reject(new Error("ack_timeout"));
      }, timeoutMs);

      this.pendingAcks.set(commandId, {
        commandId,
        deviceUid,
        createdAtMs: Date.now(),
        resolve,
        reject,
        timeout
      });
    });
  }

  resolveAck(commandId: string, payload: { ok: boolean; error?: string; payload?: unknown }): void {
    const pending = this.pendingAcks.get(commandId);
    if (!pending) {
      return;
    }

    clearTimeout(pending.timeout);
    this.pendingAcks.delete(commandId);
    pending.resolve({
      commandId,
      ok: payload.ok,
      error: payload.error,
      latencyMs: Date.now() - pending.createdAtMs,
      payload: payload.payload
    });
  }

  rejectPendingForDevice(deviceUid: string, reason: string): void {
    for (const [commandId, pending] of this.pendingAcks) {
      if (pending.deviceUid !== deviceUid) {
        continue;
      }

      clearTimeout(pending.timeout);
      this.pendingAcks.delete(commandId);
      pending.reject(new Error(reason));
    }
  }
}

export const realtimeHub = new RealtimeHub();
