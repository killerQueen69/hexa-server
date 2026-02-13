type DeviceSnapshot = {
  deviceId: string;
  deviceUid: string;
  ownerUserId: string | null;
  relays: boolean[];
  updatedAt: string;
};

type RelayPatch = {
  relayIndex: number;
  isOn: boolean;
};

class DeviceStateCache {
  private readonly byDeviceUid = new Map<string, DeviceSnapshot>();
  private readonly byDeviceId = new Map<string, string>();

  setRelayState(params: {
    deviceId: string;
    deviceUid: string;
    ownerUserId: string | null;
    relayIndex: number;
    isOn: boolean;
    relayCount: number;
    updatedAt: string;
  }): void {
    const existing = this.byDeviceUid.get(params.deviceUid);
    const relays = existing?.relays
      ? [...existing.relays]
      : new Array<boolean>(params.relayCount).fill(false);

    while (relays.length < params.relayCount) {
      relays.push(false);
    }
    if (params.relayIndex >= 0 && params.relayIndex < relays.length) {
      relays[params.relayIndex] = params.isOn;
    }

    const snapshot: DeviceSnapshot = {
      deviceId: params.deviceId,
      deviceUid: params.deviceUid,
      ownerUserId: params.ownerUserId,
      relays,
      updatedAt: params.updatedAt
    };

    this.byDeviceUid.set(params.deviceUid, snapshot);
    this.byDeviceId.set(params.deviceId, params.deviceUid);
  }

  setAllRelayStates(params: {
    deviceId: string;
    deviceUid: string;
    ownerUserId: string | null;
    relays: boolean[];
    updatedAt: string;
  }): void {
    const snapshot: DeviceSnapshot = {
      deviceId: params.deviceId,
      deviceUid: params.deviceUid,
      ownerUserId: params.ownerUserId,
      relays: [...params.relays],
      updatedAt: params.updatedAt
    };

    this.byDeviceUid.set(params.deviceUid, snapshot);
    this.byDeviceId.set(params.deviceId, params.deviceUid);
  }

  patchRelayStates(params: {
    deviceId: string;
    deviceUid: string;
    ownerUserId: string | null;
    relayCount: number;
    relays: RelayPatch[];
    updatedAt: string;
  }): boolean[] {
    const existing = this.byDeviceUid.get(params.deviceUid);
    const current = existing?.relays
      ? [...existing.relays]
      : new Array<boolean>(params.relayCount).fill(false);

    while (current.length < params.relayCount) {
      current.push(false);
    }

    for (const relay of params.relays) {
      if (relay.relayIndex < 0 || relay.relayIndex >= current.length) {
        continue;
      }
      current[relay.relayIndex] = relay.isOn;
    }

    const snapshot: DeviceSnapshot = {
      deviceId: params.deviceId,
      deviceUid: params.deviceUid,
      ownerUserId: params.ownerUserId,
      relays: current,
      updatedAt: params.updatedAt
    };
    this.byDeviceUid.set(params.deviceUid, snapshot);
    this.byDeviceId.set(params.deviceId, params.deviceUid);
    return current;
  }

  getSnapshotByUid(deviceUid: string): DeviceSnapshot | null {
    const snapshot = this.byDeviceUid.get(deviceUid);
    if (!snapshot) {
      return null;
    }
    return {
      ...snapshot,
      relays: [...snapshot.relays]
    };
  }

  getRelayState(deviceUid: string, relayIndex: number): boolean | null {
    const snapshot = this.byDeviceUid.get(deviceUid);
    if (!snapshot) {
      return null;
    }
    if (relayIndex < 0 || relayIndex >= snapshot.relays.length) {
      return null;
    }
    return snapshot.relays[relayIndex];
  }

  removeByUid(deviceUid: string): void {
    const snapshot = this.byDeviceUid.get(deviceUid);
    if (!snapshot) {
      return;
    }
    this.byDeviceUid.delete(deviceUid);
    this.byDeviceId.delete(snapshot.deviceId);
  }
}

export const deviceStateCache = new DeviceStateCache();
