export const SESSION_STORAGE_KEY = "hexa_admin_dashboard_session_v2";
export const COLLAPSE_STORAGE_KEY = "hexa_admin_dashboard_collapsed_v1";
export const DEVICE_COLLAPSE_STORAGE_KEY = "hexa_admin_dashboard_device_collapsed_v1";

export const DASHBOARD_TZ_OFFSET_HOURS = 2;
export const DASHBOARD_TZ_LABEL = `UTC${DASHBOARD_TZ_OFFSET_HOURS >= 0 ? "+" : ""}${DASHBOARD_TZ_OFFSET_HOURS}`;

export const ADMIN_ONLY_CARD_IDS = new Set([
  "overview",
  "users",
  "ota-keys",
  "ota-releases",
  "backup-runs",
  "audit-log",
  "raw-metrics"
]);

export function createDashboardState() {
  return {
    accessToken: "",
    refreshToken: "",
    user: null,
    releases: [],
    users: [],
    devices: [],
    preferences: null,
    refreshPromise: null,
    collapsedCards: {},
    collapsedDeviceCards: {},
    deviceSearchQuery: "",
    pendingDeviceActions: new Map(),
    automationTestingByDevice: new Map(),
    irCodesByDevice: new Map(),
    irLastResultByDevice: new Map(),
    irFormByDevice: new Map(),
    pendingRealtimeCommands: new Map(),
    realtimeSocket: null,
    realtimeAuthed: false,
    realtimeUrl: "",
    realtimeReconnectTimer: null,
    realtimeReconnectAttempt: 0,
    realtimeReloadTimer: null
  };
}
