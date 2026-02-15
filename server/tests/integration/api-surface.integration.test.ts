import assert from "node:assert/strict";
import test from "node:test";
import bcrypt from "bcrypt";
import { FastifyInstance } from "fastify";
import { buildApp } from "../../src/app";
import { env } from "../../src/config/env";
import { closeDb, query } from "../../src/db/connection";
import { runMigrations } from "../../src/db/migrate";
import { newId } from "../../src/utils/crypto";
import { nowIso } from "../../src/utils/time";

type JsonRecord = Record<string, unknown>;

type InjectJsonResult = {
  status: number;
  body: unknown;
};

function asRecord(value: unknown): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function readString(value: unknown, field: string): string {
  const record = asRecord(value);
  const current = record[field];
  assert.equal(typeof current, "string", `${field} must be a string.`);
  return current as string;
}

function readBoolean(value: unknown, field: string): boolean {
  const record = asRecord(value);
  const current = record[field];
  assert.equal(typeof current, "boolean", `${field} must be a boolean.`);
  return current as boolean;
}

function assertStatusOneOf(status: number, expected: number[], context: string): void {
  assert.ok(
    expected.includes(status),
    `${context} expected one of [${expected.join(", ")}], got ${status}.`
  );
}

function authHeaders(accessToken: string): Record<string, string> {
  return {
    authorization: `Bearer ${accessToken}`
  };
}

async function injectJson(
  app: FastifyInstance,
  options: {
    method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
    url: string;
    headers?: Record<string, string>;
    payload?: unknown;
  }
): Promise<InjectJsonResult> {
  const response = await app.inject({
    method: options.method,
    url: options.url,
    headers: options.headers,
    payload: options.payload
  });

  let body: unknown = {};
  if (response.body && response.body.length > 0) {
    try {
      body = JSON.parse(response.body) as unknown;
    } catch {
      body = {};
    }
  }

  return {
    status: response.statusCode,
    body
  };
}

test("integration: API surface coverage for admin/user/webhook routes", async () => {
  await runMigrations();
  const fallbackMetadataColumns = await query<{ table_name: string; column_name: string }>(
    `SELECT table_name, column_name
     FROM information_schema.columns
     WHERE table_schema = 'public'
       AND (
         (table_name = 'automation_rules' AND column_name = 'definition_updated_at')
         OR
         (table_name = 'schedules' AND column_name = 'definition_updated_at')
       )`
  );
  assert.equal(fallbackMetadataColumns.rows.length, 2);

  const app = buildApp();

  try {
    const userEmail = `surface-user-${newId()}@example.com`;
    const userPassword = "SurfaceUserPass!234";
    const register = await injectJson(app, {
      method: "POST",
      url: "/api/v1/auth/register",
      payload: {
        email: userEmail,
        password: userPassword,
        name: "Surface User"
      }
    });
    assert.equal(register.status, 201);
    const userAccessToken = readString(register.body, "access_token");

    const userRow = await query<{ id: string }>(
      `SELECT id
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [userEmail]
    );
    const userId = userRow.rows[0]?.id;
    assert.equal(typeof userId, "string");

    const adminEmail = `surface-admin-${newId()}@example.com`;
    const adminPassword = "SurfaceAdminPass!234";
    const adminHash = await bcrypt.hash(adminPassword, env.BCRYPT_ROUNDS);
    await query(
      `INSERT INTO users (
         id, email, password_hash, name, role, is_active, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, 'admin', TRUE, $5, $6)`,
      [newId(), adminEmail, adminHash, "Surface Admin", nowIso(), nowIso()]
    );

    const adminLogin = await injectJson(app, {
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        email: adminEmail,
        password: adminPassword
      }
    });
    assert.equal(adminLogin.status, 200);
    const adminAccessToken = readString(adminLogin.body, "access_token");

    const provisioned = await injectJson(app, {
      method: "POST",
      url: "/api/v1/provision/register",
      payload: {
        provision_key: env.DEVICE_PROVISION_KEY,
        chip_id: `surface-chip-${newId()}`,
        model: "hexa-mini-switch-v1",
        relay_count: 3,
        button_count: 3
      }
    });
    assert.equal(provisioned.status, 200);
    const provisionDeviceId = readString(provisioned.body, "device_id");
    const provisionDeviceUid = readString(provisioned.body, "device_uid");
    let provisionDeviceToken = readString(provisioned.body, "device_token");
    let claimCode = readString(provisioned.body, "claim_code");

    const claim = await injectJson(app, {
      method: "POST",
      url: "/api/v1/devices/claim",
      headers: authHeaders(userAccessToken),
      payload: {
        claim_code: claimCode
      }
    });
    assert.equal(claim.status, 200);
    assert.equal(readBoolean(claim.body, "ok"), true);

    const alexa = await injectJson(app, {
      method: "POST",
      url: "/api/v1/alexa/smart-home",
      payload: {}
    });
    assertStatusOneOf(alexa.status, [400, 401, 503], "alexa smart-home");

    const userAudit = await injectJson(app, {
      method: "GET",
      url: "/api/v1/audit",
      headers: authHeaders(userAccessToken)
    });
    assert.equal(userAudit.status, 200);

    const adminOverview = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/overview",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminOverview.status, 200);

    const adminUsers = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/users",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminUsers.status, 200);

    const adminPatchUser = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/admin/users/${userId as string}`,
      headers: authHeaders(adminAccessToken),
      payload: {
        name: "Surface User Updated"
      }
    });
    assert.equal(adminPatchUser.status, 200);

    const deletableEmail = `surface-delete-${newId()}@example.com`;
    const deletablePassword = "SurfaceDeletePass!234";
    const deletableRegister = await injectJson(app, {
      method: "POST",
      url: "/api/v1/auth/register",
      payload: {
        email: deletableEmail,
        password: deletablePassword,
        name: "Surface Delete Candidate"
      }
    });
    assert.equal(deletableRegister.status, 201);
    const deletableUserRow = await query<{ id: string }>(
      `SELECT id
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [deletableEmail]
    );
    const deletableUserId = deletableUserRow.rows[0]?.id;
    assert.equal(typeof deletableUserId, "string");

    const adminDeleteUser = await injectJson(app, {
      method: "DELETE",
      url: `/api/v1/admin/users/${deletableUserId}`,
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminDeleteUser.status, 200);

    const deletedUserLogin = await injectJson(app, {
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        email: deletableEmail,
        password: deletablePassword
      }
    });
    assert.equal(deletedUserLogin.status, 401);

    const adminDevices = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/devices",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminDevices.status, 200);

    const adminPatchDevice = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/admin/devices/${provisionDeviceId}`,
      headers: authHeaders(adminAccessToken),
      payload: {
        name: "Surface Device Updated"
      }
    });
    assert.equal(adminPatchDevice.status, 200);

    const adminRotateToken = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/devices/${provisionDeviceId}/token/rotate`,
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminRotateToken.status, 200);
    provisionDeviceToken = readString(adminRotateToken.body, "device_token");

    const adminRelayAll = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/devices/${provisionDeviceId}/relays/all`,
      headers: authHeaders(adminAccessToken),
      payload: {
        action: "off"
      }
    });
    assertStatusOneOf(adminRelayAll.status, [200, 409, 504], "admin relays/all");

    const adminRelaySingle = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/devices/${provisionDeviceId}/relays/0`,
      headers: authHeaders(adminAccessToken),
      payload: {
        action: "toggle"
      }
    });
    assertStatusOneOf(adminRelaySingle.status, [200, 409, 504], "admin relays/:index");

    const adminAudit = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/audit",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminAudit.status, 200);

    const adminVersioning = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/versioning",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminVersioning.status, 200);

    const backupPolicy = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/ops/backup/policy",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(backupPolicy.status, 200);

    const backupRuns = await injectJson(app, {
      method: "GET",
      url: "/api/v1/admin/ops/backup/runs",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(backupRuns.status, 200);

    const adminRelease = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/devices/${provisionDeviceId}/release`,
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminRelease.status, 200);
    claimCode = readString(adminRelease.body, "claim_code");

    const claimAfterAdminRelease = await injectJson(app, {
      method: "POST",
      url: "/api/v1/devices/claim",
      headers: authHeaders(userAccessToken),
      payload: {
        claim_code: claimCode
      }
    });
    assert.equal(claimAfterAdminRelease.status, 200);

    const userDevices = await injectJson(app, {
      method: "GET",
      url: "/api/v1/devices",
      headers: authHeaders(userAccessToken)
    });
    assert.equal(userDevices.status, 200);

    const userPatchDevice = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/devices/${provisionDeviceId}`,
      headers: authHeaders(userAccessToken),
      payload: {
        name: "Surface User Device"
      }
    });
    assert.equal(userPatchDevice.status, 200);

    const userPatchDeviceConnectivity = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/devices/${provisionDeviceId}`,
      headers: authHeaders(userAccessToken),
      payload: {
        config: {
          connectivity: {
            mqtt: {
              enabled: true,
              host: "mqtt.example.test",
              port: 1883,
              show_config: true
            }
          }
        }
      }
    });
    assert.equal(userPatchDeviceConnectivity.status, 200);
    const patchedConnectivityDevice = asRecord(userPatchDeviceConnectivity.body);
    const patchedConnectivityConfig = asRecord(patchedConnectivityDevice.config);
    const patchedConnectivityNode = asRecord(patchedConnectivityConfig.connectivity);
    const patchedConnectivityMqtt = asRecord(patchedConnectivityNode.mqtt);
    assert.equal(patchedConnectivityMqtt.show_config, true);

    const userRotateToken = await injectJson(app, {
      method: "POST",
      url: `/api/v1/devices/${provisionDeviceId}/token/rotate`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(userRotateToken.status, 200);
    provisionDeviceToken = readString(userRotateToken.body, "device_token");

    const userRelaySingle = await injectJson(app, {
      method: "POST",
      url: `/api/v1/devices/${provisionDeviceId}/relays/0`,
      headers: authHeaders(userAccessToken),
      payload: {
        action: "on"
      }
    });
    assertStatusOneOf(userRelaySingle.status, [200, 409, 504], "user relays/:index");

    const userRelease = await injectJson(app, {
      method: "POST",
      url: `/api/v1/devices/${provisionDeviceId}/release`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(userRelease.status, 200);
    claimCode = readString(userRelease.body, "claim_code");

    const claimAfterUserRelease = await injectJson(app, {
      method: "POST",
      url: "/api/v1/devices/claim",
      headers: authHeaders(userAccessToken),
      payload: {
        claim_code: claimCode
      }
    });
    assert.equal(claimAfterUserRelease.status, 200);

    const adminCreateAutomation = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/devices/${provisionDeviceId}/automations`,
      headers: authHeaders(adminAccessToken),
      payload: {
        name: "Admin-created automation",
        trigger_type: "input_event",
        trigger_config: {
          input_index: 0,
          event: "press"
        },
        condition_config: {},
        action_type: "set_relay",
        action_config: {
          relay_index: 0,
          action: "toggle"
        },
        cooldown_seconds: 0,
        is_enabled: true
      }
    });
    assert.equal(adminCreateAutomation.status, 201);
    const adminAutomationId = readString(adminCreateAutomation.body, "id");
    assert.ok(adminAutomationId.length > 0);

    const adminCreateSchedule = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/devices/${provisionDeviceId}/schedules`,
      headers: authHeaders(adminAccessToken),
      payload: {
        target_scope: "single",
        relay_index: 1,
        name: "Admin-created once",
        schedule_type: "once",
        execute_at: new Date(Date.now() + 300_000).toISOString(),
        timezone: "UTC",
        action: "off",
        is_enabled: true
      }
    });
    assert.equal(adminCreateSchedule.status, 201);
    const adminScheduleId = readString(adminCreateSchedule.body, "id");
    assert.ok(adminScheduleId.length > 0);

    const scheduleCreate = await injectJson(app, {
      method: "POST",
      url: "/api/v1/schedules",
      headers: authHeaders(userAccessToken),
      payload: {
        device_id: provisionDeviceId,
        target_scope: "single",
        relay_index: 0,
        schedule_type: "once",
        execute_at: new Date(Date.now() + 120_000).toISOString(),
        timezone: "UTC",
        action: "on",
        is_enabled: true
      }
    });
    assert.equal(scheduleCreate.status, 201);
    const scheduleId = readString(scheduleCreate.body, "id");
    const scheduleDefinition = await query<{ definition_updated_at: Date | null }>(
      `SELECT definition_updated_at
       FROM schedules
       WHERE id = $1
       LIMIT 1`,
      [scheduleId]
    );
    assert.equal(Boolean(scheduleDefinition.rows[0]?.definition_updated_at), true);

    const adminDeviceSchedules = await injectJson(app, {
      method: "GET",
      url: `/api/v1/admin/devices/${provisionDeviceId}/schedules`,
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminDeviceSchedules.status, 200);
    assert.equal(
      asArray(adminDeviceSchedules.body).some((row) => asRecord(row).id === scheduleId),
      true
    );

    const adminRunScheduleNow = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/schedules/${scheduleId}/run-now`,
      headers: authHeaders(adminAccessToken),
      payload: {}
    });
    assert.equal(adminRunScheduleNow.status, 200);
    assert.equal(readString(adminRunScheduleNow.body, "schedule_id"), scheduleId);
    assert.equal(readString(adminRunScheduleNow.body, "status").length > 0, true);

    const scheduleMetadataAfterRunNow = await query<{
      last_executed: Date | null;
      execution_count: number;
      is_enabled: boolean;
    }>(
      `SELECT last_executed, execution_count, is_enabled
       FROM schedules
       WHERE id = $1
       LIMIT 1`,
      [scheduleId]
    );
    assert.equal(scheduleMetadataAfterRunNow.rows[0]?.execution_count, 1);
    assert.equal(Boolean(scheduleMetadataAfterRunNow.rows[0]?.last_executed), true);
    assert.equal(scheduleMetadataAfterRunNow.rows[0]?.is_enabled, false);

    const scheduleList = await injectJson(app, {
      method: "GET",
      url: "/api/v1/schedules",
      headers: authHeaders(userAccessToken)
    });
    assert.equal(scheduleList.status, 200);

    const schedulePatch = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/schedules/${scheduleId}`,
      headers: authHeaders(userAccessToken),
      payload: {
        action: "off"
      }
    });
    assert.equal(schedulePatch.status, 200);

    const scheduleDisable = await injectJson(app, {
      method: "POST",
      url: `/api/v1/schedules/${scheduleId}/disable`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(scheduleDisable.status, 200);

    const scheduleEnable = await injectJson(app, {
      method: "POST",
      url: `/api/v1/schedules/${scheduleId}/enable`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(scheduleEnable.status, 200);

    const scheduleDelete = await injectJson(app, {
      method: "DELETE",
      url: `/api/v1/schedules/${scheduleId}`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(scheduleDelete.status, 200);

    const automationCreate = await injectJson(app, {
      method: "POST",
      url: "/api/v1/automations",
      headers: authHeaders(userAccessToken),
      payload: {
        device_id: provisionDeviceId,
        name: "Surface automation",
        trigger_type: "device_online",
        trigger_config: {},
        condition_config: {
          required_relay_state: {
            relay_index: 0,
            is_on: true
          }
        },
        action_type: "set_all_relays",
        action_config: { action: "off" },
        cooldown_seconds: 0,
        is_enabled: true
      }
    });
    assert.equal(automationCreate.status, 201);
    const automationId = readString(automationCreate.body, "id");
    const automationDefinition = await query<{ definition_updated_at: Date | null }>(
      `SELECT definition_updated_at
       FROM automation_rules
       WHERE id = $1
       LIMIT 1`,
      [automationId]
    );
    assert.equal(Boolean(automationDefinition.rows[0]?.definition_updated_at), true);

    const adminDeviceAutomations = await injectJson(app, {
      method: "GET",
      url: `/api/v1/admin/devices/${provisionDeviceId}/automations`,
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(adminDeviceAutomations.status, 200);
    assert.equal(
      asArray(adminDeviceAutomations.body).some((row) => asRecord(row).id === automationId),
      true
    );

    const adminRunAutomationNow = await injectJson(app, {
      method: "POST",
      url: `/api/v1/admin/automations/${automationId}/run-now`,
      headers: authHeaders(adminAccessToken),
      payload: {}
    });
    assert.equal(adminRunAutomationNow.status, 200);
    assert.equal(readString(adminRunAutomationNow.body, "automation_id"), automationId);
    assert.equal(readString(adminRunAutomationNow.body, "status"), "skipped");
    assert.equal(readString(adminRunAutomationNow.body, "reason"), "condition_not_met");

    const automationList = await injectJson(app, {
      method: "GET",
      url: "/api/v1/automations",
      headers: authHeaders(userAccessToken)
    });
    assert.equal(automationList.status, 200);

    const automationPatch = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/automations/${automationId}`,
      headers: authHeaders(userAccessToken),
      payload: {
        name: "Surface automation updated"
      }
    });
    assert.equal(automationPatch.status, 200);

    const automationDisable = await injectJson(app, {
      method: "POST",
      url: `/api/v1/automations/${automationId}/disable`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(automationDisable.status, 200);

    const automationEnable = await injectJson(app, {
      method: "POST",
      url: `/api/v1/automations/${automationId}/enable`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(automationEnable.status, 200);

    const automationDelete = await injectJson(app, {
      method: "DELETE",
      url: `/api/v1/automations/${automationId}`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(automationDelete.status, 200);

    const capabilityPut = await injectJson(app, {
      method: "PUT",
      url: `/api/v1/devices/${provisionDeviceId}/capabilities/ir_rx`,
      headers: authHeaders(userAccessToken),
      payload: {
        capability_kind: "infrared",
        config: {},
        metadata: {},
        is_enabled: true
      }
    });
    assert.equal(capabilityPut.status, 200);

    const capabilityDelete = await injectJson(app, {
      method: "DELETE",
      url: `/api/v1/devices/${provisionDeviceId}/capabilities/ir_rx`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(capabilityDelete.status, 200);

    const irCreate = await injectJson(app, {
      method: "POST",
      url: `/api/v1/devices/${provisionDeviceId}/ir-codes`,
      headers: authHeaders(userAccessToken),
      payload: {
        code_name: "Power",
        protocol: "nec",
        frequency_hz: 38000,
        payload: "A90",
        metadata: {}
      }
    });
    assert.equal(irCreate.status, 201);
    const irCodeId = readString(irCreate.body, "id");

    const irList = await injectJson(app, {
      method: "GET",
      url: `/api/v1/devices/${provisionDeviceId}/ir-codes`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(irList.status, 200);
    assert.ok(asArray(irList.body).length >= 1);

    const irPatch = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/devices/${provisionDeviceId}/ir-codes/${irCodeId}`,
      headers: authHeaders(userAccessToken),
      payload: {
        code_name: "Power2"
      }
    });
    assert.equal(irPatch.status, 200);

    const irDelete = await injectJson(app, {
      method: "DELETE",
      url: `/api/v1/devices/${provisionDeviceId}/ir-codes/${irCodeId}`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(irDelete.status, 200);

    const sensorEventsPost = await injectJson(app, {
      method: "POST",
      url: `/api/v1/devices/${provisionDeviceId}/sensor-events`,
      headers: authHeaders(userAccessToken),
      payload: {
        events: [
          {
            sensor_key: "motion.main",
            sensor_type: "motion",
            event_kind: "detected",
            value: { detected: true },
            observed_at: nowIso(),
            source: "api"
          }
        ]
      }
    });
    assert.equal(sensorEventsPost.status, 201);

    const sensorEventsGet = await injectJson(app, {
      method: "GET",
      url: `/api/v1/devices/${provisionDeviceId}/sensor-events`,
      headers: authHeaders(userAccessToken)
    });
    assert.equal(sensorEventsGet.status, 200);
    assert.ok(asArray(sensorEventsGet.body).length >= 1);

    const sensorReport = await injectJson(app, {
      method: "POST",
      url: "/api/v1/devices/sensor-report",
      payload: {
        device_uid: provisionDeviceUid,
        device_token: provisionDeviceToken,
        events: [
          {
            sensor_key: "motion.main",
            sensor_type: "motion",
            event_kind: "detected",
            value: { detected: true },
            observed_at: nowIso(),
            source: "device"
          }
        ]
      }
    });
    assert.equal(sensorReport.status, 200);

    const otaReleases = await injectJson(app, {
      method: "GET",
      url: "/api/v1/ota/releases",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(otaReleases.status, 200);

    const otaSigningKeys = await injectJson(app, {
      method: "GET",
      url: "/api/v1/ota/signing-keys",
      headers: authHeaders(adminAccessToken)
    });
    assert.equal(otaSigningKeys.status, 200);

    const missingReleasePatch = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/ota/releases/${newId()}`,
      headers: authHeaders(adminAccessToken),
      payload: {
        is_active: true
      }
    });
    assert.equal(missingReleasePatch.status, 404);

    const missingSigningKeyPatch = await injectJson(app, {
      method: "PATCH",
      url: `/api/v1/ota/signing-keys/${newId()}`,
      headers: authHeaders(adminAccessToken),
      payload: {
        status: "retired"
      }
    });
    assert.equal(missingSigningKeyPatch.status, 404);

    const dashboardPage = await injectJson(app, {
      method: "GET",
      url: "/dashboard"
    });
    assert.equal(dashboardPage.status, 200);

    const testUiPage = await injectJson(app, {
      method: "GET",
      url: "/test-ui"
    });
    assert.equal(testUiPage.status, 200);
  } finally {
    await app.close();
    await closeDb();
  }
});
