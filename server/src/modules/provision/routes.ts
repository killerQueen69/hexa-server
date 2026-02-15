import { FastifyInstance } from "fastify";
import { z } from "zod";
import { env } from "../../config/env";
import { query, withTransaction } from "../../db/connection";
import { sendApiError } from "../../http/api-error";
import { newId, randomToken, sha256 } from "../../utils/crypto";
import { deriveStableClaimCode } from "../../utils/claim-code";

type DeviceProvisionRow = {
  id: string;
  device_uid: string;
  owner_user_id: string | null;
  claim_code: string | null;
};

const provisionRegisterSchema = z.object({
  provision_key: z.string().min(16),
  chip_id: z.string().min(3).max(64).regex(/^[a-zA-Z0-9._:-]+$/),
  mac: z.string().min(2).max(64).optional(),
  claim_code: z.string().length(8).regex(/^[a-fA-F0-9]{8}$/).optional(),
  model: z.string().min(1).max(100).default("hexa-mini-switch-v1"),
  device_class: z.enum(["relay_controller", "ir_hub", "sensor_hub", "hybrid"]).default("relay_controller"),
  capabilities: z.array(
    z.object({
      key: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
      kind: z.string().min(2).max(80).regex(/^[a-zA-Z0-9._-]+$/),
      enabled: z.boolean().default(true)
    })
  ).optional(),
  firmware_version: z.string().min(1).max(100).optional(),
  relay_count: z.number().int().min(0).max(8).default(3),
  button_count: z.number().int().min(0).max(8).default(3)
});

function buildRelayNames(relayCount: number): string[] {
  return Array.from({ length: relayCount }, (_, idx) => `Relay ${idx + 1}`);
}

function buildUnclaimedName(hardwareUid: string): string {
  return `Hexa mini Switch ${hardwareUid}`;
}

function defaultCapabilities(
  deviceClass: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid",
  relayCount: number
): Array<{ key: string; kind: string; enabled: boolean }> {
  const out: Array<{ key: string; kind: string; enabled: boolean }> = [];
  if (relayCount > 0 && (deviceClass === "relay_controller" || deviceClass === "hybrid")) {
    out.push({ key: "relay", kind: "actuator", enabled: true });
  }
  if (deviceClass === "ir_hub" || deviceClass === "hybrid") {
    out.push({ key: "ir_tx", kind: "infrared", enabled: true });
    out.push({ key: "ir_rx", kind: "infrared", enabled: true });
  }
  if (deviceClass === "sensor_hub" || deviceClass === "hybrid") {
    out.push({ key: "sensor", kind: "telemetry", enabled: true });
  }
  return out;
}

function normalizeCapabilities(
  deviceClass: "relay_controller" | "ir_hub" | "sensor_hub" | "hybrid",
  relayCount: number,
  capabilities: Array<{ key: string; kind: string; enabled: boolean }> | undefined
): Array<{ key: string; kind: string; enabled: boolean }> {
  if (!capabilities || capabilities.length === 0) {
    return defaultCapabilities(deviceClass, relayCount);
  }

  const seen = new Set<string>();
  const normalized: Array<{ key: string; kind: string; enabled: boolean }> = [];
  for (const item of capabilities) {
    if (seen.has(item.key)) {
      continue;
    }
    seen.add(item.key);
    normalized.push(item);
  }

  if (normalized.length > 0) {
    return normalized;
  }
  return defaultCapabilities(deviceClass, relayCount);
}

async function allocateDeviceUid(
  client: {
    query: <T = unknown>(sql: string, params?: unknown[]) => Promise<{ rows: T[]; rowCount: number | null }>;
  },
  hardwareUid: string
): Promise<string> {
  const base = `hexa-${hardwareUid.toLowerCase()}`;
  let candidate = base;

  for (let suffix = 1; suffix < 1000; suffix += 1) {
    const existing = await client.query<{ id: string }>(
      "SELECT id FROM devices WHERE device_uid = $1 LIMIT 1",
      [candidate]
    );
    if (!existing.rowCount || existing.rowCount === 0) {
      return candidate;
    }
    candidate = `${base}-${suffix}`;
  }

  throw new Error("Unable to allocate unique device UID.");
}

export async function provisionRoutes(server: FastifyInstance): Promise<void> {
  server.post("/register", async (request, reply) => {
    const parsed = provisionRegisterSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const payload = parsed.data;
    if (payload.provision_key !== env.DEVICE_PROVISION_KEY) {
      return sendApiError(reply, 401, "unauthorized", "Provision key is invalid.");
    }

    const hardwareUid = payload.chip_id.trim().toLowerCase();
    const normalizedCapabilities = normalizeCapabilities(
      payload.device_class,
      payload.relay_count,
      payload.capabilities
    );
    const provisionClaimCode = deriveStableClaimCode({
      existingClaimCode: payload.claim_code,
      hardwareUid,
      mac: payload.mac
    });
    const rawToken = randomToken(32);
    const tokenHash = sha256(rawToken);
    const now = new Date();

    const provisioned = await withTransaction(async (client) => {
      const existing = await client.query<DeviceProvisionRow>(
        `SELECT id, device_uid, owner_user_id, claim_code
         FROM devices
         WHERE hardware_uid = $1
         LIMIT 1
         FOR UPDATE`,
        [hardwareUid]
      );
      const row = existing.rows[0];

      if (row) {
        const claimCode = deriveStableClaimCode({
          existingClaimCode: row.claim_code ?? provisionClaimCode,
          hardwareUid,
          deviceUid: row.device_uid,
          mac: payload.mac
        });
        await client.query(
          `UPDATE devices
           SET device_token_hash = $1,
               model = $2,
               device_class = $3,
               capabilities = $4::jsonb,
               firmware_version = $5,
               button_count = $6,
               relay_count = $7,
               name = CASE
                 WHEN owner_user_id IS NULL THEN $8
                 ELSE name
               END,
               claim_code = CASE
                 WHEN owner_user_id IS NULL THEN $9
                 ELSE claim_code
               END,
               claim_code_created_at = CASE
                 WHEN owner_user_id IS NULL THEN COALESCE(claim_code_created_at, $10)
                 ELSE claim_code_created_at
               END,
               updated_at = $11
           WHERE id = $12`,
          [
            tokenHash,
            payload.model,
            payload.device_class,
            JSON.stringify(normalizedCapabilities),
            payload.firmware_version ?? null,
            payload.button_count,
            payload.relay_count,
            buildUnclaimedName(hardwareUid),
            claimCode,
            claimCode ? now : null,
            now,
            row.id
          ]
        );

        return {
          deviceId: row.id,
          deviceUid: row.device_uid,
          claimCode: row.owner_user_id ? null : claimCode,
          claimed: row.owner_user_id !== null
        };
      }

      const deviceId = newId();
      const deviceUid = await allocateDeviceUid(client, hardwareUid);
      const claimCode = deriveStableClaimCode({
        existingClaimCode: provisionClaimCode,
        hardwareUid,
        deviceUid,
        mac: payload.mac
      });
      const relayNames = buildRelayNames(payload.relay_count);

      await client.query(
        `INSERT INTO devices (
           id, device_uid, hardware_uid, name, device_token_hash, model, device_class, capabilities, relay_count, button_count,
           relay_names, input_config, power_restore_mode, firmware_version, is_active, owner_user_id,
           claim_code, claim_code_created_at, config, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10,
           $11::jsonb, '[]'::jsonb, 'last_state', $12, TRUE, NULL,
           $13, $14, '{}'::jsonb, $15, $16
         )`,
        [
          deviceId,
          deviceUid,
          hardwareUid,
          buildUnclaimedName(hardwareUid),
          tokenHash,
          payload.model,
          payload.device_class,
          JSON.stringify(normalizedCapabilities),
          payload.relay_count,
          payload.button_count,
          JSON.stringify(relayNames),
          payload.firmware_version ?? null,
          claimCode,
          now,
          now,
          now
        ]
      );

      for (let relayIndex = 0; relayIndex < payload.relay_count; relayIndex += 1) {
        await client.query(
          `INSERT INTO relay_states (
             id, device_id, relay_index, relay_name, is_on, last_changed_at
           ) VALUES ($1, $2, $3, $4, FALSE, $5)`,
          [newId(), deviceId, relayIndex, relayNames[relayIndex], now]
        );
      }

      return {
        deviceId,
        deviceUid,
        claimCode,
        claimed: false
      };
    });

    return reply.send({
      device_id: provisioned.deviceId,
      device_uid: provisioned.deviceUid,
      device_token: rawToken,
      claim_code: provisioned.claimCode,
      claimed: provisioned.claimed
    });
  });
}
