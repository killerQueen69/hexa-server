import { FastifyInstance } from "fastify";
import { env } from "../../config/env";
import { query } from "../../db/connection";
import { sendApiError } from "../../http/api-error";
import { RelayServiceError, relayService } from "../../services/relay-service";
import { newId } from "../../utils/crypto";
import { nowIso } from "../../utils/time";

type AlexaDirectiveHeader = {
  namespace: string;
  name: string;
  payloadVersion: string;
  messageId: string;
  correlationToken?: string;
};

type AlexaDirective = {
  header: AlexaDirectiveHeader;
  payload: Record<string, unknown>;
  endpoint?: {
    endpointId: string;
    scope?: {
      type?: string;
      token?: string;
    };
  };
};

type AlexaRequestBody = {
  directive?: AlexaDirective;
};

type RelayRow = {
  device_id: string;
  device_uid: string;
  device_name: string;
  model: string;
  relay_index: number;
  relay_name: string;
  is_on: boolean;
};

type RelayOwnershipRow = {
  device_id: string;
  device_uid: string;
  relay_index: number;
  is_on: boolean;
};

function errorResponse(params: {
  type: string;
  message: string;
  correlationToken?: string;
  endpointId?: string;
}) {
  return {
    event: {
      header: {
        namespace: "Alexa",
        name: "ErrorResponse",
        payloadVersion: "3",
        messageId: newId(),
        ...(params.correlationToken ? { correlationToken: params.correlationToken } : {})
      },
      ...(params.endpointId
        ? {
            endpoint: {
              endpointId: params.endpointId
            }
          }
        : {}),
      payload: {
        type: params.type,
        message: params.message
      }
    }
  };
}

function parseRelayEndpointId(endpointId: string): { deviceId: string; relayIndex: number } | null {
  const parts = endpointId.split(":");
  if (parts.length !== 3 || parts[0] !== "relay") {
    return null;
  }
  const relayIndex = Number.parseInt(parts[2], 10);
  if (!Number.isInteger(relayIndex) || relayIndex < 0) {
    return null;
  }
  return {
    deviceId: parts[1],
    relayIndex
  };
}

function stripBearer(token: string): string {
  if (token.toLowerCase().startsWith("bearer ")) {
    return token.slice(7).trim();
  }
  return token.trim();
}

async function verifyAlexaUserId(server: FastifyInstance, token: string): Promise<string | null> {
  try {
    const payload = await server.jwt.verify<{ sub: string }>(stripBearer(token));
    return payload.sub;
  } catch {
    return null;
  }
}

function responseEvent(params: {
  namespace?: string;
  name?: string;
  correlationToken?: string;
  endpointId?: string;
  powerState?: "ON" | "OFF";
  payload?: Record<string, unknown>;
}) {
  return {
    context: params.powerState
      ? {
          properties: [
            {
              namespace: "Alexa.PowerController",
              name: "powerState",
              value: params.powerState,
              timeOfSample: nowIso(),
              uncertaintyInMilliseconds: 500
            },
            {
              namespace: "Alexa.EndpointHealth",
              name: "connectivity",
              value: {
                value: "OK"
              },
              timeOfSample: nowIso(),
              uncertaintyInMilliseconds: 500
            }
          ]
        }
      : undefined,
    event: {
      header: {
        namespace: params.namespace ?? "Alexa",
        name: params.name ?? "Response",
        payloadVersion: "3",
        messageId: newId(),
        ...(params.correlationToken ? { correlationToken: params.correlationToken } : {})
      },
      ...(params.endpointId
        ? {
            endpoint: {
              scope: {
                type: "BearerToken",
                token: "redacted"
              },
              endpointId: params.endpointId
            }
          }
        : {}),
      payload: params.payload ?? {}
    }
  };
}

export async function alexaRoutes(server: FastifyInstance): Promise<void> {
  server.post("/smart-home", async (request, reply) => {
    if (!env.ALEXA_ENABLED) {
      return sendApiError(reply, 503, "alexa_disabled", "Alexa integration is disabled.");
    }

    const body = request.body as AlexaRequestBody | null;
    const directive = body?.directive;
    if (!directive || !directive.header) {
      return reply.code(400).send(
        errorResponse({
          type: "INVALID_DIRECTIVE",
          message: "directive.header is required."
        })
      );
    }

    const header = directive.header;
    const namespace = header.namespace;
    const name = header.name;

    if (namespace === "Alexa.Authorization" && name === "AcceptGrant") {
      return reply.send(
        responseEvent({
          namespace: "Alexa.Authorization",
          name: "AcceptGrant.Response"
        })
      );
    }

    let token = "";
    if (namespace === "Alexa.Discovery") {
      const scope = directive.payload?.scope as { token?: unknown } | undefined;
      token = typeof scope?.token === "string" ? scope.token : "";
    } else {
      token = typeof directive.endpoint?.scope?.token === "string" ? directive.endpoint.scope.token : "";
    }

    if (!token) {
      return reply.code(401).send(
        errorResponse({
          type: "INVALID_AUTHORIZATION_CREDENTIAL",
          message: "Missing OAuth token.",
          correlationToken: header.correlationToken,
          endpointId: directive.endpoint?.endpointId
        })
      );
    }

    const userId = await verifyAlexaUserId(server, token);
    if (!userId) {
      return reply.code(401).send(
        errorResponse({
          type: "INVALID_AUTHORIZATION_CREDENTIAL",
          message: "OAuth token is invalid.",
          correlationToken: header.correlationToken,
          endpointId: directive.endpoint?.endpointId
        })
      );
    }

    if (namespace === "Alexa.Discovery" && name === "Discover") {
      const relays = await query<RelayRow>(
        `SELECT
           d.id AS device_id,
           d.device_uid,
           d.name AS device_name,
           d.model,
           rs.relay_index,
           COALESCE(NULLIF(rs.relay_name, ''), 'Relay ' || (rs.relay_index + 1)::text) AS relay_name,
           rs.is_on
         FROM devices d
         JOIN relay_states rs ON rs.device_id = d.id
         WHERE d.owner_user_id = $1
           AND d.is_active = TRUE
         ORDER BY d.created_at ASC, rs.relay_index ASC`,
        [userId]
      );

      const endpoints = relays.rows.map((row) => ({
        endpointId: `relay:${row.device_id}:${row.relay_index}`,
        manufacturerName: "Hexa Tech",
        friendlyName: `${row.device_name} ${row.relay_name}`,
        description: `${row.model} relay ${row.relay_index + 1}`,
        displayCategories: ["SWITCH"],
        cookie: {
          device_uid: row.device_uid,
          relay_index: row.relay_index
        },
        capabilities: [
          {
            type: "AlexaInterface",
            interface: "Alexa",
            version: "3"
          },
          {
            type: "AlexaInterface",
            interface: "Alexa.PowerController",
            version: "3",
            properties: {
              supported: [{ name: "powerState" }],
              proactivelyReported: false,
              retrievable: true
            }
          },
          {
            type: "AlexaInterface",
            interface: "Alexa.EndpointHealth",
            version: "3",
            properties: {
              supported: [{ name: "connectivity" }],
              proactivelyReported: false,
              retrievable: true
            }
          }
        ]
      }));

      return reply.send({
        event: {
          header: {
            namespace: "Alexa.Discovery",
            name: "Discover.Response",
            payloadVersion: "3",
            messageId: newId()
          },
          payload: {
            endpoints
          }
        }
      });
    }

    if (!directive.endpoint?.endpointId) {
      return reply.code(400).send(
        errorResponse({
          type: "INVALID_DIRECTIVE",
          message: "endpoint.endpointId is required for this directive.",
          correlationToken: header.correlationToken
        })
      );
    }

    const endpointInfo = parseRelayEndpointId(directive.endpoint.endpointId);
    if (!endpointInfo) {
      return reply.code(400).send(
        errorResponse({
          type: "NO_SUCH_ENDPOINT",
          message: "endpointId is invalid.",
          correlationToken: header.correlationToken,
          endpointId: directive.endpoint.endpointId
        })
      );
    }

    const ownedRelay = await query<RelayOwnershipRow>(
      `SELECT
         d.id AS device_id,
         d.device_uid,
         rs.relay_index,
         rs.is_on
       FROM devices d
       JOIN relay_states rs ON rs.device_id = d.id
       WHERE d.id = $1
         AND d.owner_user_id = $2
         AND d.is_active = TRUE
         AND rs.relay_index = $3
       LIMIT 1`,
      [endpointInfo.deviceId, userId, endpointInfo.relayIndex]
    );
    const relay = ownedRelay.rows[0];
    if (!relay) {
      return reply.code(404).send(
        errorResponse({
          type: "NO_SUCH_ENDPOINT",
          message: "Endpoint not found.",
          correlationToken: header.correlationToken,
          endpointId: directive.endpoint.endpointId
        })
      );
    }

    if (namespace === "Alexa.PowerController" && (name === "TurnOn" || name === "TurnOff")) {
      try {
        const action = name === "TurnOn" ? "on" : "off";
        const result = await relayService.setRelay({
          deviceId: relay.device_id,
          relayIndex: relay.relay_index,
          action,
          source: {
            actorUserId: userId,
            source: "alexa"
          }
        });

        return reply.send(
          responseEvent({
            correlationToken: header.correlationToken,
            endpointId: directive.endpoint.endpointId,
            powerState: result.is_on ? "ON" : "OFF"
          })
        );
      } catch (error) {
        if (error instanceof RelayServiceError) {
          const type = error.code === "device_offline"
            ? "ENDPOINT_UNREACHABLE"
            : "BRIDGE_UNREACHABLE";
          return reply.code(409).send(
            errorResponse({
              type,
              message: error.message,
              correlationToken: header.correlationToken,
              endpointId: directive.endpoint.endpointId
            })
          );
        }

        return reply.code(500).send(
          errorResponse({
            type: "INTERNAL_ERROR",
            message: "Failed to execute directive.",
            correlationToken: header.correlationToken,
            endpointId: directive.endpoint.endpointId
          })
        );
      }
    }

    if (namespace === "Alexa" && name === "ReportState") {
      const latest = await query<{ is_on: boolean }>(
        `SELECT is_on
         FROM relay_states
         WHERE device_id = $1
           AND relay_index = $2
         LIMIT 1`,
        [relay.device_id, relay.relay_index]
      );
      const isOn = latest.rows[0]?.is_on ?? relay.is_on;

      return reply.send(
        responseEvent({
          correlationToken: header.correlationToken,
          endpointId: directive.endpoint.endpointId,
          powerState: isOn ? "ON" : "OFF"
        })
      );
    }

    return reply.code(400).send(
      errorResponse({
        type: "INVALID_DIRECTIVE",
        message: "Unsupported Alexa directive.",
        correlationToken: header.correlationToken,
        endpointId: directive.endpoint.endpointId
      })
    );
  });
}
