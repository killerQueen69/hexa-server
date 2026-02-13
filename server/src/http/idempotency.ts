import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { query } from "../db/connection";
import { newId, sha256 } from "../utils/crypto";
import { sendApiError } from "./api-error";

const TTL_HOURS = 24;
const MAX_KEY_LENGTH = 200;

type MutatingMethod = "POST" | "PATCH" | "PUT" | "DELETE";

type IdempotencyRecord = {
  request_hash: string;
  status_code: number;
  response_body: unknown;
};

type RequestContext = {
  actorKey: string;
  method: string;
  path: string;
  idempotencyKey: string;
  requestHash: string;
};

function isMutatingMethod(method: string): method is MutatingMethod {
  return method === "POST" || method === "PATCH" || method === "PUT" || method === "DELETE";
}

function toKeyValue(value: string | string[] | undefined): string | null {
  if (!value) {
    return null;
  }
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }
  return value;
}

function getActorKey(request: FastifyRequest): string {
  const authorization = toKeyValue(request.headers.authorization)?.trim() ?? "";
  const basis = authorization.length > 0
    ? `auth:${authorization}`
    : `ip:${request.ip}`;
  return sha256(basis);
}

function getRoutePath(request: FastifyRequest): string {
  const [path] = request.url.split("?");
  return path;
}

function getRequestHash(request: FastifyRequest, routePath: string): string {
  const body =
    typeof request.body === "undefined" ? "null" : JSON.stringify(request.body);
  const normalized = `${request.method}|${routePath}|${body}`;
  return sha256(normalized);
}

function getRequestContext(request: FastifyRequest): RequestContext | null {
  return (request as FastifyRequest & { idempotencyContext?: RequestContext }).idempotencyContext ?? null;
}

function setRequestContext(request: FastifyRequest, context: RequestContext): void {
  (request as FastifyRequest & { idempotencyContext?: RequestContext }).idempotencyContext = context;
}

function parseResponseBody(payload: unknown): unknown | null {
  if (typeof payload === "string") {
    if (payload.length === 0) {
      return {};
    }
    try {
      return JSON.parse(payload);
    } catch {
      return null;
    }
  }

  if (Buffer.isBuffer(payload)) {
    try {
      const text = payload.toString("utf8");
      return text.length === 0 ? {} : JSON.parse(text);
    } catch {
      return null;
    }
  }

  if (payload && typeof payload === "object") {
    return payload;
  }

  return null;
}

export function registerIdempotencyHooks(server: FastifyInstance): void {
  server.addHook("preHandler", async (request, reply) => {
    if (!isMutatingMethod(request.method)) {
      return;
    }

    const idempotencyKey = toKeyValue(request.headers["idempotency-key"])?.trim();
    if (!idempotencyKey) {
      return;
    }

    if (idempotencyKey.length > MAX_KEY_LENGTH) {
      sendApiError(reply, 400, "validation_error", "idempotency-key exceeds maximum length.");
      return;
    }

    const routePath = getRoutePath(request);
    const actorKey = getActorKey(request);
    const requestHash = getRequestHash(request, routePath);

    const existing = await query<IdempotencyRecord>(
      `SELECT request_hash, status_code, response_body
       FROM idempotency_keys
       WHERE actor_key = $1
         AND method = $2
         AND path = $3
         AND idempotency_key = $4
         AND expires_at > now()
       LIMIT 1`,
      [actorKey, request.method, routePath, idempotencyKey]
    );

    const row = existing.rows[0];
    if (!row) {
      setRequestContext(request, {
        actorKey,
        method: request.method,
        path: routePath,
        idempotencyKey,
        requestHash
      });
      return;
    }

    if (row.request_hash !== requestHash) {
      sendApiError(
        reply,
        409,
        "idempotency_conflict",
        "idempotency-key was already used with a different request payload."
      );
      return;
    }

    reply.header("idempotency-replayed", "true");
    reply.code(row.status_code);
    reply.send(row.response_body);
  });

  server.addHook("onSend", async (request, reply, payload) => {
    if (!isMutatingMethod(request.method)) {
      return payload;
    }

    const context = getRequestContext(request);
    if (!context) {
      return payload;
    }

    if (reply.statusCode >= 500) {
      return payload;
    }

    const responseBody = parseResponseBody(payload);
    if (responseBody === null) {
      return payload;
    }

    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + TTL_HOURS * 60 * 60 * 1000);

    await query(
      `INSERT INTO idempotency_keys (
         id, actor_key, method, path, idempotency_key, request_hash,
         status_code, response_body, created_at, expires_at
       ) VALUES (
         $1, $2, $3, $4, $5, $6,
         $7, $8::jsonb, $9, $10
       )
       ON CONFLICT (actor_key, method, path, idempotency_key) DO UPDATE
       SET status_code = EXCLUDED.status_code,
           response_body = EXCLUDED.response_body,
           request_hash = EXCLUDED.request_hash,
           created_at = EXCLUDED.created_at,
           expires_at = EXCLUDED.expires_at`,
      [
        newId(),
        context.actorKey,
        context.method,
        context.path,
        context.idempotencyKey,
        context.requestHash,
        reply.statusCode,
        JSON.stringify(responseBody),
        createdAt.toISOString(),
        expiresAt.toISOString()
      ]
    );

    return payload;
  });
}
