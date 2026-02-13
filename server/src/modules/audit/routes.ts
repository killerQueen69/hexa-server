import { FastifyInstance } from "fastify";
import { query } from "../../db/connection";
import { authenticate } from "../../http/auth-guards";

type AuditRow = {
  id: string;
  device_id: string | null;
  device_uid: string | null;
  device_name: string | null;
  user_id: string | null;
  schedule_id: string | null;
  automation_id: string | null;
  action: string;
  details: unknown;
  source: string | null;
  created_at: Date | string;
};

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function serializeAudit(row: AuditRow) {
  return {
    id: row.id,
    device_id: row.device_id,
    device_uid: row.device_uid,
    device_name: row.device_name,
    user_id: row.user_id,
    schedule_id: row.schedule_id,
    automation_id: row.automation_id,
    action: row.action,
    details: asObject(row.details),
    source: row.source,
    created_at: toIso(row.created_at)
  };
}

export async function auditRoutes(server: FastifyInstance): Promise<void> {
  server.get("/", { preHandler: [authenticate] }, async (request, reply) => {
    const queryParams = request.query as {
      device_id?: string;
      source?: string;
      action?: string;
      limit?: string;
      offset?: string;
    };
    const limit = Math.min(Math.max(Number.parseInt(queryParams.limit ?? "100", 10) || 100, 1), 500);
    const offset = Math.max(Number.parseInt(queryParams.offset ?? "0", 10) || 0, 0);

    const filters: string[] = [];
    const values: unknown[] = [];

    const isAdmin = request.user.role === "admin";
    if (!isAdmin) {
      values.push(request.user.sub);
      filters.push(`d.owner_user_id = $${values.length}`);
    }

    if (queryParams.device_id) {
      values.push(queryParams.device_id);
      filters.push(`a.device_id = $${values.length}`);
    }
    if (queryParams.source) {
      values.push(queryParams.source);
      filters.push(`a.source = $${values.length}`);
    }
    if (queryParams.action) {
      values.push(queryParams.action);
      filters.push(`a.action = $${values.length}`);
    }

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
    values.push(limit);
    const limitArg = values.length;
    values.push(offset);
    const offsetArg = values.length;

    const result = await query<AuditRow>(
      `SELECT
         a.id,
         a.device_id,
         d.device_uid,
         d.name AS device_name,
         a.user_id,
         a.schedule_id,
         a.automation_id,
         a.action,
         a.details,
         a.source,
         a.created_at
       FROM audit_log a
       LEFT JOIN devices d ON d.id = a.device_id
       ${whereClause}
       ORDER BY a.created_at DESC
       LIMIT $${limitArg}
       OFFSET $${offsetArg}`,
      values
    );

    return reply.send(result.rows.map((row) => serializeAudit(row)));
  });
}
