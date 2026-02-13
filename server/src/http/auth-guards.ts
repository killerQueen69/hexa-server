import { FastifyReply, FastifyRequest } from "fastify";
import { sendApiError } from "./api-error";

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    await request.jwtVerify();
  } catch {
    sendApiError(reply, 401, "unauthorized", "Authentication required.");
  }
}

export function requireRole(allowedRoles: string[]) {
  return async function roleGuard(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    if (!request.user || !allowedRoles.includes(request.user.role)) {
      sendApiError(reply, 403, "forbidden", "Insufficient role.");
    }
  };
}
