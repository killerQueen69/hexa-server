import { FastifyReply } from "fastify";
import { metricsService } from "../services/metrics-service";

export function sendApiError(
  reply: FastifyReply,
  statusCode: number,
  code: string,
  message: string,
  details?: unknown
) {
  metricsService.observeApiError({ statusCode, code });
  return reply.code(statusCode).send({
    code,
    message,
    details: details ?? null,
    request_id: reply.request.id
  });
}
