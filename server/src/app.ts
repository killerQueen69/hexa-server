import fastify from "fastify";
import { readFile } from "node:fs/promises";
import path from "node:path";
import jwt from "@fastify/jwt";
import multipart from "@fastify/multipart";
import { env } from "./config/env";
import { query } from "./db/connection";
import { sendApiError } from "./http/api-error";
import { registerIdempotencyHooks } from "./http/idempotency";
import { authRoutes } from "./modules/auth/routes";
import { auditRoutes } from "./modules/audit/routes";
import { adminRoutes } from "./modules/admin/routes";
import { deviceRoutes } from "./modules/devices/routes";
import { deviceFeatureRoutes } from "./modules/device-features/routes";
import { alexaRoutes } from "./modules/alexa/routes";
import { automationRoutes } from "./modules/automations/routes";
import { otaRoutes } from "./modules/ota/routes";
import { preferenceRoutes } from "./modules/preferences/routes";
import { provisionRoutes } from "./modules/provision/routes";
import { scheduleRoutes } from "./modules/schedules/routes";
import { registerRealtimeGateway } from "./modules/realtime/gateway";
import { metricsService } from "./services/metrics-service";
import { relayService } from "./services/relay-service";
import { schedulerService } from "./services/scheduler-service";
import { smartHomeService } from "./services/smart-home-service";

export function buildApp() {
  const testUiPath = path.resolve(process.cwd(), "public", "test-ui.html");
  const dashboardPath = path.resolve(process.cwd(), "public", "dashboard.html");
  const dashboardAssetsDir = path.resolve(process.cwd(), "public", "dashboard");

  const app = fastify({
    logger: true,
    requestIdHeader: "x-request-id",
    requestIdLogLabel: "request_id",
    trustProxy: env.TRUST_PROXY
  });
  app.register(multipart, {
    limits: {
      fileSize: env.OTA_UPLOAD_MAX_BYTES,
      files: 1,
      fields: 24
    }
  });

  if (env.NODE_ENV === "production" && env.ENFORCE_HTTPS) {
    app.addHook("onRequest", async (request, reply) => {
      const forwardedProto = request.headers["x-forwarded-proto"];
      const forwardedProtoValue = Array.isArray(forwardedProto)
        ? forwardedProto[0]
        : forwardedProto;
      const firstForwardedProto = (forwardedProtoValue ?? "")
        .split(",")[0]
        ?.trim()
        .toLowerCase();

      const isEncryptedSocket = Boolean(
        (request.raw.socket as { encrypted?: boolean } | undefined)?.encrypted
      );
      const isSecure = request.protocol === "https" || firstForwardedProto === "https" || isEncryptedSocket;
      if (isSecure) {
        return;
      }

      const host = String(request.headers.host ?? "").toLowerCase();
      if (host.startsWith("localhost") || host.startsWith("127.0.0.1")) {
        return;
      }

      sendApiError(reply, 426, "https_required", "HTTPS is required in production mode.");
    });
  }

  app.register(jwt, {
    secret: env.JWT_SECRET
  });
  registerIdempotencyHooks(app);

  app.get("/health", async () => {
    await query("SELECT 1");
    return {
      status: "ok",
      uptime_seconds: process.uptime(),
      db_engine: "postgres",
      now: new Date().toISOString()
    };
  });

  app.get("/metrics", async (_request, reply) => {
    const [deviceTotals, userTotals] = await Promise.all([
      query<{
        total: string;
        claimed: string;
        unclaimed: string;
        online_estimate: string;
      }>(
        `SELECT
           COUNT(*)::text AS total,
           COUNT(*) FILTER (WHERE owner_user_id IS NOT NULL)::text AS claimed,
           COUNT(*) FILTER (WHERE owner_user_id IS NULL)::text AS unclaimed,
           COUNT(*) FILTER (WHERE last_seen_at > now() - interval '90 seconds')::text AS online_estimate
         FROM devices`
      ),
      query<{ total: string; active: string }>(
        `SELECT
           COUNT(*)::text AS total,
           COUNT(*) FILTER (WHERE is_active = TRUE)::text AS active
         FROM users`
      )
    ]);

    const deviceRow = deviceTotals.rows[0];
    const userRow = userTotals.rows[0];
    const uptime = process.uptime().toFixed(3);
    const customMetrics = metricsService.renderPrometheus();

    reply.type("text/plain; version=0.0.4");
    return [
      "# HELP hexa_uptime_seconds Process uptime in seconds.",
      "# TYPE hexa_uptime_seconds gauge",
      `hexa_uptime_seconds ${uptime}`,
      "# HELP hexa_devices_total Total registered devices.",
      "# TYPE hexa_devices_total gauge",
      `hexa_devices_total ${deviceRow?.total ?? "0"}`,
      "# HELP hexa_devices_claimed_total Total claimed devices.",
      "# TYPE hexa_devices_claimed_total gauge",
      `hexa_devices_claimed_total ${deviceRow?.claimed ?? "0"}`,
      "# HELP hexa_devices_unclaimed_total Total unclaimed devices.",
      "# TYPE hexa_devices_unclaimed_total gauge",
      `hexa_devices_unclaimed_total ${deviceRow?.unclaimed ?? "0"}`,
      "# HELP hexa_devices_online_estimate Approx online devices (last_seen within 90s).",
      "# TYPE hexa_devices_online_estimate gauge",
      `hexa_devices_online_estimate ${deviceRow?.online_estimate ?? "0"}`,
      "# HELP hexa_users_total Total users.",
      "# TYPE hexa_users_total gauge",
      `hexa_users_total ${userRow?.total ?? "0"}`,
      "# HELP hexa_users_active_total Active users.",
      "# TYPE hexa_users_active_total gauge",
      `hexa_users_active_total ${userRow?.active ?? "0"}`,
      customMetrics
    ].join("\n");
  });

  app.get("/test-ui", async (_request, reply) => {
    try {
      const html = await readFile(testUiPath, "utf8");
      reply.type("text/html; charset=utf-8");
      return reply.send(html);
    } catch {
      reply.code(404).type("text/plain; charset=utf-8");
      return reply.send("test-ui.html not found");
    }
  });

  app.get("/dashboard", async (_request, reply) => {
    try {
      const html = await readFile(dashboardPath, "utf8");
      reply.type("text/html; charset=utf-8");
      return reply.send(html);
    } catch {
      reply.code(404).type("text/plain; charset=utf-8");
      return reply.send("dashboard.html not found");
    }
  });

  app.get("/dashboard/*", async (request, reply) => {
    const wildcard = (request.params as { "*": string })["*"] ?? "";
    const normalized = path.posix.normalize(wildcard).replace(/^\/+/, "");
    if (!normalized || normalized.includes("..")) {
      reply.code(404).type("text/plain; charset=utf-8");
      return reply.send("asset not found");
    }

    const assetPath = path.resolve(dashboardAssetsDir, ...normalized.split("/"));
    if (
      assetPath !== dashboardAssetsDir &&
      !assetPath.startsWith(`${dashboardAssetsDir}${path.sep}`)
    ) {
      reply.code(404).type("text/plain; charset=utf-8");
      return reply.send("asset not found");
    }

    try {
      const content = await readFile(assetPath);
      const ext = path.extname(assetPath).toLowerCase();
      if (ext === ".js") {
        reply.type("text/javascript; charset=utf-8");
      } else if (ext === ".css") {
        reply.type("text/css; charset=utf-8");
      } else if (ext === ".json") {
        reply.type("application/json; charset=utf-8");
      } else if (ext === ".svg") {
        reply.type("image/svg+xml");
      } else if (ext === ".png") {
        reply.type("image/png");
      } else if (ext === ".jpg" || ext === ".jpeg") {
        reply.type("image/jpeg");
      } else if (ext === ".webp") {
        reply.type("image/webp");
      } else {
        reply.type("application/octet-stream");
      }
      return reply.send(content);
    } catch {
      reply.code(404).type("text/plain; charset=utf-8");
      return reply.send("asset not found");
    }
  });

  app.register(authRoutes, { prefix: "/api/v1/auth" });
  app.register(provisionRoutes, { prefix: "/api/v1/provision" });
  app.register(deviceRoutes, { prefix: "/api/v1/devices" });
  app.register(deviceFeatureRoutes, { prefix: "/api/v1/devices" });
  app.register(preferenceRoutes, { prefix: "/api/v1/preferences" });
  app.register(auditRoutes, { prefix: "/api/v1/audit" });
  app.register(adminRoutes, { prefix: "/api/v1/admin" });
  app.register(alexaRoutes, { prefix: "/api/v1/alexa" });
  app.register(scheduleRoutes, { prefix: "/api/v1/schedules" });
  app.register(automationRoutes, { prefix: "/api/v1/automations" });
  app.register(otaRoutes, { prefix: "/api/v1/ota" });
  registerRealtimeGateway(app);

  app.addHook("onReady", async () => {
    smartHomeService.setCommandExecutor(async (request) => {
      if (request.scope === "all") {
        if (request.action !== "on" && request.action !== "off") {
          throw new Error("all_scope_invalid_action");
        }
        await relayService.setAllRelays({
          deviceId: request.deviceId,
          action: request.action,
          source: {
            actorUserId: request.actorUserId,
            source: request.source
          }
        });
        return;
      }

      await relayService.setRelay({
        deviceId: request.deviceId,
        relayIndex: request.relayIndex as number,
        action: request.action,
        source: {
          actorUserId: request.actorUserId,
          source: request.source
        }
      });
    });
    await smartHomeService.start(app.log);
    schedulerService.start(app.log);
  });

  app.addHook("onClose", async () => {
    schedulerService.stop();
    await smartHomeService.stop();
  });

  return app;
}
