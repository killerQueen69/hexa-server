import bcrypt from "bcrypt";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import { env } from "../../config/env";
import { query, withTransaction } from "../../db/connection";
import { sendApiError } from "../../http/api-error";
import { automationService } from "../../services/automation-service";
import { newId, randomToken, sha256 } from "../../utils/crypto";
import { daysFromNowIso, nowIso } from "../../utils/time";

const registerSchema = z.object({
  email: z.string().email().transform((v) => v.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100).transform((v) => v.trim()),
  claim_code: z.string().min(6).max(24).regex(/^[a-zA-Z0-9]+$/).optional()
});

const loginSchema = z.object({
  email: z.string().email().transform((v) => v.trim().toLowerCase()),
  password: z.string().min(8).max(128)
});

const refreshSchema = z.object({
  refresh_token: z.string().min(20)
});

type UserRow = {
  id: string;
  email: string;
  password_hash: string;
  name: string;
  role: string;
  is_active: boolean;
  created_at: Date | string;
  updated_at: Date | string;
};

type PublicUser = Omit<UserRow, "password_hash"> & {
  created_at: string;
  updated_at: string;
};

type RefreshLookupRow = {
  id: string;
  user_id: string;
  expires_at: Date | string;
  revoked_at: Date | string | null;
  email: string;
  role: string;
  name: string;
  is_active: boolean;
  created_at: Date | string;
  updated_at: Date | string;
};

type Queryable = {
  query: (
    sql: string,
    params?: unknown[]
  ) => Promise<{ rows: unknown[]; rowCount: number | null }>;
};

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toPublicUser(user: UserRow): PublicUser {
  const { password_hash, created_at, updated_at, ...publicUser } = user;
  return {
    ...publicUser,
    created_at: toIso(created_at),
    updated_at: toIso(updated_at)
  };
}

function issueAccessToken(server: FastifyInstance, user: PublicUser): string {
  return server.jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role
    },
    {
      expiresIn: "15m"
    }
  );
}

function getUserAgent(header: string | string[] | undefined): string | undefined {
  if (Array.isArray(header)) {
    return header[0];
  }
  return header;
}

async function insertRefreshToken(
  executor: Queryable,
  params: {
    userId: string;
    ip?: string;
    userAgent?: string;
  }
): Promise<{ tokenId: string; rawToken: string }> {
  const rawToken = randomToken();
  const tokenHash = sha256(rawToken);
  const tokenId = newId();
  const expiresAt = daysFromNowIso(30);

  await executor.query(
    `INSERT INTO refresh_tokens (
      id, user_id, token_hash, expires_at, created_ip, user_agent
    ) VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      tokenId,
      params.userId,
      tokenHash,
      expiresAt,
      params.ip ?? null,
      params.userAgent ?? null
    ]
  );

  return { tokenId, rawToken };
}

export async function authRoutes(server: FastifyInstance): Promise<void> {
  server.post("/register", async (request, reply) => {
    const parsed = registerSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const { email, password, name, claim_code } = parsed.data;
    const existing = await query<{ id: string }>(
      "SELECT id FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (existing.rowCount && existing.rowCount > 0) {
      return sendApiError(reply, 409, "email_exists", "Email is already registered.");
    }

    const id = newId();
    const passwordHash = await bcrypt.hash(password, env.BCRYPT_ROUNDS);

    try {
      const registration = await withTransaction(async (client) => {
        const inserted = await client.query<UserRow>(
          `INSERT INTO users (
             id, email, password_hash, name, role
           ) VALUES ($1, $2, $3, $4, 'user')
           RETURNING id, email, password_hash, name, role, is_active, created_at, updated_at`,
          [id, email, passwordHash, name]
        );
        const user = inserted.rows[0];

        let claimedDeviceUid: string | null = null;
        let claimedDeviceId: string | null = null;
        if (claim_code) {
          const claimCode = claim_code.trim().toUpperCase();
          const claimTarget = await client.query<{ id: string; device_uid: string }>(
            `SELECT id, device_uid
             FROM devices
             WHERE claim_code = $1
               AND owner_user_id IS NULL
               AND is_active = TRUE
             LIMIT 1
             FOR UPDATE`,
            [claimCode]
          );

          const claimRow = claimTarget.rows[0];
          if (!claimRow) {
            const error = new Error("claim_code_invalid");
            throw error;
          }

          await client.query(
            `UPDATE devices
             SET owner_user_id = $1,
                 updated_at = $2
             WHERE id = $3`,
            [user.id, nowIso(), claimRow.id]
          );

          await client.query("DELETE FROM user_devices WHERE device_id = $1", [claimRow.id]);
          await client.query(
            `INSERT INTO user_devices (id, user_id, device_id, permission, created_at)
             VALUES ($1, $2, $3, 'admin', $4)`,
            [newId(), user.id, claimRow.id, nowIso()]
          );

          claimedDeviceId = claimRow.id;
          claimedDeviceUid = claimRow.device_uid;
        }

        const refresh = await insertRefreshToken(client, {
          userId: user.id,
          ip: request.ip,
          userAgent: getUserAgent(request.headers["user-agent"])
        });

        return {
          user,
          refreshToken: refresh.rawToken,
          claimedDeviceUid,
          claimedDeviceId
        };
      });

      if (registration.claimedDeviceId) {
        await automationService.ensureDefaultHoldRule(
          registration.user.id,
          registration.claimedDeviceId
        );
      }

      const publicUser = toPublicUser(registration.user);
      const accessToken = issueAccessToken(server, publicUser);

      return reply.code(201).send({
        user: publicUser,
        access_token: accessToken,
        refresh_token: registration.refreshToken,
        claimed_device_uid: registration.claimedDeviceUid
      });
    } catch (error) {
      if (error instanceof Error && error.message === "claim_code_invalid") {
        return sendApiError(reply, 404, "claim_code_invalid", "Claim code is invalid or already used.");
      }
      throw error;
    }
  });

  server.post("/login", async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const { email, password } = parsed.data;
    const result = await query<UserRow>(
      `SELECT id, email, password_hash, name, role, is_active, created_at, updated_at
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );
    const user = result.rows[0];

    if (!user || user.is_active !== true) {
      return sendApiError(reply, 401, "invalid_credentials", "Invalid email or password.");
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return sendApiError(reply, 401, "invalid_credentials", "Invalid email or password.");
    }

    const publicUser = toPublicUser(user);
    const accessToken = issueAccessToken(server, publicUser);
    const refresh = await insertRefreshToken(poolClientAdapter, {
      userId: publicUser.id,
      ip: request.ip,
      userAgent: getUserAgent(request.headers["user-agent"])
    });

    return reply.send({
      user: publicUser,
      access_token: accessToken,
      refresh_token: refresh.rawToken
    });
  });

  server.post("/refresh", async (request, reply) => {
    const parsed = refreshSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const tokenHash = sha256(parsed.data.refresh_token);
    const refreshLookup = await query<RefreshLookupRow>(
      `SELECT
         rt.id,
         rt.user_id,
         rt.expires_at,
         rt.revoked_at,
         u.email,
         u.role,
         u.name,
         u.is_active,
         u.created_at,
         u.updated_at
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1
       LIMIT 1`,
      [tokenHash]
    );
    const row = refreshLookup.rows[0];

    if (!row || row.is_active !== true) {
      return sendApiError(reply, 401, "invalid_refresh_token", "Refresh token is invalid.");
    }

    if (row.revoked_at) {
      return sendApiError(reply, 401, "invalid_refresh_token", "Refresh token is revoked.");
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return sendApiError(reply, 401, "invalid_refresh_token", "Refresh token has expired.");
    }

    const publicUser: PublicUser = {
      id: row.user_id,
      email: row.email,
      name: row.name,
      role: row.role,
      is_active: row.is_active,
      created_at: toIso(row.created_at),
      updated_at: toIso(row.updated_at)
    };

    const nextRefresh = await withTransaction(async (client) => {
      const next = await insertRefreshToken(client, {
        userId: row.user_id,
        ip: request.ip,
        userAgent: getUserAgent(request.headers["user-agent"])
      });

      await client.query(
        `UPDATE refresh_tokens
         SET revoked_at = $1, replaced_by_token_id = $2
         WHERE id = $3`,
        [nowIso(), next.tokenId, row.id]
      );

      return next;
    });

    const accessToken = issueAccessToken(server, publicUser);
    return reply.send({
      access_token: accessToken,
      refresh_token: nextRefresh.rawToken
    });
  });

  server.post("/logout", async (request, reply) => {
    const parsed = refreshSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendApiError(reply, 400, "validation_error", "Invalid request body.", parsed.error.flatten());
    }

    const tokenHash = sha256(parsed.data.refresh_token);
    await query(
      `UPDATE refresh_tokens
       SET revoked_at = COALESCE(revoked_at, $1)
       WHERE token_hash = $2`,
      [nowIso(), tokenHash]
    );

    return reply.send({ ok: true });
  });
}

const poolClientAdapter: Queryable = { query };
