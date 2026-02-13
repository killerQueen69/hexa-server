import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { env } from "../config/env";
import { query } from "../db/connection";
import { newId } from "../utils/crypto";
import { nowIso } from "../utils/time";

type BackupTableDump = {
  row_count: number;
  rows: Record<string, unknown>[];
};

type BackupEnvelope = {
  schema_version: number;
  created_at: string;
  created_by: string;
  tables: Record<string, BackupTableDump>;
};

type EncryptedPayload = {
  alg: "aes-256-gcm";
  iv: string;
  auth_tag: string;
  ciphertext: string;
  key_fingerprint: string;
  created_at: string;
};

type OpsRunRow = {
  id: string;
  operation: "backup" | "restore_drill";
  started_at: Date | string;
  finished_at: Date | string | null;
  status: "running" | "ok" | "error";
  backup_path: string | null;
  metadata: unknown;
  error_message: string | null;
};

const BACKUP_TABLES = [
  "users",
  "devices",
  "user_devices",
  "relay_states",
  "schedules",
  "automation_rules",
  "audit_log",
  "refresh_tokens",
  "ota_releases",
  "ota_reports",
  "ota_signing_keys",
  "idempotency_keys"
] as const;

function toIso(value: Date | string | null): string | null {
  if (!value) {
    return null;
  }
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function parseEncryptionKey(raw: string | undefined): Buffer | null {
  if (!raw || raw.trim().length === 0) {
    return null;
  }

  const trimmed = raw.trim();
  if (trimmed.startsWith("base64:")) {
    return Buffer.from(trimmed.slice(7), "base64");
  }
  if (trimmed.startsWith("hex:")) {
    return Buffer.from(trimmed.slice(4), "hex");
  }
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }

  return createHash("sha256").update(trimmed).digest();
}

function resolveEncryptionKey(): Buffer {
  const explicit = parseEncryptionKey(env.BACKUP_ENCRYPTION_KEY);
  if (explicit && explicit.length === 32) {
    return explicit;
  }
  if (env.NODE_ENV !== "production") {
    return createHash("sha256").update(env.JWT_SECRET).digest();
  }
  throw new Error("backup_encryption_key_missing");
}

function resolveBackupDir(): string {
  const absolute = path.resolve(process.cwd(), env.BACKUP_OUTPUT_DIR);
  mkdirSync(absolute, { recursive: true });
  return absolute;
}

function backupFilesInDir(directory: string): string[] {
  return readdirSync(directory)
    .filter((name) => name.startsWith("backup-") && name.endsWith(".json.enc"))
    .map((name) => path.join(directory, name))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
}

function encryptPayload(plaintext: string, key: Buffer): EncryptedPayload {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    alg: "aes-256-gcm",
    iv: iv.toString("base64url"),
    auth_tag: authTag.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    key_fingerprint: createHash("sha256").update(key).digest("hex").slice(0, 16),
    created_at: nowIso()
  };
}

function decryptPayload(payload: EncryptedPayload, key: Buffer): string {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64url")
  );
  decipher.setAuthTag(Buffer.from(payload.auth_tag, "base64url"));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64url")),
    decipher.final()
  ]);
  return plaintext.toString("utf8");
}

function serializeRun(row: OpsRunRow) {
  return {
    id: row.id,
    operation: row.operation,
    started_at: toIso(row.started_at),
    finished_at: toIso(row.finished_at),
    status: row.status,
    backup_path: row.backup_path,
    metadata: asObject(row.metadata),
    error_message: row.error_message
  };
}

async function insertRun(operation: "backup" | "restore_drill"): Promise<string> {
  const id = newId();
  await query(
    `INSERT INTO ops_backup_runs (
       id, operation, status, started_at, metadata
     ) VALUES (
       $1, $2, 'running', $3, '{}'::jsonb
     )`,
    [id, operation, nowIso()]
  );
  return id;
}

async function finishRun(params: {
  runId: string;
  status: "ok" | "error";
  backupPath?: string;
  metadata?: Record<string, unknown>;
  errorMessage?: string;
}): Promise<void> {
  await query(
    `UPDATE ops_backup_runs
     SET status = $1,
         backup_path = $2,
         metadata = $3::jsonb,
         error_message = $4,
         finished_at = $5
     WHERE id = $6`,
    [
      params.status,
      params.backupPath ?? null,
      JSON.stringify(params.metadata ?? {}),
      params.errorMessage ?? null,
      nowIso(),
      params.runId
    ]
  );
}

async function dumpTable(tableName: string): Promise<BackupTableDump> {
  const result = await query<{ row: Record<string, unknown> }>(
    `SELECT row_to_json(t)::jsonb AS row
     FROM (SELECT * FROM ${tableName}) AS t`
  );
  return {
    row_count: result.rows.length,
    rows: result.rows.map((row) => row.row)
  };
}

function parseEncryptedFile(content: string): EncryptedPayload {
  const parsed = JSON.parse(content) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("backup_file_invalid");
  }

  const record = parsed as Record<string, unknown>;
  if (
    record.alg !== "aes-256-gcm" ||
    typeof record.iv !== "string" ||
    typeof record.auth_tag !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new Error("backup_file_invalid");
  }

  return {
    alg: "aes-256-gcm",
    iv: record.iv,
    auth_tag: record.auth_tag,
    ciphertext: record.ciphertext,
    key_fingerprint: typeof record.key_fingerprint === "string" ? record.key_fingerprint : "",
    created_at: typeof record.created_at === "string" ? record.created_at : nowIso()
  };
}

function parseEnvelope(raw: string): BackupEnvelope {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("backup_payload_invalid");
  }
  const envelope = parsed as Record<string, unknown>;
  if (!envelope.tables || typeof envelope.tables !== "object" || Array.isArray(envelope.tables)) {
    throw new Error("backup_payload_invalid");
  }

  const tables = envelope.tables as Record<string, unknown>;
  for (const table of BACKUP_TABLES) {
    if (!tables[table] || typeof tables[table] !== "object") {
      throw new Error(`backup_table_missing:${table}`);
    }
  }

  return {
    schema_version: Number(envelope.schema_version ?? 0),
    created_at: String(envelope.created_at ?? ""),
    created_by: String(envelope.created_by ?? "system"),
    tables: tables as Record<string, BackupTableDump>
  };
}

class OpsBackupService {
  async runBackup(params?: { initiatedBy?: string }): Promise<{
    run_id: string;
    backup_path: string;
    row_counts: Record<string, number>;
    deleted_old_backups: string[];
  }> {
    const runId = await insertRun("backup");
    const started = Date.now();

    try {
      const key = resolveEncryptionKey();
      const directory = resolveBackupDir();
      const dumps = await Promise.all(BACKUP_TABLES.map(async (table) => [table, await dumpTable(table)] as const));

      const tables: Record<string, BackupTableDump> = {};
      const rowCounts: Record<string, number> = {};
      for (const [table, dump] of dumps) {
        tables[table] = dump;
        rowCounts[table] = dump.row_count;
      }

      const envelope: BackupEnvelope = {
        schema_version: 1,
        created_at: nowIso(),
        created_by: params?.initiatedBy ?? "system",
        tables
      };

      const encrypted = encryptPayload(JSON.stringify(envelope), key);
      const fileName = `backup-${new Date().toISOString().replace(/[-:.]/g, "")}-${runId}.json.enc`;
      const fullPath = path.join(directory, fileName);
      writeFileSync(fullPath, JSON.stringify(encrypted), "utf8");

      const files = backupFilesInDir(directory);
      const toDelete = files.slice(env.BACKUP_RETENTION_COUNT);
      const deleted: string[] = [];
      for (const candidate of toDelete) {
        rmSync(candidate, { force: true });
        deleted.push(path.basename(candidate));
      }

      await finishRun({
        runId,
        status: "ok",
        backupPath: fullPath,
        metadata: {
          row_counts: rowCounts,
          elapsed_ms: Date.now() - started,
          deleted_old_backups: deleted
        }
      });

      return {
        run_id: runId,
        backup_path: fullPath,
        row_counts: rowCounts,
        deleted_old_backups: deleted
      };
    } catch (error) {
      await finishRun({
        runId,
        status: "error",
        errorMessage: error instanceof Error ? error.message : "backup_failed"
      });
      throw error;
    }
  }

  async runRestoreDrill(params?: { backupPath?: string }): Promise<{
    run_id: string;
    backup_path: string;
    backup_row_counts: Record<string, number>;
    live_row_counts: Record<string, number>;
    elapsed_ms: number;
    rto_target_met: boolean;
  }> {
    const runId = await insertRun("restore_drill");
    const started = Date.now();

    try {
      const key = resolveEncryptionKey();
      const directory = resolveBackupDir();
      const backupPath = params?.backupPath
        ? path.resolve(process.cwd(), params.backupPath)
        : backupFilesInDir(directory)[0];

      if (!backupPath) {
        throw new Error("backup_not_found");
      }

      const encrypted = parseEncryptedFile(readFileSync(backupPath, "utf8"));
      const plaintext = decryptPayload(encrypted, key);
      const envelope = parseEnvelope(plaintext);

      const backupRowCounts: Record<string, number> = {};
      for (const table of BACKUP_TABLES) {
        const dump = envelope.tables[table];
        backupRowCounts[table] = Number(dump?.row_count ?? 0);
      }

      const liveRowCounts: Record<string, number> = {};
      for (const table of BACKUP_TABLES) {
        const result = await query<{ total: string }>(
          `SELECT COUNT(*)::text AS total FROM ${table}`
        );
        liveRowCounts[table] = Number(result.rows[0]?.total ?? "0");
      }

      const elapsedMs = Date.now() - started;
      const rtoTargetMs = env.BACKUP_RTO_MINUTES * 60 * 1000;
      const rtoTargetMet = elapsedMs <= rtoTargetMs;
      if (!rtoTargetMet) {
        throw new Error("restore_drill_rto_target_exceeded");
      }

      await finishRun({
        runId,
        status: "ok",
        backupPath,
        metadata: {
          backup_row_counts: backupRowCounts,
          live_row_counts: liveRowCounts,
          elapsed_ms: elapsedMs,
          rto_target_minutes: env.BACKUP_RTO_MINUTES,
          rto_target_met: true
        }
      });

      return {
        run_id: runId,
        backup_path: backupPath,
        backup_row_counts: backupRowCounts,
        live_row_counts: liveRowCounts,
        elapsed_ms: elapsedMs,
        rto_target_met: true
      };
    } catch (error) {
      await finishRun({
        runId,
        status: "error",
        metadata: {
          rto_target_minutes: env.BACKUP_RTO_MINUTES
        },
        errorMessage: error instanceof Error ? error.message : "restore_drill_failed"
      });
      throw error;
    }
  }

  async listRuns(limit = 50): Promise<ReturnType<typeof serializeRun>[]> {
    const safeLimit = Number.isFinite(limit) ? Math.min(Math.max(Math.trunc(limit), 1), 500) : 50;
    const result = await query<OpsRunRow>(
      `SELECT
         id, operation, started_at, finished_at, status,
         backup_path, metadata, error_message
       FROM ops_backup_runs
       ORDER BY started_at DESC
       LIMIT $1`,
      [safeLimit]
    );
    return result.rows.map((row) => serializeRun(row));
  }

  getPolicy(): {
    output_dir: string;
    retention_count: number;
    encryption_configured: boolean;
    rpo_minutes: number;
    rto_minutes: number;
  } {
    const key = parseEncryptionKey(env.BACKUP_ENCRYPTION_KEY);
    return {
      output_dir: path.resolve(process.cwd(), env.BACKUP_OUTPUT_DIR),
      retention_count: env.BACKUP_RETENTION_COUNT,
      encryption_configured: Boolean(key && key.length === 32),
      rpo_minutes: env.BACKUP_RPO_MINUTES,
      rto_minutes: env.BACKUP_RTO_MINUTES
    };
  }
}

export const opsBackupService = new OpsBackupService();
