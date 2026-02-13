import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  DATABASE_URL: z.string().url().default("postgres://postgres:postgres@localhost:5432/relay_platform"),
  TRUST_PROXY: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value === "true"),
  ENFORCE_HTTPS: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value === "true"),
  DB_SSL: z
    .string()
    .optional()
    .transform((value) => value === "true"),
  DB_SSL_REJECT_UNAUTHORIZED: z
    .string()
    .optional()
    .default("true")
    .transform((value) => value !== "false"),
  ALEXA_ENABLED: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value === "true"),
  HOMEKIT_ENABLED: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value === "true"),
  HOMEKIT_BRIDGE_NAME: z.string().default("Hexa Bridge"),
  HOMEKIT_BRIDGE_PIN: z.string().default("031-45-154"),
  HOMEKIT_BRIDGE_USERNAME: z.string().default("0E:AA:00:12:34:56"),
  HOMEKIT_SETUP_ID: z.string().length(4).default("HEXA"),
  HOMEKIT_BRIDGE_PORT: z.coerce.number().int().min(1).max(65535).default(51826),
  HOMEKIT_STORAGE_PATH: z.string().default("./data/homekit"),
  HA_MQTT_ENABLED: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value === "true"),
  HA_MQTT_URL: z.string().optional(),
  HA_MQTT_USERNAME: z.string().optional(),
  HA_MQTT_PASSWORD: z.string().optional(),
  HA_MQTT_REJECT_UNAUTHORIZED: z
    .string()
    .optional()
    .default("true")
    .transform((value) => value !== "false"),
  HA_MQTT_CA_FILE: z.string().optional(),
  HA_MQTT_CERT_FILE: z.string().optional(),
  HA_MQTT_KEY_FILE: z.string().optional(),
  HA_MQTT_KEY_PASSPHRASE: z.string().optional(),
  HA_MQTT_SNI_SERVERNAME: z.string().optional(),
  HA_MQTT_KEEPALIVE_SECONDS: z.coerce.number().int().min(5).max(1200).default(30),
  HA_MQTT_CONNECT_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120000).default(30000),
  HA_MQTT_BASE_TOPIC: z.string().default("hexa"),
  HA_MQTT_DISCOVERY_PREFIX: z.string().default("homeassistant"),
  HA_MQTT_CLIENT_ID: z.string().default("hexa-server-bridge"),
  API_REST_VERSION: z.string().default("v1"),
  API_WS_VERSION: z.string().default("v1"),
  API_DEPRECATION_WINDOW_DAYS: z.coerce.number().int().min(1).max(3650).default(180),
  API_DEPRECATION_NOTICE: z.string().optional(),
  SECRET_MANAGER_FILE: z.string().optional(),
  OTA_SIGNING_PRIVATE_KEYS_JSON: z.string().optional(),
  BACKUP_OUTPUT_DIR: z.string().default("./data/backups"),
  BACKUP_RETENTION_COUNT: z.coerce.number().int().min(1).max(365).default(7),
  BACKUP_ENCRYPTION_KEY: z.string().optional(),
  BACKUP_RPO_MINUTES: z.coerce.number().int().min(1).max(525600).default(1440),
  BACKUP_RTO_MINUTES: z.coerce.number().int().min(1).max(525600).default(60),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  BCRYPT_ROUNDS: z.coerce.number().int().min(8).max(15).default(12),
  DEVICE_PROVISION_KEY: z.string().min(16),
  OTA_ALLOWED_HOSTS: z
    .string()
    .optional()
    .transform((value) =>
      (value ?? "")
        .split(",")
        .map((host) => host.trim().toLowerCase())
        .filter((host) => host.length > 0)
    )
});

export const env = envSchema.parse(process.env);
