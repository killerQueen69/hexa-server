import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { env } from "../config/env";

type SecretMap = Record<string, string>;

class SecretManager {
  private readonly fileSecrets: SecretMap;
  private readonly inlineSecrets: SecretMap;

  constructor() {
    this.fileSecrets = this.loadFileSecrets();
    this.inlineSecrets = this.parseJsonMap(env.OTA_SIGNING_PRIVATE_KEYS_JSON ?? "{}");
  }

  resolveSecret(ref: string): string | null {
    const trimmed = ref.trim();
    if (trimmed.length === 0) {
      return null;
    }

    if (trimmed.startsWith("env:")) {
      const envVar = trimmed.slice(4).trim();
      if (!envVar) {
        return null;
      }
      return process.env[envVar] ?? null;
    }

    if (trimmed.startsWith("file:")) {
      const fileRef = trimmed.slice(5).trim();
      const [filePathRaw, keyRaw] = fileRef.split("#");
      const filePath = path.resolve(process.cwd(), filePathRaw);
      if (!existsSync(filePath)) {
        return null;
      }
      const parsed = this.parseJsonMap(readFileSync(filePath, "utf8"));
      if (keyRaw && keyRaw.trim().length > 0) {
        return parsed[keyRaw.trim()] ?? null;
      }
      return null;
    }

    return this.inlineSecrets[trimmed] ?? this.fileSecrets[trimmed] ?? process.env[trimmed] ?? null;
  }

  resolveSigningPrivateKey(secretRef: string): string | null {
    return this.resolveSecret(secretRef);
  }

  private loadFileSecrets(): SecretMap {
    if (!env.SECRET_MANAGER_FILE) {
      return {};
    }

    const secretFilePath = path.resolve(process.cwd(), env.SECRET_MANAGER_FILE);
    if (!existsSync(secretFilePath)) {
      return {};
    }

    const raw = readFileSync(secretFilePath, "utf8");
    return this.parseJsonMap(raw);
  }

  private parseJsonMap(raw: string): SecretMap {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return {};
      }

      const out: SecretMap = {};
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value === "string") {
          out[key] = value;
        }
      }
      return out;
    } catch {
      return {};
    }
  }
}

export const secretManager = new SecretManager();
