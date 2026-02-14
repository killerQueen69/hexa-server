import { createSign, createVerify } from "node:crypto";

export type OtaManifestPayload = {
  version: string;
  security_version: number;
  channel: "dev" | "beta" | "stable";
  url: string;
  size_bytes: number;
  sha256: string;
  signature_alg: "ecdsa-p256-sha256";
  expires_at: string;
};

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortDeep(item));
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const input = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(input).sort((a, b) => a.localeCompare(b))) {
    output[key] = sortDeep(input[key]);
  }
  return output;
}

export function canonicalManifestPayload(payload: OtaManifestPayload): OtaManifestPayload {
  return {
    version: payload.version,
    security_version: payload.security_version,
    channel: payload.channel,
    url: payload.url,
    size_bytes: payload.size_bytes,
    sha256: payload.sha256.toLowerCase(),
    signature_alg: "ecdsa-p256-sha256",
    expires_at: payload.expires_at
  };
}

export function canonicalManifestString(payload: OtaManifestPayload): string {
  const canonical = canonicalManifestPayload(payload);
  return JSON.stringify(sortDeep(canonical));
}

function normalizePublicKeyPem(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.includes("-----BEGIN PUBLIC KEY-----")) {
    return `${trimmed}\n`;
  }

  const base64 = trimmed.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
    return raw;
  }

  const lines = base64.match(/.{1,64}/g) ?? [base64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

export function signManifestPayload(payload: OtaManifestPayload, privateKeyPem: string): string {
  const signer = createSign("SHA256");
  signer.update(canonicalManifestString(payload));
  signer.end();
  return signer
    .sign({
      key: privateKeyPem,
      dsaEncoding: "ieee-p1363"
    })
    .toString("base64url");
}

export function verifyManifestSignature(
  payload: OtaManifestPayload,
  signature: string,
  publicKeyPem: string
): boolean {
  const verifier = createVerify("SHA256");
  verifier.update(canonicalManifestString(payload));
  verifier.end();
  const normalizedPublicKeyPem = normalizePublicKeyPem(publicKeyPem);
  try {
    return verifier.verify(
      {
        key: normalizedPublicKeyPem,
        dsaEncoding: "ieee-p1363"
      },
      Buffer.from(signature, "base64url")
    );
  } catch {
    return false;
  }
}
