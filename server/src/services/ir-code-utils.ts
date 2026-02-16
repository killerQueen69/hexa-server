import { sha256 } from "../utils/crypto";

export const IR_PAYLOAD_FORMAT_VALUES = ["raw", "hex", "base64", "json"] as const;

export type IrPayloadFormat = (typeof IR_PAYLOAD_FORMAT_VALUES)[number];

export type IrNormalizationInput = {
  protocol: string;
  frequencyHz?: number | null;
  payload: string;
  payloadFormat?: string | null;
};

export type IrNormalizationResult = {
  protocolNorm: string;
  frequencyNormHz: number | null;
  payloadFormat: IrPayloadFormat;
  payloadCanonical: string;
  payloadFingerprint: string;
  normalizedPayload: Record<string, unknown>;
};

export type IrRankableRecord = {
  source: "device" | "library";
  codeId: string;
  codeName: string | null;
  libraryRecordId: string | null;
  protocolNorm: string;
  frequencyNormHz: number | null;
  payloadFingerprint: string;
  payloadCanonical: string;
  brand: string | null;
  model: string | null;
  metadata: Record<string, unknown>;
};

export type IrRankOptions = {
  brandHint?: string | null;
  modelHint?: string | null;
  topN?: number;
};

export type IrRankedMatch = {
  source: "device" | "library";
  code_id: string;
  code_name: string | null;
  library_record_id: string | null;
  protocol_norm: string;
  frequency_norm_hz: number | null;
  payload_fingerprint: string;
  brand: string | null;
  model: string | null;
  confidence: number;
  explanation: string[];
  metadata: Record<string, unknown>;
};

function normalizeProtocol(raw: string): string {
  const normalized = raw.trim().replace(/\s+/g, "_").toUpperCase();
  return normalized.length > 0 ? normalized : "UNKNOWN";
}

function normalizeFrequency(raw: number | null | undefined): number | null {
  if (typeof raw !== "number" || !Number.isFinite(raw)) {
    return null;
  }
  const rounded = Math.trunc(raw);
  if (rounded <= 0) {
    return null;
  }
  return rounded;
}

function normalizePayloadFormat(raw: string | null | undefined): IrPayloadFormat {
  if (typeof raw !== "string") {
    return "raw";
  }
  const lowered = raw.trim().toLowerCase();
  if (lowered === "hex" || lowered === "base64" || lowered === "json" || lowered === "raw") {
    return lowered;
  }
  return "raw";
}

function normalizeHexPayload(raw: string): string {
  const normalized = raw.toUpperCase().replace(/[^0-9A-F]/g, "");
  return normalized.length > 0 ? normalized : "0";
}

function normalizeBase64Payload(raw: string): string {
  return raw
    .trim()
    .replace(/\s+/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function normalizeRawPayload(raw: string): string {
  const normalized = raw.trim().replace(/\s+/g, " ");
  return normalized.length > 0 ? normalized : "0";
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortJsonValue(item));
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const record = value as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort((a, b) => a.localeCompare(b));
  const out: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    out[key] = sortJsonValue(record[key]);
  }
  return out;
}

function normalizeJsonPayload(raw: string): {
  canonical: string;
  normalizedPayload: Record<string, unknown>;
} {
  try {
    const parsed = JSON.parse(raw) as unknown;
    const sorted = sortJsonValue(parsed);
    const canonical = JSON.stringify(sorted);
    if (Array.isArray(sorted)) {
      return {
        canonical,
        normalizedPayload: {
          shape: "array",
          item_count: sorted.length
        }
      };
    }
    if (sorted && typeof sorted === "object") {
      return {
        canonical,
        normalizedPayload: {
          shape: "object",
          key_count: Object.keys(sorted as Record<string, unknown>).length
        }
      };
    }
    return {
      canonical,
      normalizedPayload: {
        shape: typeof sorted
      }
    };
  } catch {
    const canonical = normalizeRawPayload(raw);
    return {
      canonical,
      normalizedPayload: {
        shape: "string",
        parse_error: true
      }
    };
  }
}

export function normalizeIrPayload(input: IrNormalizationInput): IrNormalizationResult {
  const protocolNorm = normalizeProtocol(input.protocol);
  const frequencyNormHz = normalizeFrequency(input.frequencyHz ?? null);
  const payloadFormat = normalizePayloadFormat(input.payloadFormat);

  let payloadCanonical = "";
  let normalizedPayload: Record<string, unknown> = {};
  if (payloadFormat === "hex") {
    payloadCanonical = normalizeHexPayload(input.payload);
    normalizedPayload = {
      shape: "hex",
      token_count: Math.floor(payloadCanonical.length / 2)
    };
  } else if (payloadFormat === "base64") {
    payloadCanonical = normalizeBase64Payload(input.payload);
    normalizedPayload = {
      shape: "base64url",
      length: payloadCanonical.length
    };
  } else if (payloadFormat === "json") {
    const normalizedJson = normalizeJsonPayload(input.payload);
    payloadCanonical = normalizedJson.canonical;
    normalizedPayload = normalizedJson.normalizedPayload;
  } else {
    payloadCanonical = normalizeRawPayload(input.payload);
    const tokens = payloadCanonical.split(/[,\s]+/).filter((item) => item.length > 0);
    normalizedPayload = {
      shape: "raw",
      token_count: tokens.length
    };
  }

  const payloadFingerprint = sha256(
    `${protocolNorm}|${frequencyNormHz ?? 0}|${payloadFormat}|${payloadCanonical}`
  );

  return {
    protocolNorm,
    frequencyNormHz,
    payloadFormat,
    payloadCanonical,
    payloadFingerprint,
    normalizedPayload
  };
}

function normalizeHint(raw: string | null | undefined): string {
  if (!raw) {
    return "";
  }
  return raw
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, " ");
}

function sharedPrefixRatio(a: string, b: string): number {
  if (!a || !b) {
    return 0;
  }
  const len = Math.min(a.length, b.length);
  let same = 0;
  for (let i = 0; i < len; i += 1) {
    if (a[i] !== b[i]) {
      break;
    }
    same += 1;
  }
  return same / Math.max(a.length, b.length);
}

function scoreFrequency(candidate: number | null, target: number | null): number {
  if (!candidate && !target) {
    return 0.04;
  }
  if (!candidate || !target) {
    return 0;
  }
  const delta = Math.abs(candidate - target);
  const tolerance = Math.max(candidate, target);
  if (tolerance <= 0) {
    return 0;
  }
  const ratio = Math.max(0, 1 - delta / tolerance);
  return ratio * 0.2;
}

function includesHint(target: string | null, hint: string): boolean {
  if (!target || !hint) {
    return false;
  }
  return normalizeHint(target).includes(hint);
}

function clamp(value: number, min: number, max: number): number {
  if (value < min) {
    return min;
  }
  if (value > max) {
    return max;
  }
  return value;
}

export function rankIrMatches(
  candidate: IrNormalizationResult,
  records: IrRankableRecord[],
  options: IrRankOptions = {}
): IrRankedMatch[] {
  const brandHint = normalizeHint(options.brandHint);
  const modelHint = normalizeHint(options.modelHint);
  const topN = Math.min(Math.max(options.topN ?? 5, 1), 20);

  const scored = records.map((record) => {
    let score = 0;
    const explanation: string[] = [];

    if (candidate.protocolNorm === record.protocolNorm) {
      score += 0.4;
      explanation.push("protocol_exact");
    } else if (
      candidate.protocolNorm.includes(record.protocolNorm) ||
      record.protocolNorm.includes(candidate.protocolNorm)
    ) {
      score += 0.12;
      explanation.push("protocol_partial");
    }

    if (candidate.payloadFingerprint === record.payloadFingerprint) {
      score += 0.25;
      explanation.push("fingerprint_exact");
    } else {
      const prefixRatio = sharedPrefixRatio(candidate.payloadFingerprint, record.payloadFingerprint);
      if (prefixRatio > 0) {
        score += prefixRatio * 0.18;
        explanation.push("fingerprint_partial");
      }
    }

    const payloadShapeSimilarity = sharedPrefixRatio(
      candidate.payloadCanonical.slice(0, 64),
      record.payloadCanonical.slice(0, 64)
    );
    if (payloadShapeSimilarity > 0) {
      score += payloadShapeSimilarity * 0.08;
      explanation.push("payload_shape");
    }

    const frequencyScore = scoreFrequency(candidate.frequencyNormHz, record.frequencyNormHz);
    if (frequencyScore > 0) {
      score += frequencyScore;
      explanation.push("frequency_compatible");
    }

    if (brandHint && includesHint(record.brand, brandHint)) {
      score += 0.06;
      explanation.push("brand_hint");
    }
    if (modelHint && includesHint(record.model, modelHint)) {
      score += 0.08;
      explanation.push("model_hint");
    }

    if (record.source === "device") {
      score += 0.03;
      explanation.push("device_prior");
    }

    const confidence = Number(clamp(score, 0, 1).toFixed(4));
    return {
      source: record.source,
      code_id: record.codeId,
      code_name: record.codeName,
      library_record_id: record.libraryRecordId,
      protocol_norm: record.protocolNorm,
      frequency_norm_hz: record.frequencyNormHz,
      payload_fingerprint: record.payloadFingerprint,
      brand: record.brand,
      model: record.model,
      confidence,
      explanation,
      metadata: record.metadata
    } satisfies IrRankedMatch;
  });

  scored.sort((a, b) => {
    if (b.confidence !== a.confidence) {
      return b.confidence - a.confidence;
    }
    return a.code_id.localeCompare(b.code_id);
  });

  return scored.slice(0, topN);
}
