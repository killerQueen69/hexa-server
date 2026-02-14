function extractHex(input: string): string {
  return input.replace(/[^a-fA-F0-9]/g, "").toUpperCase();
}

export function deriveStableClaimCode(params: {
  existingClaimCode?: string | null;
  hardwareUid?: string | null;
  deviceUid?: string | null;
  mac?: string | null;
}): string {
  const existing = (params.existingClaimCode ?? "").trim().toUpperCase();
  if (existing.length > 0) {
    return existing;
  }

  const macHex = extractHex(params.mac ?? "");
  if (macHex.length >= 8) {
    return macHex.slice(-8);
  }

  const hwHex = extractHex(params.hardwareUid ?? "");
  if (hwHex.length >= 8) {
    return hwHex.slice(-8);
  }

  const uidHex = extractHex(params.deviceUid ?? "");
  if (uidHex.length >= 8) {
    return uidHex.slice(-8);
  }

  return hwHex.padStart(8, "0").slice(-8);
}
