ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS claim_code TEXT,
  ADD COLUMN IF NOT EXISTS claim_code_created_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS hardware_uid TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_hardware_uid_unique
  ON devices(hardware_uid)
  WHERE hardware_uid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_owner_user
  ON devices(owner_user_id);

CREATE INDEX IF NOT EXISTS idx_devices_claim_code
  ON devices(claim_code)
  WHERE claim_code IS NOT NULL;

-- Backfill ownership from existing user-device mappings when available.
UPDATE devices d
SET owner_user_id = src.user_id
FROM (
  SELECT device_id, MIN(user_id) AS user_id
  FROM user_devices
  GROUP BY device_id
) AS src
WHERE d.id = src.device_id
  AND d.owner_user_id IS NULL;

-- Ensure unowned devices are claimable.
UPDATE devices
SET claim_code = UPPER(SUBSTRING(MD5(device_uid || now()::text || random()::text) FROM 1 FOR 8)),
    claim_code_created_at = now()
WHERE owner_user_id IS NULL
  AND (claim_code IS NULL OR claim_code = '');
