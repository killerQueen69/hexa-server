ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS ota_channel TEXT NOT NULL DEFAULT 'stable',
  ADD COLUMN IF NOT EXISTS ota_security_version INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_ota_check_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_ota_status TEXT,
  ADD COLUMN IF NOT EXISTS last_ota_reason TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'devices_ota_channel_valid'
  ) THEN
    ALTER TABLE devices
      ADD CONSTRAINT devices_ota_channel_valid
      CHECK (ota_channel IN ('dev', 'beta', 'stable'));
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS ota_releases (
  id TEXT PRIMARY KEY,
  model TEXT NOT NULL,
  version TEXT NOT NULL,
  security_version INTEGER NOT NULL CHECK (security_version >= 0),
  channel TEXT NOT NULL CHECK (channel IN ('dev', 'beta', 'stable')),
  url TEXT NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
  sha256 TEXT NOT NULL,
  signature_alg TEXT NOT NULL,
  signature TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (model, version, channel)
);

CREATE TABLE IF NOT EXISTS ota_reports (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  from_version TEXT,
  to_version TEXT,
  security_version INTEGER,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ota_releases_active
  ON ota_releases(model, channel, is_active, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ota_releases_expiry
  ON ota_releases(expires_at);

CREATE INDEX IF NOT EXISTS idx_ota_reports_device_created
  ON ota_reports(device_id, created_at DESC);
