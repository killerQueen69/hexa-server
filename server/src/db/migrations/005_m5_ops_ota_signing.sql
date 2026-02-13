CREATE TABLE IF NOT EXISTS ota_signing_keys (
  id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL UNIQUE,
  public_key_pem TEXT NOT NULL,
  private_key_secret_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'retired',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at TIMESTAMPTZ
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ota_signing_keys_status_valid'
  ) THEN
    ALTER TABLE ota_signing_keys
      ADD CONSTRAINT ota_signing_keys_status_valid
      CHECK (status IN ('active', 'next', 'retired'));
  END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ota_signing_keys_active_unique
  ON ota_signing_keys(status)
  WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS idx_ota_signing_keys_next_unique
  ON ota_signing_keys(status)
  WHERE status = 'next';

ALTER TABLE ota_releases
  ADD COLUMN IF NOT EXISTS verification_key_id TEXT,
  ADD COLUMN IF NOT EXISTS next_verification_key_id TEXT,
  ADD COLUMN IF NOT EXISTS manifest_payload JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_ota_releases_verification_key_id
  ON ota_releases(verification_key_id);

CREATE TABLE IF NOT EXISTS ops_backup_runs (
  id TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  status TEXT NOT NULL,
  backup_path TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ops_backup_runs_operation_valid'
  ) THEN
    ALTER TABLE ops_backup_runs
      ADD CONSTRAINT ops_backup_runs_operation_valid
      CHECK (operation IN ('backup', 'restore_drill'));
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ops_backup_runs_status_valid'
  ) THEN
    ALTER TABLE ops_backup_runs
      ADD CONSTRAINT ops_backup_runs_status_valid
      CHECK (status IN ('running', 'ok', 'error'));
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_ops_backup_runs_started
  ON ops_backup_runs(started_at DESC);
