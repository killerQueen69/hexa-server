ALTER TABLE device_ir_codes
  ADD COLUMN IF NOT EXISTS payload_format TEXT NOT NULL DEFAULT 'raw',
  ADD COLUMN IF NOT EXISTS payload_fingerprint TEXT,
  ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'device',
  ADD COLUMN IF NOT EXISTS source_ref TEXT,
  ADD COLUMN IF NOT EXISTS protocol_norm TEXT,
  ADD COLUMN IF NOT EXISTS frequency_norm_hz INTEGER,
  ADD COLUMN IF NOT EXISTS normalized_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS learned_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE device_ir_codes
SET protocol_norm = UPPER(TRIM(protocol))
WHERE protocol_norm IS NULL;

UPDATE device_ir_codes
SET frequency_norm_hz = frequency_hz
WHERE frequency_norm_hz IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_ir_codes_payload_format_valid'
  ) THEN
    ALTER TABLE device_ir_codes
      ADD CONSTRAINT device_ir_codes_payload_format_valid
      CHECK (payload_format IN ('raw', 'hex', 'base64', 'json'));
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_ir_codes_source_type_valid'
  ) THEN
    ALTER TABLE device_ir_codes
      ADD CONSTRAINT device_ir_codes_source_type_valid
      CHECK (source_type IN ('device', 'migration', 'library', 'user'));
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_ir_codes_protocol_norm_nonempty'
  ) THEN
    ALTER TABLE device_ir_codes
      ADD CONSTRAINT device_ir_codes_protocol_norm_nonempty
      CHECK (protocol_norm IS NULL OR LENGTH(TRIM(protocol_norm)) > 0);
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_ir_codes_normalized_payload_object'
  ) THEN
    ALTER TABLE device_ir_codes
      ADD CONSTRAINT device_ir_codes_normalized_payload_object
      CHECK (jsonb_typeof(normalized_payload) = 'object');
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_device_ir_codes_fingerprint
  ON device_ir_codes(device_id, payload_fingerprint);

CREATE INDEX IF NOT EXISTS idx_device_ir_codes_protocol_norm
  ON device_ir_codes(protocol_norm, frequency_norm_hz);

CREATE INDEX IF NOT EXISTS idx_device_ir_codes_source_type
  ON device_ir_codes(source_type);

CREATE TABLE IF NOT EXISTS ir_library_sources (
  id TEXT PRIMARY KEY,
  source_key TEXT NOT NULL UNIQUE,
  source_url TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  source_version TEXT NOT NULL,
  license TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ir_library_sources_metadata_object'
  ) THEN
    ALTER TABLE ir_library_sources
      ADD CONSTRAINT ir_library_sources_metadata_object
      CHECK (jsonb_typeof(metadata) = 'object');
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS ir_library_records (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES ir_library_sources(id) ON DELETE CASCADE,
  source_record_id TEXT NOT NULL,
  brand TEXT,
  model TEXT,
  protocol TEXT NOT NULL,
  protocol_norm TEXT NOT NULL,
  frequency_hz INTEGER,
  frequency_norm_hz INTEGER,
  payload TEXT NOT NULL,
  payload_format TEXT NOT NULL DEFAULT 'raw',
  payload_fingerprint TEXT NOT NULL,
  normalized_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source_id, source_record_id)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ir_library_records_payload_format_valid'
  ) THEN
    ALTER TABLE ir_library_records
      ADD CONSTRAINT ir_library_records_payload_format_valid
      CHECK (payload_format IN ('raw', 'hex', 'base64', 'json'));
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ir_library_records_metadata_object'
  ) THEN
    ALTER TABLE ir_library_records
      ADD CONSTRAINT ir_library_records_metadata_object
      CHECK (jsonb_typeof(metadata) = 'object');
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ir_library_records_normalized_payload_object'
  ) THEN
    ALTER TABLE ir_library_records
      ADD CONSTRAINT ir_library_records_normalized_payload_object
      CHECK (jsonb_typeof(normalized_payload) = 'object');
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_ir_library_records_fingerprint
  ON ir_library_records(payload_fingerprint);

CREATE INDEX IF NOT EXISTS idx_ir_library_records_protocol
  ON ir_library_records(protocol_norm, frequency_norm_hz);

CREATE INDEX IF NOT EXISTS idx_ir_library_records_brand_model
  ON ir_library_records(brand, model);

CREATE TABLE IF NOT EXISTS ir_match_feedback (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  library_record_id TEXT REFERENCES ir_library_records(id) ON DELETE SET NULL,
  candidate_fingerprint TEXT NOT NULL,
  accepted BOOLEAN NOT NULL,
  confidence NUMERIC(5,4),
  context JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ir_match_feedback_confidence_range'
  ) THEN
    ALTER TABLE ir_match_feedback
      ADD CONSTRAINT ir_match_feedback_confidence_range
      CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1));
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ir_match_feedback_context_object'
  ) THEN
    ALTER TABLE ir_match_feedback
      ADD CONSTRAINT ir_match_feedback_context_object
      CHECK (jsonb_typeof(context) = 'object');
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_ir_match_feedback_device
  ON ir_match_feedback(device_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ir_match_feedback_library_record
  ON ir_match_feedback(library_record_id);
