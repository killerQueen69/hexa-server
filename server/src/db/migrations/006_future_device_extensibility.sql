ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS device_class TEXT NOT NULL DEFAULT 'relay_controller',
  ADD COLUMN IF NOT EXISTS capabilities JSONB NOT NULL DEFAULT '[]'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'devices_device_class_valid'
  ) THEN
    ALTER TABLE devices
      ADD CONSTRAINT devices_device_class_valid
      CHECK (device_class IN ('relay_controller', 'ir_hub', 'sensor_hub', 'hybrid'));
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'devices_capabilities_array'
  ) THEN
    ALTER TABLE devices
      ADD CONSTRAINT devices_capabilities_array
      CHECK (jsonb_typeof(capabilities) = 'array');
  END IF;
END;
$$;

UPDATE devices
SET capabilities = '[{"key":"relay","kind":"actuator"}]'::jsonb
WHERE relay_count > 0
  AND jsonb_typeof(capabilities) = 'array'
  AND jsonb_array_length(capabilities) = 0;

CREATE TABLE IF NOT EXISTS device_capabilities (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  capability_key TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (device_id, capability_key)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_capabilities_config_object'
  ) THEN
    ALTER TABLE device_capabilities
      ADD CONSTRAINT device_capabilities_config_object
      CHECK (jsonb_typeof(config) = 'object');
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_capabilities_metadata_object'
  ) THEN
    ALTER TABLE device_capabilities
      ADD CONSTRAINT device_capabilities_metadata_object
      CHECK (jsonb_typeof(metadata) = 'object');
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_device_capabilities_device
  ON device_capabilities(device_id);

CREATE TABLE IF NOT EXISTS device_ir_codes (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  code_name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  frequency_hz INTEGER,
  payload TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (device_id, code_name)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_ir_codes_frequency_valid'
  ) THEN
    ALTER TABLE device_ir_codes
      ADD CONSTRAINT device_ir_codes_frequency_valid
      CHECK (frequency_hz IS NULL OR frequency_hz > 0);
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_ir_codes_metadata_object'
  ) THEN
    ALTER TABLE device_ir_codes
      ADD CONSTRAINT device_ir_codes_metadata_object
      CHECK (jsonb_typeof(metadata) = 'object');
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_device_ir_codes_device
  ON device_ir_codes(device_id);

CREATE INDEX IF NOT EXISTS idx_device_ir_codes_owner
  ON device_ir_codes(owner_user_id);

CREATE TABLE IF NOT EXISTS device_sensor_state (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  sensor_key TEXT NOT NULL,
  sensor_type TEXT NOT NULL,
  state JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ NOT NULL,
  source TEXT NOT NULL DEFAULT 'device',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (device_id, sensor_key)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'device_sensor_state_state_object'
  ) THEN
    ALTER TABLE device_sensor_state
      ADD CONSTRAINT device_sensor_state_state_object
      CHECK (jsonb_typeof(state) = 'object');
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_device_sensor_state_device
  ON device_sensor_state(device_id);

CREATE TABLE IF NOT EXISTS device_sensor_events (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  sensor_key TEXT NOT NULL,
  sensor_type TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ NOT NULL,
  source TEXT NOT NULL DEFAULT 'device',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_sensor_events_device_observed
  ON device_sensor_events(device_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_device_sensor_events_sensor_observed
  ON device_sensor_events(sensor_key, observed_at DESC);

CREATE TABLE IF NOT EXISTS user_preferences (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  dashboard_layout JSONB NOT NULL DEFAULT '{}'::jsonb,
  dashboard_settings JSONB NOT NULL DEFAULT '{}'::jsonb,
  device_view_state JSONB NOT NULL DEFAULT '{}'::jsonb,
  notification_settings JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'user_preferences_dashboard_layout_object'
  ) THEN
    ALTER TABLE user_preferences
      ADD CONSTRAINT user_preferences_dashboard_layout_object
      CHECK (jsonb_typeof(dashboard_layout) = 'object');
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'user_preferences_dashboard_settings_object'
  ) THEN
    ALTER TABLE user_preferences
      ADD CONSTRAINT user_preferences_dashboard_settings_object
      CHECK (jsonb_typeof(dashboard_settings) = 'object');
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'user_preferences_device_view_state_object'
  ) THEN
    ALTER TABLE user_preferences
      ADD CONSTRAINT user_preferences_device_view_state_object
      CHECK (jsonb_typeof(device_view_state) = 'object');
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'user_preferences_notification_settings_object'
  ) THEN
    ALTER TABLE user_preferences
      ADD CONSTRAINT user_preferences_notification_settings_object
      CHECK (jsonb_typeof(notification_settings) = 'object');
  END IF;
END;
$$;
