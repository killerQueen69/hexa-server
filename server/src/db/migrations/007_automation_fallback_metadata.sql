ALTER TABLE automation_rules
  ADD COLUMN IF NOT EXISTS definition_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE schedules
  ADD COLUMN IF NOT EXISTS definition_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE automation_rules
SET definition_updated_at = COALESCE(definition_updated_at, updated_at, created_at, now())
WHERE definition_updated_at IS NULL;

UPDATE schedules
SET definition_updated_at = COALESCE(definition_updated_at, updated_at, created_at, now())
WHERE definition_updated_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_automation_definition_updated
  ON automation_rules(device_id, definition_updated_at DESC)
  WHERE is_enabled = TRUE;

CREATE INDEX IF NOT EXISTS idx_schedules_definition_updated
  ON schedules(device_id, definition_updated_at DESC)
  WHERE is_enabled = TRUE;
