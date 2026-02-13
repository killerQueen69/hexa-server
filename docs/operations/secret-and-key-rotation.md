# Secrets and Key Rotation Plan

## Secret Sources

Server resolves secrets from:
- `env:<VAR_NAME>`
- `file:<path>#<key>` JSON secret files
- secret map from `OTA_SIGNING_PRIVATE_KEYS_JSON`
- optional shared secret file via `SECRET_MANAGER_FILE`

## OTA Signing Keys

- Signing key registry table: `ota_signing_keys`
- Supported states: `active`, `next`, `retired`
- Release manifests store:
  - `verification_key_id` (active key used for signature)
  - `next_verification_key_id` (next key announced for firmware rotation)

## Rotation Procedure

1. Create/import next key (`status=next`) with secret reference.
2. Confirm key visibility in `/api/v1/ota/signing-keys`.
3. Publish at least one signed release showing active+next key IDs.
4. Rotate with `POST /api/v1/ota/signing-keys/rotate`.
5. Validate new releases are signed by new active key.
6. Retire old key after firmware fleet adoption window.

## JWT and Integration Secret Rotation

- Rotate JWT and integration secrets on scheduled cadence.
- Perform staged deploy:
  - update secret source
  - deploy staging
  - run smoke/integration
  - approve production sign-off

## Safety Rules

- Private signing keys never stored in firmware.
- Private keys are not persisted in database.
- OTA serving fails closed when signature or key integrity checks fail.
