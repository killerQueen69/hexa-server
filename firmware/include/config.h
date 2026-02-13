#pragma once

// Core build metadata
#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "hexa-mini-switch-v1-dev"
#endif

// Server defaults
#ifndef FW_DEFAULT_SERVER_HOST
#define FW_DEFAULT_SERVER_HOST "192.168.0.152"
#endif

#ifndef FW_DEFAULT_SERVER_PORT
#define FW_DEFAULT_SERVER_PORT 3000
#endif

#ifndef FW_DEFAULT_USE_TLS
#define FW_DEFAULT_USE_TLS 0
#endif

// Bootstrap credentials (kept empty for self-provisioned devices)
#ifndef FW_BOOTSTRAP_DEVICE_UID
#define FW_BOOTSTRAP_DEVICE_UID ""
#endif

#ifndef FW_BOOTSTRAP_DEVICE_TOKEN
#define FW_BOOTSTRAP_DEVICE_TOKEN ""
#endif

// Device identity and provisioning
#ifndef FW_DEVICE_MODEL
#define FW_DEVICE_MODEL "hexa-mini-switch-v1"
#endif

#ifndef FW_PROVISION_KEY
#error "FW_PROVISION_KEY must be provided via build flags (platformio.secrets.ini)."
#endif

#ifndef FW_PROVISION_ENDPOINT
#define FW_PROVISION_ENDPOINT "/api/v1/provision/register"
#endif
