#pragma once

#include <Arduino.h>
#include <array>

#include "config.h"

struct AppConfig {
  String wifiSsid;
  String wifiPass;
  String serverHost = FW_DEFAULT_SERVER_HOST;
  uint16_t serverPort = FW_DEFAULT_SERVER_PORT;
  String deviceUid = FW_BOOTSTRAP_DEVICE_UID;
  String deviceToken = FW_BOOTSTRAP_DEVICE_TOKEN;
  std::array<uint8_t, 3> relayPins = {12, 13, 14};
  std::array<uint8_t, 3> inputPins = {4, 5, 3};
  bool relayActiveLow = false;
  uint16_t reportIntervalSec = 30;
  bool useTls = FW_DEFAULT_USE_TLS != 0;
};

bool loadAppConfig(AppConfig &config);
bool saveAppConfig(const AppConfig &config);
String provisioningApName(const AppConfig &config);
