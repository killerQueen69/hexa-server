#include "app_config.h"

#include <ArduinoJson.h>
#include <LittleFS.h>

namespace {
constexpr const char *kConfigPath = "/config.json";
}

bool loadAppConfig(AppConfig &config) {
  if (!LittleFS.exists(kConfigPath)) {
    return false;
  }

  File file = LittleFS.open(kConfigPath, "r");
  if (!file) {
    return false;
  }

  JsonDocument doc;
  const DeserializationError err = deserializeJson(doc, file);
  file.close();
  if (err) {
    return false;
  }

  config.wifiSsid = doc["wifi_ssid"] | config.wifiSsid;
  config.wifiPass = doc["wifi_pass"] | config.wifiPass;
  config.serverHost = doc["server_host"] | config.serverHost;
  config.serverPort = doc["server_port"] | config.serverPort;
  config.deviceUid = doc["device_uid"] | config.deviceUid;
  config.deviceToken = doc["device_token"] | config.deviceToken;
  config.relayActiveLow = doc["relay_active_low"] | config.relayActiveLow;
  config.reportIntervalSec = doc["report_interval"] | config.reportIntervalSec;
  config.useTls = doc["use_tls"] | config.useTls;

  const JsonArray relayPins = doc["relay_pins"].as<JsonArray>();
  if (!relayPins.isNull() && relayPins.size() == config.relayPins.size()) {
    for (size_t i = 0; i < config.relayPins.size(); i += 1) {
      config.relayPins[i] = relayPins[i] | config.relayPins[i];
    }
  }

  const JsonArray inputPins = doc["input_pins"].as<JsonArray>();
  if (!inputPins.isNull() && inputPins.size() == config.inputPins.size()) {
    for (size_t i = 0; i < config.inputPins.size(); i += 1) {
      config.inputPins[i] = inputPins[i] | config.inputPins[i];
    }
  }

  return true;
}

bool saveAppConfig(const AppConfig &config) {
  JsonDocument doc;
  doc["wifi_ssid"] = config.wifiSsid;
  doc["wifi_pass"] = config.wifiPass;
  doc["server_host"] = config.serverHost;
  doc["server_port"] = config.serverPort;
  doc["device_uid"] = config.deviceUid;
  doc["device_token"] = config.deviceToken;
  doc["relay_active_low"] = config.relayActiveLow;
  doc["report_interval"] = config.reportIntervalSec;
  doc["use_tls"] = config.useTls;

  JsonArray relayPins = doc["relay_pins"].to<JsonArray>();
  for (const uint8_t pin : config.relayPins) {
    relayPins.add(pin);
  }

  JsonArray inputPins = doc["input_pins"].to<JsonArray>();
  for (const uint8_t pin : config.inputPins) {
    inputPins.add(pin);
  }

  File file = LittleFS.open(kConfigPath, "w");
  if (!file) {
    return false;
  }

  const size_t written = serializeJson(doc, file);
  file.close();
  return written > 0;
}

String provisioningApName(const AppConfig &config) {
  const int keep = 4;
  const int len = config.deviceUid.length();
  const String suffix = len > keep ? config.deviceUid.substring(len - keep) : config.deviceUid;
  return "HexaMini-Setup-" + suffix;
}
