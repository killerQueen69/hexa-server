#include "device_provision_service.h"

#include <ArduinoJson.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>
#include <memory>

#include "config.h"

namespace {
String buildProvisionUrl(const AppConfig &config) {
  String url = config.useTls ? "https://" : "http://";
  url += config.serverHost;
  url += ":";
  url += config.serverPort;
  url += FW_PROVISION_ENDPOINT;
  return url;
}

String chipIdHex() {
  char out[9];
  snprintf(out, sizeof(out), "%08X", ESP.getChipId());
  return String(out);
}
} // namespace

DeviceProvisionResult DeviceProvisionService::provision(const AppConfig &config) const {
  DeviceProvisionResult result;

  HTTPClient http;
  const String url = buildProvisionUrl(config);
  std::unique_ptr<WiFiClient> plainClient;
  std::unique_ptr<BearSSL::WiFiClientSecure> secureClient;

  if (config.useTls) {
    secureClient = std::make_unique<BearSSL::WiFiClientSecure>();
    secureClient->setInsecure();
    if (!http.begin(*secureClient, url)) {
      result.error = "http_begin_failed";
      return result;
    }
  } else {
    plainClient = std::make_unique<WiFiClient>();
    if (!http.begin(*plainClient, url)) {
      result.error = "http_begin_failed";
      return result;
    }
  }

  http.addHeader("Content-Type", "application/json");

  JsonDocument payload;
  payload["provision_key"] = FW_PROVISION_KEY;
  payload["chip_id"] = chipIdHex();
  payload["mac"] = WiFi.macAddress();
  payload["model"] = FW_DEVICE_MODEL;
  payload["firmware_version"] = FIRMWARE_VERSION;
  payload["relay_count"] = 3;
  payload["button_count"] = 3;

  String body;
  serializeJson(payload, body);

  const int status = http.POST(body);
  const String response = http.getString();
  http.end();

  if (status < 200 || status >= 300) {
    result.error = "http_" + String(status);
    return result;
  }

  JsonDocument doc;
  const DeserializationError err = deserializeJson(doc, response);
  if (err) {
    result.error = "json_parse_failed";
    return result;
  }

  const String uid = doc["device_uid"] | "";
  const String token = doc["device_token"] | "";
  if (uid.isEmpty() || token.isEmpty()) {
    result.error = "missing_credentials";
    return result;
  }

  result.ok = true;
  result.deviceUid = uid;
  result.deviceToken = token;
  result.claimCode = doc["claim_code"] | "";
  return result;
}
