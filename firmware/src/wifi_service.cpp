#include "wifi_service.h"

#include <ESP8266WiFi.h>
#include <WiFiManager.h>

namespace {
constexpr uint32_t kWifiConnectTimeoutMs = 20000;
}

bool WifiService::connect(AppConfig &config, StatusLed &statusLed, bool forceProvisioning) {
  if (!forceProvisioning && connectWithConfig(config, statusLed)) {
    return true;
  }

  return runProvisioningPortal(config, statusLed);
}

void WifiService::resetWifiCredentials() {
  WiFiManager wm;
  wm.resetSettings();
  WiFi.disconnect(true);
}

bool WifiService::connectWithConfig(const AppConfig &config, StatusLed &statusLed) {
  if (config.wifiSsid.isEmpty()) {
    return false;
  }

  statusLed.setActive(LedState::WIFI_CONNECTING, true);
  WiFi.persistent(true);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.disconnect(false);
  delay(50);

  if (config.wifiPass.isEmpty()) {
    Serial.printf("[wifi] connect via stored creds ssid_hint=%s\n", config.wifiSsid.c_str());
    WiFi.begin();
  } else {
    Serial.printf("[wifi] connect via config ssid=%s\n", config.wifiSsid.c_str());
    WiFi.begin(config.wifiSsid.c_str(), config.wifiPass.c_str());
  }

  const uint32_t startedAt = millis();
  while ((millis() - startedAt) < kWifiConnectTimeoutMs) {
    if (WiFi.status() == WL_CONNECTED) {
      statusLed.setActive(LedState::WIFI_CONNECTING, false);
      Serial.printf("[wifi] connected ip=%s\n", WiFi.localIP().toString().c_str());
      return true;
    }

    delay(200);
    yield();
  }

  statusLed.setActive(LedState::WIFI_CONNECTING, false);
  Serial.printf("[wifi] connect failed status=%d\n", static_cast<int>(WiFi.status()));
  return false;
}

bool WifiService::runProvisioningPortal(AppConfig &config, StatusLed &statusLed) {
  statusLed.setActive(LedState::WIFI_CONNECTING, false);
  statusLed.setActive(LedState::PROVISIONING, true);

  WiFi.persistent(true);
  WiFiManager wm;
  wm.setConfigPortalBlocking(true);
  wm.setConfigPortalTimeout(180);

  char serverHost[64];
  char serverPort[8];
  char deviceUid[48];
  char deviceToken[96];
  char useTls[2];

  config.serverHost.toCharArray(serverHost, sizeof(serverHost));
  snprintf(serverPort, sizeof(serverPort), "%u", config.serverPort);
  config.deviceUid.toCharArray(deviceUid, sizeof(deviceUid));
  config.deviceToken.toCharArray(deviceToken, sizeof(deviceToken));
  snprintf(useTls, sizeof(useTls), "%s", config.useTls ? "1" : "0");

  WiFiManagerParameter serverHostParam("server_host", "Server host", serverHost,
                                       sizeof(serverHost));
  WiFiManagerParameter serverPortParam("server_port", "Server port", serverPort,
                                       sizeof(serverPort));
  WiFiManagerParameter deviceUidParam("device_uid", "Device UID", deviceUid,
                                      sizeof(deviceUid));
  WiFiManagerParameter deviceTokenParam("device_token", "Device token", deviceToken,
                                        sizeof(deviceToken));
  WiFiManagerParameter useTlsParam("use_tls", "Use TLS (1/0)", useTls, sizeof(useTls));

  wm.addParameter(&serverHostParam);
  wm.addParameter(&serverPortParam);
  wm.addParameter(&deviceUidParam);
  wm.addParameter(&deviceTokenParam);
  wm.addParameter(&useTlsParam);

  const bool connected = wm.autoConnect(provisioningApName(config).c_str());
  statusLed.setActive(LedState::PROVISIONING, false);

  if (!connected) {
    return false;
  }

  config.serverHost = String(serverHostParam.getValue());
  config.serverPort = String(serverPortParam.getValue()).toInt();
  config.deviceUid = String(deviceUidParam.getValue());
  config.deviceToken = String(deviceTokenParam.getValue());
  config.useTls = String(useTlsParam.getValue()) == "1";
  config.wifiSsid = WiFi.SSID();
  config.wifiPass = "";

  saveAppConfig(config);
  return true;
}
