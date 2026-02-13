#include <Arduino.h>
#include <LittleFS.h>
#include <WiFiManager.h>

#include "app_config.h"
#include "config.h"
#include "device_provision_service.h"
#include "local_input_service.h"
#include "relay_manager.h"
#include "service_button.h"
#include "status_led.h"
#include "wifi_service.h"
#include "ws_client_service.h"

namespace {
constexpr uint8_t kServiceButtonPin = 0; // GPIO0
constexpr uint8_t kStatusLedPin = 2;     // GPIO2

constexpr std::array<uint8_t, 3> kLegacyRelayPins = {5, 4, 14};
constexpr std::array<uint8_t, 3> kLegacyInputPins = {12, 13, 15};
constexpr std::array<uint8_t, 3> kProductionRelayPins = {12, 13, 14};
constexpr std::array<uint8_t, 3> kProductionInputPins = {4, 5, 3}; // GPIO4, GPIO5, RX/GPIO3

AppConfig config;
RelayManager relayManager;
LocalInputService localInputs;
DeviceProvisionService deviceProvisionService;
StatusLed statusLed;
ServiceButton serviceButton;
WifiService wifiService;
WsClientService wsClient;
}

void migrateLegacyPinMapIfNeeded(AppConfig &cfg) {
  if (cfg.relayPins == kLegacyRelayPins && cfg.inputPins == kLegacyInputPins) {
    cfg.relayPins = kProductionRelayPins;
    cfg.inputPins = kProductionInputPins;
    saveAppConfig(cfg);
    Serial.println("[boot] migrated legacy pin map to production profile");
  }
}

bool needsCloudProvisioning(const AppConfig &cfg) {
  const String bootstrapUid = FW_BOOTSTRAP_DEVICE_UID;
  const String bootstrapToken = FW_BOOTSTRAP_DEVICE_TOKEN;

  if (cfg.deviceUid.isEmpty() || cfg.deviceToken.isEmpty()) {
    return true;
  }
  if (!bootstrapUid.isEmpty() && cfg.deviceUid == bootstrapUid) {
    return true;
  }
  if (!bootstrapToken.isEmpty() && cfg.deviceToken == bootstrapToken) {
    return true;
  }

  // Legacy placeholders from early dev builds.
  if (cfg.deviceUid == "hexa-mini-001" || cfg.deviceToken == "change-me") {
    return true;
  }

  return false;
}

bool provisionCloudIdentityIfNeeded(AppConfig &cfg) {
  if (!needsCloudProvisioning(cfg)) {
    return true;
  }

  Serial.println("[prov] starting device self-provision");
  const DeviceProvisionResult provisioned = deviceProvisionService.provision(cfg);
  if (!provisioned.ok) {
    Serial.printf("[prov] failed error=%s\n", provisioned.error.c_str());
    return false;
  }

  cfg.deviceUid = provisioned.deviceUid;
  cfg.deviceToken = provisioned.deviceToken;
  if (!saveAppConfig(cfg)) {
    Serial.println("[prov] failed to persist provisioned credentials");
    return false;
  }

  Serial.printf("[prov] registered uid=%s\n", cfg.deviceUid.c_str());
  if (!provisioned.claimCode.isEmpty()) {
    Serial.printf("[prov] claim_code=%s\n", provisioned.claimCode.c_str());
  } else {
    Serial.println("[prov] device already claimed");
  }

  return true;
}

void rebootIntoProvisioning() {
  statusLed.setActive(LedState::CLOUD_CONNECTED, false);
  statusLed.setActive(LedState::PROVISIONING, true);
  const bool connected = wifiService.connect(config, statusLed, true);
  if (connected) {
    wsClient.begin(config, &relayManager, &statusLed);
  } else {
    statusLed.setActive(LedState::PROVISIONING, false);
    statusLed.setActive(LedState::FATAL_ERROR, true);
  }
}

void factoryResetAndReboot() {
  statusLed.clearAll();
  statusLed.setActive(LedState::FATAL_ERROR, true);

  wifiService.resetWifiCredentials();
  LittleFS.remove("/config.json");
  delay(1000);
  ESP.restart();
}

void setup() {
#if defined(ESP8266)
  Serial.begin(74880, SERIAL_8N1, SERIAL_TX_ONLY);
#else
  Serial.begin(74880);
#endif
  Serial.setDebugOutput(true);
  delay(200);
  Serial.println();
  Serial.printf("[boot] fw=%s reset=%s heap=%u\n", FIRMWARE_VERSION, ESP.getResetReason().c_str(),
                ESP.getFreeHeap());

  statusLed.begin(kStatusLedPin, true);
  statusLed.setActive(LedState::BOOT_SELF_TEST, true);

  if (!LittleFS.begin()) {
    Serial.println("[boot] LittleFS mount failed");
    statusLed.clearAll();
    statusLed.setActive(LedState::FATAL_ERROR, true);
    return;
  }

  const bool loaded = loadAppConfig(config);
  migrateLegacyPinMapIfNeeded(config);
  Serial.printf("[boot] config_loaded=%d ssid_set=%d host=%s port=%u uid=%s tls=%d\n", loaded ? 1 : 0,
                config.wifiSsid.isEmpty() ? 0 : 1, config.serverHost.c_str(), config.serverPort,
                config.deviceUid.c_str(), config.useTls ? 1 : 0);
  Serial.printf("[boot] pin_map relays=%u,%u,%u inputs=%u,%u,%u\n", config.relayPins[0],
                config.relayPins[1], config.relayPins[2], config.inputPins[0], config.inputPins[1],
                config.inputPins[2]);
  if (!loaded) {
    saveAppConfig(config);
    Serial.println("[boot] default config saved");
  }

  relayManager.begin(config.relayPins, config.relayActiveLow);
  localInputs.begin(config.inputPins);
  serviceButton.begin(kServiceButtonPin);
  Serial.println("[boot] io initialized");

  const bool connected = wifiService.connect(config, statusLed, false);
  Serial.printf("[boot] wifi_connected=%d ip=%s\n", connected ? 1 : 0,
                WiFi.localIP().toString().c_str());
  if (!connected) {
    statusLed.clearAll();
    statusLed.setActive(LedState::FATAL_ERROR, true);
    Serial.println("[boot] wifi failed, entering fatal state");
    return;
  }

  if (!provisionCloudIdentityIfNeeded(config)) {
    statusLed.clearAll();
    statusLed.setActive(LedState::FATAL_ERROR, true);
    Serial.println("[boot] device provisioning failed");
    return;
  }

  statusLed.setActive(LedState::BOOT_SELF_TEST, false);
  wsClient.begin(config, &relayManager, &statusLed);
  Serial.println("[boot] ws client started");
}

void loop() {
  const uint32_t now = millis();

  const ServiceButtonEvent event = serviceButton.poll(now);
  if (event == ServiceButtonEvent::ENTER_PROVISIONING) {
    rebootIntoProvisioning();
  } else if (event == ServiceButtonEvent::FACTORY_RESET) {
    factoryResetAndReboot();
  }

  if (localInputs.poll(now, relayManager)) {
    wsClient.requestStateReport();
  }

  wsClient.loop();
  statusLed.tick(now);
  yield();
}
