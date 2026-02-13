#include "ws_client_service.h"

#include <ArduinoJson.h>
#include <ESP8266WiFi.h>

WsClientService *WsClientService::instance_ = nullptr;

namespace {
constexpr uint32_t kBackoffMs[] = {5000, 10000, 20000, 30000};
constexpr uint32_t kInitialReportDelayMs = 1500;
}

void WsClientService::begin(const AppConfig &config, RelayManager *relayManager, StatusLed *statusLed) {
  config_ = config;
  relayManager_ = relayManager;
  statusLed_ = statusLed;
  connected_ = false;
  reconnectStep_ = 0;
  reconnectAtMs_ = 0;
  shouldReportNow_ = true;
  lastReportAtMs_ = 0;
  initialReportAtMs_ = 0;
  instance_ = this;

  wsClient_.onEvent(onWsEvent);
  wsClient_.setReconnectInterval(0);
  wsClient_.enableHeartbeat(15000, 3000, 2);
}

void WsClientService::loop() {
  wsClient_.loop();

  const uint32_t now = millis();
  if (!connected_) {
    if (reconnectAtMs_ == 0 || now >= reconnectAtMs_) {
      connect();
    }
    return;
  }

  if (!relayManager_) {
    return;
  }

  if (initialReportAtMs_ > 0 && now >= initialReportAtMs_) {
    sendStateReport();
    lastReportAtMs_ = now;
    initialReportAtMs_ = 0;
    shouldReportNow_ = false;
    return;
  }

  const uint32_t reportEveryMs = static_cast<uint32_t>(config_.reportIntervalSec) * 1000U;
  if (shouldReportNow_ || (now - lastReportAtMs_) >= reportEveryMs) {
    sendStateReport();
    shouldReportNow_ = false;
    lastReportAtMs_ = now;
  }
}

bool WsClientService::isConnected() const {
  return connected_;
}

void WsClientService::requestStateReport() {
  shouldReportNow_ = true;
}

void WsClientService::onWsEvent(WStype_t type, uint8_t *payload, size_t length) {
  if (!instance_) {
    return;
  }
  instance_->handleWsEvent(type, payload, length);
}

void WsClientService::handleWsEvent(WStype_t type, uint8_t *payload, size_t length) {
  switch (type) {
  case WStype_CONNECTED:
    Serial.println("[ws] connected");
    connected_ = true;
    reconnectStep_ = 0;
    reconnectAtMs_ = 0;
    shouldReportNow_ = false;
    initialReportAtMs_ = millis() + kInitialReportDelayMs;
    if (statusLed_) {
      statusLed_->setActive(LedState::WIFI_CONNECTING, false);
      statusLed_->setActive(LedState::CLOUD_CONNECTED, true);
    }
    break;

  case WStype_DISCONNECTED:
    Serial.println("[ws] disconnected");
    connected_ = false;
    initialReportAtMs_ = 0;
    if (statusLed_) {
      statusLed_->setActive(LedState::CLOUD_CONNECTED, false);
      statusLed_->setActive(LedState::WIFI_CONNECTING, true);
    }
    scheduleReconnect();
    break;

  case WStype_TEXT:
    if (payload && length > 0) {
      handleMessage(reinterpret_cast<const char *>(payload), length);
    }
    break;

  default:
    break;
  }
}

void WsClientService::connect() {
  const String path = buildWsPath();
  Serial.printf("[ws] connecting host=%s port=%u tls=%d path=%s\n", config_.serverHost.c_str(),
                config_.serverPort, config_.useTls ? 1 : 0, path.c_str());
  if (config_.useTls) {
    wsClient_.beginSSL(config_.serverHost.c_str(), config_.serverPort, path.c_str());
  } else {
    wsClient_.begin(config_.serverHost.c_str(), config_.serverPort, path.c_str());
  }

  if (statusLed_) {
    statusLed_->setActive(LedState::WIFI_CONNECTING, true);
  }

  scheduleReconnect();
}

void WsClientService::scheduleReconnect() {
  const uint32_t now = millis();
  reconnectAtMs_ = now + kBackoffMs[reconnectStep_];
  if (reconnectStep_ < (sizeof(kBackoffMs) / sizeof(kBackoffMs[0])) - 1) {
    reconnectStep_ += 1;
  }
}

void WsClientService::sendStateReport() {
  if (!connected_ || !relayManager_) {
    return;
  }

  JsonDocument doc;
  doc["type"] = "state_report";
  doc["device_uid"] = config_.deviceUid;

  JsonArray relayStates = doc["relays"].to<JsonArray>();
  for (size_t i = 0; i < relayManager_->relayCount(); i += 1) {
    relayStates.add(relayManager_->getRelayState(i));
  }

  JsonObject telemetry = doc["telemetry"].to<JsonObject>();
  telemetry["heap"] = ESP.getFreeHeap();
  telemetry["rssi"] = WiFi.RSSI();
  telemetry["uptime_ms"] = millis();
  telemetry["firmware"] = FIRMWARE_VERSION;

  doc["ts_ms"] = millis();

  String body;
  serializeJson(doc, body);
  wsClient_.sendTXT(body);
}

void WsClientService::sendAck(const String &commandId, bool ok, const String &error) {
  if (!connected_) {
    return;
  }

  JsonDocument doc;
  doc["type"] = "ack";
  doc["device_uid"] = config_.deviceUid;
  doc["command_id"] = commandId;
  doc["ok"] = ok;
  if (!ok && !error.isEmpty()) {
    doc["error"] = error;
  }
  doc["ts_ms"] = millis();

  String body;
  serializeJson(doc, body);
  wsClient_.sendTXT(body);
}

void WsClientService::handleMessage(const char *payload, size_t length) {
  JsonDocument doc;
  const DeserializationError err = deserializeJson(doc, payload, length);
  if (err) {
    return;
  }

  const String type = doc["type"] | "";
  if (type == "set_relay") {
    const String commandId = doc["command_id"] | "";
    const int relayIndex = doc["relay_index"] | -1;
    const String action = doc["action"] | "";

    if (!relayManager_ || commandId.isEmpty()) {
      sendAck(commandId, false, "invalid_command");
      return;
    }

    bool ok = false;
    if (relayIndex >= 0 && relayIndex < static_cast<int>(relayManager_->relayCount())) {
      if (action == "on") {
        ok = relayManager_->setRelay(relayIndex, true);
      } else if (action == "off") {
        ok = relayManager_->setRelay(relayIndex, false);
      } else if (action == "toggle") {
        ok = relayManager_->toggleRelay(relayIndex);
      }
    }

    sendAck(commandId, ok, ok ? "" : "unsupported_action");
    if (ok) {
      requestStateReport();
    }
    return;
  }

  if (type == "set_all_relays") {
    const String commandId = doc["command_id"] | "";
    const String action = doc["action"] | "";

    if (!relayManager_ || commandId.isEmpty()) {
      sendAck(commandId, false, "invalid_command");
      return;
    }

    if (action == "on") {
      relayManager_->setAll(true);
      sendAck(commandId, true);
      requestStateReport();
      return;
    }

    if (action == "off") {
      relayManager_->setAll(false);
      sendAck(commandId, true);
      requestStateReport();
      return;
    }

    sendAck(commandId, false, "unsupported_action");
  }
}

String WsClientService::buildWsPath() const {
  String path = "/ws/device?uid=";
  path += urlEncode(config_.deviceUid);
  path += "&token=";
  path += urlEncode(config_.deviceToken);
  return path;
}

String WsClientService::urlEncode(const String &input) const {
  String out;
  out.reserve(input.length() * 3);

  for (size_t i = 0; i < input.length(); i += 1) {
    const char c = input.charAt(i);
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
      continue;
    }

    char encoded[4];
    snprintf(encoded, sizeof(encoded), "%%%02X", static_cast<unsigned char>(c));
    out += encoded;
  }

  return out;
}
