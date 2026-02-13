#pragma once

#include <Arduino.h>
#include <WebSocketsClient.h>

#include "app_config.h"
#include "relay_manager.h"
#include "status_led.h"

class WsClientService {
public:
  void begin(const AppConfig &config, RelayManager *relayManager, StatusLed *statusLed);
  void loop();
  bool isConnected() const;
  void requestStateReport();

private:
  static void onWsEvent(WStype_t type, uint8_t *payload, size_t length);
  void handleWsEvent(WStype_t type, uint8_t *payload, size_t length);
  void connect();
  void scheduleReconnect();
  void sendStateReport();
  void sendAck(const String &commandId, bool ok, const String &error = String());
  void handleMessage(const char *payload, size_t length);
  String buildWsPath() const;
  String urlEncode(const String &input) const;

  static WsClientService *instance_;

  AppConfig config_;
  RelayManager *relayManager_ = nullptr;
  StatusLed *statusLed_ = nullptr;
  WebSocketsClient wsClient_;
  bool connected_ = false;
  bool shouldReportNow_ = false;
  uint32_t lastReportAtMs_ = 0;
  uint32_t initialReportAtMs_ = 0;
  uint32_t reconnectAtMs_ = 0;
  uint8_t reconnectStep_ = 0;
};
