#pragma once

#include <Arduino.h>
#include <array>

enum class LedState : uint8_t {
  BOOT_SELF_TEST = 0,
  WIFI_CONNECTING = 1,
  CLOUD_CONNECTED = 2,
  PROVISIONING = 3,
  OTA_DOWNLOAD = 4,
  OTA_VERIFY = 5,
  FATAL_ERROR = 6
};

class StatusLed {
public:
  void begin(uint8_t pin, bool activeLow);
  void setActive(LedState state, bool enabled);
  void clearAll();
  void tick(uint32_t nowMs);

private:
  LedState currentState_ = LedState::BOOT_SELF_TEST;
  uint8_t pin_ = 2;
  bool activeLow_ = true;
  bool ledOn_ = false;
  uint32_t lastPhaseChangeMs_ = 0;
  uint8_t phaseIndex_ = 0;
  std::array<bool, 7> active_ = {false, false, false, false, false, false, false};

  LedState selectHighestPriorityState() const;
  uint32_t phaseDurationMs(LedState state, uint8_t phaseIndex) const;
  bool phaseOn(LedState state, uint8_t phaseIndex) const;
  uint8_t phaseCount(LedState state) const;
  void applyOutput(bool on);
};
