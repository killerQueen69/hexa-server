#include "status_led.h"

namespace {
constexpr uint8_t kPriorityOrder[] = {
    static_cast<uint8_t>(LedState::FATAL_ERROR),
    static_cast<uint8_t>(LedState::OTA_VERIFY),
    static_cast<uint8_t>(LedState::OTA_DOWNLOAD),
    static_cast<uint8_t>(LedState::PROVISIONING),
    static_cast<uint8_t>(LedState::WIFI_CONNECTING),
    static_cast<uint8_t>(LedState::CLOUD_CONNECTED),
    static_cast<uint8_t>(LedState::BOOT_SELF_TEST)};
}

void StatusLed::begin(uint8_t pin, bool activeLow) {
  pin_ = pin;
  activeLow_ = activeLow;
  pinMode(pin_, OUTPUT);
  applyOutput(false);
  clearAll();
}

void StatusLed::setActive(LedState state, bool enabled) {
  active_[static_cast<uint8_t>(state)] = enabled;
}

void StatusLed::clearAll() {
  for (bool &flag : active_) {
    flag = false;
  }
}

void StatusLed::tick(uint32_t nowMs) {
  const LedState targetState = selectHighestPriorityState();
  if (targetState != currentState_) {
    currentState_ = targetState;
    phaseIndex_ = 0;
    lastPhaseChangeMs_ = nowMs;
    const bool on = phaseOn(currentState_, phaseIndex_);
    ledOn_ = on;
    applyOutput(on);
    return;
  }

  const uint32_t waitMs = phaseDurationMs(currentState_, phaseIndex_);
  if ((nowMs - lastPhaseChangeMs_) < waitMs) {
    return;
  }

  lastPhaseChangeMs_ = nowMs;
  phaseIndex_ = (phaseIndex_ + 1) % phaseCount(currentState_);
  const bool on = phaseOn(currentState_, phaseIndex_);
  ledOn_ = on;
  applyOutput(on);
}

LedState StatusLed::selectHighestPriorityState() const {
  for (const uint8_t rawState : kPriorityOrder) {
    if (active_[rawState]) {
      return static_cast<LedState>(rawState);
    }
  }

  return LedState::BOOT_SELF_TEST;
}

uint32_t StatusLed::phaseDurationMs(LedState state, uint8_t phaseIndex) const {
  switch (state) {
  case LedState::FATAL_ERROR:
    return phaseIndex == 0 ? 3000 : 1000;
  case LedState::OTA_VERIFY:
    return 100;
  case LedState::OTA_DOWNLOAD:
    return phaseIndex == 0 ? 80 : 420;
  case LedState::PROVISIONING:
    return 1000;
  case LedState::WIFI_CONNECTING:
    return phaseIndex == 0 ? 100 : (phaseIndex == 1 ? 100 : (phaseIndex == 2 ? 100 : 1700));
  case LedState::CLOUD_CONNECTED:
    return phaseIndex == 0 ? 50 : 4950;
  case LedState::BOOT_SELF_TEST:
    return 200;
  default:
    return 200;
  }
}

bool StatusLed::phaseOn(LedState state, uint8_t phaseIndex) const {
  switch (state) {
  case LedState::FATAL_ERROR:
  case LedState::OTA_DOWNLOAD:
  case LedState::PROVISIONING:
  case LedState::CLOUD_CONNECTED:
  case LedState::BOOT_SELF_TEST:
    return phaseIndex == 0;
  case LedState::OTA_VERIFY:
    return phaseIndex == 0;
  case LedState::WIFI_CONNECTING:
    return phaseIndex == 0 || phaseIndex == 2;
  default:
    return false;
  }
}

uint8_t StatusLed::phaseCount(LedState state) const {
  if (state == LedState::WIFI_CONNECTING) {
    return 4;
  }
  return 2;
}

void StatusLed::applyOutput(bool on) {
  const bool driveHigh = activeLow_ ? !on : on;
  digitalWrite(pin_, driveHigh ? HIGH : LOW);
}
