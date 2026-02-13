#pragma once

#include <Arduino.h>

enum class ServiceButtonEvent : uint8_t {
  NONE = 0,
  ENTER_PROVISIONING = 1,
  FACTORY_RESET = 2
};

class ServiceButton {
public:
  void begin(uint8_t pin);
  ServiceButtonEvent poll(uint32_t nowMs);

private:
  uint8_t pin_ = 0;
  bool rawLevelHigh_ = true;
  bool stableLevelHigh_ = true;
  uint32_t rawChangedAtMs_ = 0;
  uint32_t pressedSinceMs_ = 0;
  uint32_t releaseGapSinceMs_ = 0;
  bool pressActive_ = false;
  bool provisioningSent_ = false;
  bool factoryResetSent_ = false;

  static constexpr uint32_t kDebounceMs = 30;
  static constexpr uint32_t kProvisioningHoldMinMs = 800;
  static constexpr uint32_t kProvisioningHoldMaxMs = 4000;
  static constexpr uint32_t kFactoryResetHoldMs = 10000;
  static constexpr uint32_t kReleaseGapResetMs = 100;
  static constexpr uint32_t kBootGuardMs = 3000;
};
