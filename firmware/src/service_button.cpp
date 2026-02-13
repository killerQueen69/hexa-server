#include "service_button.h"

void ServiceButton::begin(uint8_t pin) {
  pin_ = pin;
  pinMode(pin_, INPUT_PULLUP);
  rawLevelHigh_ = digitalRead(pin_) == HIGH;
  stableLevelHigh_ = rawLevelHigh_;
  rawChangedAtMs_ = millis();
}

ServiceButtonEvent ServiceButton::poll(uint32_t nowMs) {
  const bool currentHigh = digitalRead(pin_) == HIGH;
  if (currentHigh != rawLevelHigh_) {
    rawLevelHigh_ = currentHigh;
    rawChangedAtMs_ = nowMs;
  }

  if ((nowMs - rawChangedAtMs_) >= kDebounceMs) {
    stableLevelHigh_ = rawLevelHigh_;
  }

  if (nowMs < kBootGuardMs) {
    return ServiceButtonEvent::NONE;
  }

  if (!stableLevelHigh_) {
    if (!pressActive_) {
      pressActive_ = true;
      provisioningSent_ = false;
      factoryResetSent_ = false;
      pressedSinceMs_ = nowMs;
    } else if (releaseGapSinceMs_ > 0) {
      if ((nowMs - releaseGapSinceMs_) > kReleaseGapResetMs) {
        pressedSinceMs_ = nowMs;
        provisioningSent_ = false;
        factoryResetSent_ = false;
      }
      releaseGapSinceMs_ = 0;
    }

    const uint32_t heldMs = nowMs - pressedSinceMs_;
    if (!factoryResetSent_ && heldMs >= kFactoryResetHoldMs) {
      factoryResetSent_ = true;
      return ServiceButtonEvent::FACTORY_RESET;
    }

    if (!provisioningSent_ && heldMs >= kProvisioningHoldMinMs &&
        heldMs < kProvisioningHoldMaxMs) {
      provisioningSent_ = true;
      return ServiceButtonEvent::ENTER_PROVISIONING;
    }
  } else if (pressActive_) {
    if (releaseGapSinceMs_ == 0) {
      releaseGapSinceMs_ = nowMs;
    } else if ((nowMs - releaseGapSinceMs_) > kReleaseGapResetMs) {
      pressActive_ = false;
      releaseGapSinceMs_ = 0;
      provisioningSent_ = false;
      factoryResetSent_ = false;
    }
  }

  return ServiceButtonEvent::NONE;
}
