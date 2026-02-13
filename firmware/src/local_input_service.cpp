#include "local_input_service.h"

#include "relay_manager.h"

void LocalInputService::begin(const std::array<uint8_t, 3> &pins) {
  pins_ = pins;

  for (size_t i = 0; i < pins_.size(); i += 1) {
    pinMode(pins_[i], INPUT_PULLUP);
    const bool pressed = digitalRead(pins_[i]) == LOW;
    rawPressed_[i] = pressed;
    stablePressed_[i] = pressed;
    lastEdgeAtMs_[i] = 0;
  }
}

bool LocalInputService::poll(uint32_t nowMs, RelayManager &relayManager) {
  bool changed = false;

  for (size_t i = 0; i < pins_.size(); i += 1) {
    const bool rawPressed = digitalRead(pins_[i]) == LOW;
    if (rawPressed != rawPressed_[i]) {
      rawPressed_[i] = rawPressed;
      lastEdgeAtMs_[i] = nowMs;
    }

    if (rawPressed_[i] == stablePressed_[i]) {
      continue;
    }

    if ((nowMs - lastEdgeAtMs_[i]) < kDebounceMs) {
      continue;
    }

    stablePressed_[i] = rawPressed_[i];
    if (!stablePressed_[i]) {
      continue;
    }

    if (!relayManager.toggleRelay(i)) {
      continue;
    }

    changed = true;
    Serial.printf("[input] button=%u pin=%u toggled relay=%u state=%d\n", static_cast<unsigned>(i),
                  static_cast<unsigned>(pins_[i]), static_cast<unsigned>(i),
                  relayManager.getRelayState(i) ? 1 : 0);
  }

  return changed;
}
