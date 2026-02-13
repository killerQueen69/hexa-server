#pragma once

#include <Arduino.h>
#include <array>

class RelayManager;

class LocalInputService {
public:
  void begin(const std::array<uint8_t, 3> &pins);
  bool poll(uint32_t nowMs, RelayManager &relayManager);

private:
  static constexpr uint32_t kDebounceMs = 30;

  std::array<uint8_t, 3> pins_ = {4, 5, 3};
  std::array<bool, 3> rawPressed_ = {false, false, false};
  std::array<bool, 3> stablePressed_ = {false, false, false};
  std::array<uint32_t, 3> lastEdgeAtMs_ = {0, 0, 0};
};
