#pragma once

#include <Arduino.h>
#include <array>

class RelayManager {
public:
  void begin(const std::array<uint8_t, 3> &pins, bool activeLow);
  bool setRelay(uint8_t relayIndex, bool on);
  bool toggleRelay(uint8_t relayIndex);
  void setAll(bool on);
  bool getRelayState(uint8_t relayIndex) const;
  const std::array<bool, 3> &getRelayStates() const;
  size_t relayCount() const;

private:
  void writePin(uint8_t relayIndex, bool on);

  std::array<uint8_t, 3> pins_ = {12, 13, 14};
  std::array<bool, 3> states_ = {false, false, false};
  bool activeLow_ = false;
};
