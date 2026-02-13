#include "relay_manager.h"

void RelayManager::begin(const std::array<uint8_t, 3> &pins, bool activeLow) {
  pins_ = pins;
  activeLow_ = activeLow;

  for (size_t i = 0; i < pins_.size(); i += 1) {
    pinMode(pins_[i], OUTPUT);
    writePin(i, false);
    states_[i] = false;
  }
}

bool RelayManager::setRelay(uint8_t relayIndex, bool on) {
  if (relayIndex >= states_.size()) {
    return false;
  }

  states_[relayIndex] = on;
  writePin(relayIndex, on);
  return true;
}

bool RelayManager::toggleRelay(uint8_t relayIndex) {
  if (relayIndex >= states_.size()) {
    return false;
  }

  return setRelay(relayIndex, !states_[relayIndex]);
}

void RelayManager::setAll(bool on) {
  for (size_t i = 0; i < states_.size(); i += 1) {
    setRelay(i, on);
  }
}

bool RelayManager::getRelayState(uint8_t relayIndex) const {
  if (relayIndex >= states_.size()) {
    return false;
  }

  return states_[relayIndex];
}

const std::array<bool, 3> &RelayManager::getRelayStates() const {
  return states_;
}

size_t RelayManager::relayCount() const {
  return states_.size();
}

void RelayManager::writePin(uint8_t relayIndex, bool on) {
  const bool driveHigh = activeLow_ ? !on : on;
  digitalWrite(pins_[relayIndex], driveHigh ? HIGH : LOW);
}
