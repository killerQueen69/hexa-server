#pragma once

#include <Arduino.h>

#include "app_config.h"

struct DeviceProvisionResult {
  bool ok = false;
  String deviceUid;
  String deviceToken;
  String claimCode;
  String error;
};

class DeviceProvisionService {
public:
  DeviceProvisionResult provision(const AppConfig &config) const;
};
