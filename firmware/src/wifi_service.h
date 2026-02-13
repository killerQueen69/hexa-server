#pragma once

#include "app_config.h"
#include "status_led.h"

class WifiService {
public:
  bool connect(AppConfig &config, StatusLed &statusLed, bool forceProvisioning);
  void resetWifiCredentials();

private:
  bool connectWithConfig(const AppConfig &config, StatusLed &statusLed);
  bool runProvisioningPortal(AppConfig &config, StatusLed &statusLed);
};
