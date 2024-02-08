/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_ARDUINO_CLOUD_DEVICE_ID_H_
#define SECURE_ELEMENT_ARDUINO_CLOUD_DEVICE_ID_H_

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <utility/SElementArduinoCloud.h>

 /******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class SElementArduinoCloudDeviceId
{
public:

  static int write(SecureElement & se, String & deviceId, const SElementArduinoCloudSlot idSlot);
  static int read(SecureElement & se, String & deviceId, const SElementArduinoCloudSlot idSlot);

};

#endif /* SECURE_ELEMENT_ARDUINO_CLOUD_DEVICE_ID_H_ */