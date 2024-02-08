/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <utility/SElementArduinoCloudDeviceId.h>

int SElementArduinoCloudDeviceId::write(SecureElement & se, String & deviceId, const SElementArduinoCloudSlot idSlot)
{
  byte device_id_bytes[ECP256_CERT_COMPRESSED_CERT_SLOT_LENGTH] = {0};

  deviceId.getBytes(device_id_bytes, sizeof(device_id_bytes));
  
  if (!se.writeSlot(static_cast<int>(idSlot), device_id_bytes, sizeof(device_id_bytes))) {
    return 0;
  }
  return 1;
}

int SElementArduinoCloudDeviceId::read(SecureElement & se, String & deviceId, const SElementArduinoCloudSlot idSlot)
{
  byte device_id_bytes[ECP256_CERT_COMPRESSED_CERT_SLOT_LENGTH] = {0};

  if (!se.readSlot(static_cast<int>(idSlot), device_id_bytes, sizeof(device_id_bytes))) {
    return 0;
  }

  deviceId = String(reinterpret_cast<char *>(device_id_bytes));
  return 1;
}
