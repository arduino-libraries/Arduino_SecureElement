/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_ARDUINO_CLOUD_H_
#define SECURE_ELEMENT_ARDUINO_CLOUD_H_

#include <Arduino_SecureElement.h>

/******************************************************************************
 * DEFINE
 ******************************************************************************/
#if defined(SECURE_ELEMENT_IS_SE050)
#define SECURE_ELEMENT_SLOT_OFFSET                100
#else
#define SECURE_ELEMENT_SLOT_OFFSET                0
#endif

/******************************************************************************
   TYPEDEF
 ******************************************************************************/
enum class SElementArduinoCloudSlot : int
{
  Key                                   = (0  + SECURE_ELEMENT_SLOT_OFFSET),
  CompressedCertificate                 = (10 + SECURE_ELEMENT_SLOT_OFFSET),
  SerialNumberAndAuthorityKeyIdentifier = (11 + SECURE_ELEMENT_SLOT_OFFSET),
  DeviceId                              = (12 + SECURE_ELEMENT_SLOT_OFFSET)
};

#endif /* SECURE_ELEMENT_ARDUINO_CLOUD_H_ */