/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_AIoTCloud_JWT_H_
#define SECURE_ELEMENT_AIoTCloud_JWT_H_
#include "SElementJWS.h"

String getAIoTCloudJWT(SecureElement &se, String issuer, uint64_t iat, uint8_t slot = 1);

#endif
