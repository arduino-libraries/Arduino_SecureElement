/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include "SElementArduinoCloudJWT.h"

constexpr char JWT_HEADER[] = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
String getAIoTCloudJWT(SecureElement &se, String issuer, uint64_t iat, uint8_t slot)
{
  SElementJWS jws;
  String jwtClaim = "{\"iat\":";
  jwtClaim += String((uint32_t)iat);
  jwtClaim += ",\"iss\":\"";
  jwtClaim += issuer;
  jwtClaim += "\"}";
  String token = jws.sign(se, slot, JWT_HEADER, jwtClaim.c_str());
  return token;
}
