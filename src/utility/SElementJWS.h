/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_JWS_H_
#define SECURE_ELEMENT_JWS_H_

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <Arduino_SecureElement.h>

 /******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class SElementJWS : public ECP256Certificate
{
public:

  String publicKey(SecureElement & se, int slot, bool newPrivateKey = true);

  String sign(SecureElement & se, int slot, const char* header, const char* payload);
  String sign(SecureElement & se, int slot, const String& header, const String& payload);

};


#endif /* SECURE_ELEMENT_JWS_H_ */
