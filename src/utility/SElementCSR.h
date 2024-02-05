/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_CSR_H_
#define SECURE_ELEMENT_CSR_H_

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <Arduino_SecureElement.h>

 /******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class SElementCSR
{
public:

  static int build(SecureElement & se, ECP256Certificate & cert, const int keySlot, bool newPrivateKey);

};

#endif /* SECURE_ELEMENT_CSR_H_ */
