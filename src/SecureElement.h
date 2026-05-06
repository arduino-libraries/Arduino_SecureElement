/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_H_
#define SECURE_ELEMENT_H_

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <Arduino.h>
#include <SecureElementConfig.h>

#if defined(SECURE_ELEMENT_IS_ECCX08)
  #include <ECCX08.h>
  #include <utility/ECCX08DefaultTLSConfig.h>
#elif defined(SECURE_ELEMENT_IS_SE050)
  #include <SE05X.h>
#elif defined(SECURE_ELEMENT_IS_SOFTSE)
  #include <SoftwareATSE.h>
#else
  #error "Board not supported"
#endif

#include "ECP256Certificate.h"

/******************************************************************************
 * DEFINE
 ******************************************************************************/
#define SE_SHA256_BUFFER_LENGTH  32
#define SE_CERT_BUFFER_LENGTH  1024

#if defined(SECURE_ELEMENT_IS_SE050)
  #define SE_SN_LENGTH SE05X_SN_LENGTH
#elif defined(SECURE_ELEMENT_IS_ECCX08)
  #define SE_SN_LENGTH 9
#elif defined(SECURE_ELEMENT_IS_SOFTSE)
  #define SE_SN_LENGTH 6
#endif

/******************************************************************************
 * GLOBAL OBJECT DECLARATION
 ******************************************************************************/

#if defined(SECURE_ELEMENT_IS_SE050)
using SecureElementClass = SE05XClass;
extern SecureElementClass &SecureElement;
#elif defined(SECURE_ELEMENT_IS_ECCX08)
using SecureElementClass = ECCX08Class;
extern SecureElementClass &SecureElement;
#elif defined(SECURE_ELEMENT_IS_SOFTSE)
using SecureElementClass = SoftwareATSEClass;
extern SecureElementClass &SecureElement;
#else
#error "Undefined secure element implementation for the current platform"
#endif

#endif /* SECURE_ELEMENT_H_ */
