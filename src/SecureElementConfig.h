/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_CONFIG_H_
#define SECURE_ELEMENT_CONFIG_H_

#if defined(ARDUINO_AVR_UNO_WIFI_REV2) || \
  defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT) ||  \ 
  defined(ARDUINO_SAMD_MKRGSM1400)  || defined(ARDUINO_SAMD_MKR1000) ||      \
  defined(ARDUINO_SAMD_MKRNB1500)   || defined(ARDUINO_PORTENTA_H7_M7)  ||   \
  defined(ARDUINO_NANO_RP2040_CONNECT) || defined(ARDUINO_OPTA) || \
  defined(ARDUINO_GIGA)
  #define SECURE_ELEMENT_IS_ECCX08
#endif

#if defined(ARDUINO_NICLA_VISION) || defined(ARDUINO_PORTENTA_C33)
  #define SECURE_ELEMENT_IS_SE050
#endif

#if defined(ARDUINO_UNOR4_WIFI)
  #define SECURE_ELEMENT_IS_SOFTSE
#endif

#endif /* SECURE_ELEMENT_CONFIG_H_ */
