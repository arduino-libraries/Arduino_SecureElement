
/*
  SecureElementConfig.h
  Copyright (c) 2023 Arduino SA.  All right reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef SECURE_ELEMENT_CONFIG_H_
#define SECURE_ELEMENT_CONFIG_H_

#if defined(ARDUINO_AVR_UNO_WIFI_REV2) || \
  defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT) ||  \ 
  defined(ARDUINO_SAMD_MKRGSM1400)  || defined(ARDUINO_SAMD_MKR1000) ||      \
  defined(ARDUINO_SAMD_MKRNB1500)   || defined(ARDUINO_PORTENTA_H7_M7)  ||   \
  defined(ARDUINO_NANO_RP2040_CONNECT) || defined(ARDUINO_OPTA) || \
  defined(ARDUINO_GIGA)
  #define BOARD_HAS_ECCX08
#endif

#if defined(ARDUINO_NICLA_VISION) || defined(ARDUINO_PORTENTA_C33)
  #define BOARD_HAS_SE050
#endif

#endif /* SECURE_ELEMENT_CONFIG_H_ */
