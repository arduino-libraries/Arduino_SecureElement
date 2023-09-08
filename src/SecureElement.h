/*
  SecureElement.h
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

#ifndef SECURE_ELEMENT_H_
#define SECURE_ELEMENT_H_

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <Arduino.h>
#include <SecureElementConfig.h>

#if defined(BOARD_HAS_ECCX08)
  #include <ECCX08.h>
  #include <ECCX08DefaultTLSConfig.h>
#elif defined(BOARD_HAS_SE050)
  #include <SE05X.h>
#else
  #error "Board not supported"
#endif

#include "ECP256Certificate.h"

/******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class SecureElement
{
public:

  SecureElement();

  inline int begin() { return _secureElement.begin(); }
  inline int locked() { return _secureElement.locked(); }
#if defined(BOARD_HAS_ECCX08)
  inline int writeConfiguration(const byte config[] = ECCX08_DEFAULT_TLS_CONFIG) { return _secureElement.writeConfiguration(config); }
#else
  inline int writeConfiguration(const byte config[] = nullptr) { return _secureElement.writeConfiguration(config); }
#endif
  inline int lock() { return _secureElement.lock(); }

  inline String serialNumber() { return _secureElement.serialNumber(); }

  int SHA256(const uint8_t *buffer, size_t size, uint8_t *digest);

  int buildCSR(ECP256Certificate & cert, const int keySlot, bool newPrivateKey);
  int buildCert(ECP256Certificate & cert, const int keySlot);

  int writeCert(ECP256Certificate & cert, const int certSlot);
  int readCert(ECP256Certificate & cert, const int certSlot);
  
  inline long random(long min, long max) { return this->_secureElement.random(min, max); };
  inline long random(long max) { return this->_secureElement.random(max); };
private:
#if defined(BOARD_HAS_SE050)
  SE05XClass & _secureElement;
#else
  ECCX08Class & _secureElement;
#endif

};

#endif /* SECURE_ELEMENT_H_ */
