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

/******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class SecureElement
{
public:

  SecureElement();

  inline int begin() { return _secureElement.begin(); }
  inline void end() { return _secureElement.end(); }

  inline String serialNumber() { return _secureElement.serialNumber(); }

  inline long random(long min, long max) { return this->_secureElement.random(min, max); };
  inline long random(long max) { return this->_secureElement.random(max); };

  inline int generatePrivateKey(int slot, byte publicKey[]) { return _secureElement.generatePrivateKey(slot, publicKey); };
  inline int generatePublicKey(int slot, byte publicKey[]) { return _secureElement.generatePublicKey(slot, publicKey); };

  inline int ecdsaVerify(const byte message[], const byte signature[], const byte pubkey[]) { return _secureElement.ecdsaVerify(message, signature, pubkey); };
  inline int ecSign(int slot, const byte message[], byte signature[]) { return _secureElement.ecSign(slot, message, signature); };

  int SHA256(const uint8_t *buffer, size_t size, uint8_t *digest);

  inline int readSlot(int slot, byte data[], int length) { return _secureElement.readSlot(slot, data, length); };
  inline int writeSlot(int slot, const byte data[], int length) { return _secureElement.writeSlot(slot, data, length); };

  inline int locked() { return _secureElement.locked(); }
  inline int lock() { return _secureElement.lock(); }
#if defined(SECURE_ELEMENT_IS_ECCX08)
  inline int writeConfiguration(const byte config[] = ECCX08_DEFAULT_TLS_CONFIG) { return _secureElement.writeConfiguration(config); }
#else
  inline int writeConfiguration(const byte config[] = nullptr) { return _secureElement.writeConfiguration(config); }
#endif

private:
#if defined(SECURE_ELEMENT_IS_SE050)
  SE05XClass & _secureElement;
#elif defined(SECURE_ELEMENT_IS_ECCX08)
  ECCX08Class & _secureElement;
#elif defined(SECURE_ELEMENT_IS_SOFTSE)
  SoftwareATSEClass & _secureElement;
#else

#endif

};

#endif /* SECURE_ELEMENT_H_ */
