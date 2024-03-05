/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <SecureElementConfig.h>
#include <SecureElement.h>

/**************************************************************************************
 * CTOR/DTOR
 **************************************************************************************/
SecureElement::SecureElement()
#if defined(SECURE_ELEMENT_IS_SE050)
: _secureElement {SE05X}
#elif defined(SECURE_ELEMENT_IS_ECCX08)
: _secureElement {ECCX08}
#elif defined(SECURE_ELEMENT_IS_SOFTSE)
: _secureElement {SATSE}
#else

#endif
{

}

/******************************************************************************
 * PUBLIC MEMBER FUNCTIONS
 ******************************************************************************/

int SecureElement::SHA256(const uint8_t *buffer, size_t size, uint8_t *digest)
{
#if defined(SECURE_ELEMENT_IS_SOFTSE)
  return _secureElement.SHA256(buffer, size, digest);
#else
  _secureElement.beginSHA256();
  uint8_t * cursor = (uint8_t*)buffer;
  uint32_t bytes_read = 0;
#if defined(SECURE_ELEMENT_IS_SE050)
  size_t outLen = 32;
  for(; bytes_read + 64 < size; bytes_read += 64, cursor += 64) {
    _secureElement.updateSHA256(cursor, 64);
  }
  _secureElement.updateSHA256(cursor, size - bytes_read);
  return _secureElement.endSHA256(digest, &outLen);
#else
  for(; bytes_read + 64 < size; bytes_read += 64, cursor += 64) {
    _secureElement.updateSHA256(cursor);
  }
  return _secureElement.endSHA256(cursor, size - bytes_read, digest);
#endif
#endif
}

