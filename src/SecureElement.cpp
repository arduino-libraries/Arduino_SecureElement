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
#if defined(BOARD_HAS_SE050)
: _secureElement {SE05X}
#else
: _secureElement {ECCX08}
#endif
{

}

/******************************************************************************
 * PUBLIC MEMBER FUNCTIONS
 ******************************************************************************/

int SecureElement::writeCert(ECP256Certificate & cert, const int certSlot)
{
#if defined(BOARD_HAS_SE050)
  if (!_secureElement.writeSlot(certSlot, cert.bytes(), cert.length())) {
    return 0;
  }
#else
  if (!_secureElement.writeSlot(certSlot, cert.compressedCertSignatureAndDatesBytes(), cert.compressedCertSignatureAndDatesLength())) {
    return 0;
  }

  if (!_secureElement.writeSlot(certSlot + 1, cert.compressedCertSerialAndAuthorityKeyIdBytes(), cert.compressedCertSerialAndAuthorityKeyIdLenght())) {
    return 0;
  }

  if (!_secureElement.writeSlot(certSlot + 2, cert.subjectCommonNameBytes(), cert.subjectCommonNameLenght())) {
    return 0;
  }
#endif
  return 1;
}

int SecureElement::readCert(ECP256Certificate & cert, const int certSlot, const int keySlot)
{
#if defined(BOARD_HAS_SE050)
  byte derBuffer[SE_CERT_BUFFER_LENGTH];
  size_t derLen;
  if (!_secureElement.readBinaryObject(certSlot, derBuffer, sizeof(derBuffer), &derLen)) {
    return 0;
  }

  if (!cert.importCert(derBuffer, derLen)) {
    return 0;
  }
#else
  String deviceId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];

  cert.begin();

  if (!_secureElement.readSlot(certSlot, cert.compressedCertSignatureAndDatesBytes(), cert.compressedCertSignatureAndDatesLength())) {
    return 0;
  }

  if (!_secureElement.readSlot(certSlot + 1, cert.compressedCertSerialAndAuthorityKeyIdBytes(), cert.compressedCertSerialAndAuthorityKeyIdLenght())) {
    return 0;
  }

  if (!_secureElement.readSlot(certSlot + 2, (byte*)deviceId.begin(), deviceId.length())) {
    return 0;
  }

  if (!_secureElement.generatePublicKey(keySlot, publicKey)) {
    return 0;
  }

  cert.setSubjectCommonName(deviceId);
  cert.setIssuerCountryName("US");
  cert.setIssuerOrganizationName("Arduino LLC US");
  cert.setIssuerOrganizationalUnitName("IT");
  cert.setIssuerCommonName("Arduino");

  if (!cert.setPublicKey(publicKey, ECP256_CERT_PUBLIC_KEY_LENGTH)) {
    return 0;
  }

  if (!cert.buildCert()) {
    return 0;
  }

  if (!cert.signCert()) {
    return 0;
  }
#endif
  return 1;
}

int SecureElement::SHA256(const uint8_t *buffer, size_t size, uint8_t *digest)
{
  _secureElement.beginSHA256();
  uint8_t * cursor = (uint8_t*)buffer;
  uint32_t bytes_read = 0;
#if defined(BOARD_HAS_SE050)
  size_t outLen = 32;
  for(; bytes_read + 64 < size; bytes_read += 64, cursor += 64) {
    _secureElement.updateSHA256(cursor, 64);
  }
  _secureElement.updateSHA256(cursor, size - bytes_read);
  _secureElement.endSHA256(digest, &outLen);
#else
  for(; bytes_read + 64 < size; bytes_read += 64, cursor += 64) {
    _secureElement.updateSHA256(cursor);
  }
  _secureElement.endSHA256(cursor, size - bytes_read, digest);
#endif
}

