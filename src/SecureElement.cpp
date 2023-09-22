/*
  SecureElement.cpp
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
#endif
  return 1;
}

int SecureElement::readCert(ECP256Certificate & cert, const int certSlot)
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
  String deviceId;
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];

  cert.begin();

  /* To do certificate is splitted into multiple slots */
  //if (!readDeviceId(deviceId, 0)) {
  //  return 0;
  //}

  if (!_secureElement.readSlot(certSlot, cert.compressedCertSignatureAndDatesBytes(), cert.compressedCertSignatureAndDatesLength())) {
    return 0;
  }

  if (!_secureElement.readSlot(certSlot + 1, cert.compressedCertSerialAndAuthorityKeyIdBytes(), cert.compressedCertSerialAndAuthorityKeyIdLenght())) {
    return 0;
  }

  /* TODO check key slot */
  if (!_secureElement.generatePublicKey(0, publicKey)) {
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

