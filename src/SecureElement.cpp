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

/******************************************************************************
 * DEFINE
 ******************************************************************************/
#define SE_SHA256_BUFFER_LENGTH  32
#define SE_CERT_BUFFER_LENGTH  1024

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

int SecureElement::buildCSR(ECP256Certificate & cert, const int keySlot, bool newPrivateKey)
{
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];
  byte signature[ECP256_CERT_SIGNATURE_LENGTH];

  if (newPrivateKey) {
    if (!_secureElement.generatePrivateKey(keySlot, publicKey)) {
      Serial.println("Error1");
      return 0;
    }
  } else {
    if (!_secureElement.generatePublicKey(keySlot, publicKey)) {
            Serial.println("Error2");
      return 0;
    }
  }

  /* Store public key in csr */
  if (!cert.setPublicKey(publicKey, ECP256_CERT_PUBLIC_KEY_LENGTH)) {
      Serial.println("Error3");
    return 0;
  }
  
  /* Build CSR */
  if (!cert.buildCSR()) {
        Serial.println("Error4");
    return 0;
  }

  /* compute CSR SHA256 */
  byte sha256buf[SE_SHA256_BUFFER_LENGTH];
  this->SHA256(cert.bytes(), cert.length(), sha256buf);

  if (!_secureElement.ecSign(keySlot, sha256buf, signature)) {
        Serial.println("Error5");
    return 0;
  }

  /* sign CSR */
  return cert.signCSR(signature);
}

int SecureElement::buildCert(ECP256Certificate & cert, const int keySlot)
{
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];

  if (!_secureElement.generatePublicKey(keySlot, publicKey)) {
    return 0;
  }

  /* Store public key in csr */
  if (!cert.setPublicKey(publicKey, ECP256_CERT_PUBLIC_KEY_LENGTH)) {
    return 0;
  }

  /* Build CSR */
  if (!cert.buildCert()) {
    return 0;
  }

  /* sign CSR */
  return cert.signCert();
}

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

  if (!readDeviceId(deviceId, int::DeviceId)) {
    return 0;
  }

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
#if defined(BOARD_HAS_SE050)
  size_t outLen;
  _secureElement.SHA256(buffer, size, digest, 32, &outLen);
#else
  _secureElement.beginSHA256();
  
  unit8_t * cursor = buffer;
  uint32_t bytes_read = 0;
  for(; bytes_read + 64 < size; bytes_read += 64, cursor += 64;) {
    _secureElement.updateSHA256(cursor);
  }
  _secureElement.endSHA256(cursor, size - bytes_read, digest);
#endif
}

