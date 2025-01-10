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

#include <utility/SElementArduinoCloudCertificate.h>

/******************************************************************************
 * LOCAL MODULE FUNCTIONS
 ******************************************************************************/

static void hexStringToBytes(String in, byte out[], int length) {
  int inLength = in.length();
  in.toUpperCase();
  int outLength = 0;

  for (int i = 0; i < inLength && outLength < length; i += 2) {
    char highChar = in[i];
    char lowChar = in[i + 1];

    byte highByte = (highChar <= '9') ? (highChar - '0') : (highChar + 10 - 'A');
    byte lowByte = (lowChar <= '9') ? (lowChar - '0') : (lowChar + 10 - 'A');

    out[outLength++] = (highByte << 4) | (lowByte & 0xF);
  }
}

/******************************************************************************
 * PUBLIC MEMBER FUNCTIONS
 ******************************************************************************/

int SElementArduinoCloudCertificate::write(SecureElement & se, ECP256Certificate & cert, const SElementArduinoCloudSlot certSlot)
{
#if defined(SECURE_ELEMENT_IS_SE050) || defined(SECURE_ELEMENT_IS_SOFTSE)
  if (!se.writeSlot(static_cast<int>(certSlot), cert.bytes(), cert.length())) {
    return 0;
  }
#else
  if (!se.writeSlot(static_cast<int>(certSlot), cert.compressedCertSignatureAndDatesBytes(), cert.compressedCertSignatureAndDatesLength())) {
    return 0;
  }

  if (!se.writeSlot(static_cast<int>(certSlot) + 1, cert.compressedCertSerialAndAuthorityKeyIdBytes(), cert.compressedCertSerialAndAuthorityKeyIdLenght())) {
    return 0;
  }

  if (!se.writeSlot(static_cast<int>(certSlot) + 2, cert.subjectCommonNameBytes(), cert.subjectCommonNameLenght())) {
    return 0;
  }
#endif
  return 1;
}

int SElementArduinoCloudCertificate::read(SecureElement & se, ECP256Certificate & cert, const SElementArduinoCloudSlot certSlot, const SElementArduinoCloudSlot keySlot)
{
#if defined(SECURE_ELEMENT_IS_SE050) || defined(SECURE_ELEMENT_IS_SOFTSE)
  (void)keySlot;
  byte derBuffer[SE_CERT_BUFFER_LENGTH];
  size_t derLen;
  if (!se.readSlot(static_cast<int>(certSlot), derBuffer, sizeof(derBuffer))) {
    return 0;
  }

  derLen = (derBuffer[2] << 8 | derBuffer[3]) + 4;
  if (!cert.importCert(derBuffer, derLen)) {
    return 0;
  }
#else
  String deviceId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];

  cert.begin();

  if (!se.readSlot(static_cast<int>(certSlot), cert.compressedCertSignatureAndDatesBytes(), cert.compressedCertSignatureAndDatesLength())) {
    return 0;
  }

  if (!se.readSlot(static_cast<int>(certSlot) + 1, cert.compressedCertSerialAndAuthorityKeyIdBytes(), cert.compressedCertSerialAndAuthorityKeyIdLenght())) {
    return 0;
  }

  if (!se.readSlot(static_cast<int>(certSlot) + 2, (byte*)deviceId.begin(), deviceId.length())) {
    return 0;
  }

  if (!se.generatePublicKey(static_cast<int>(keySlot), publicKey)) {
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

int SElementArduinoCloudCertificate::isAuthorityKeyIdDifferent(const ECP256Certificate & cert, const String & authorityKeyIdentifier)
{
  byte authorityKeyIdentifierBytes[ECP256_CERT_AUTHORITY_KEY_ID_LENGTH];

  if (authorityKeyIdentifier.length() == 0 || cert.authorityKeyId() == nullptr) {
    DEBUG_ERROR("SEACC::%s input params error.", __FUNCTION__);
    return -1;
  }

  hexStringToBytes(authorityKeyIdentifier, authorityKeyIdentifierBytes, sizeof(authorityKeyIdentifierBytes));

  /* If authorityKeyId are matching there is no need to rebuild*/
  if (memcmp(authorityKeyIdentifierBytes, cert.authorityKeyId() , ECP256_CERT_AUTHORITY_KEY_ID_LENGTH) == 0) {
    DEBUG_VERBOSE("SEACC::%s authorityKeyIdentifierBytes are equal", __FUNCTION__);
    return 0;
  }
  return 1;
}

int SElementArduinoCloudCertificate::rebuild(SecureElement & se, ECP256Certificate & cert, const String & deviceId, const String & notBefore, const String & notAfter, const String & serialNumber, const String & authorityKeyIdentifier, const String & signature, const SElementArduinoCloudSlot keySlot)
{
  byte serialNumberBytes[ECP256_CERT_SERIAL_NUMBER_LENGTH];
  byte authorityKeyIdentifierBytes[ECP256_CERT_AUTHORITY_KEY_ID_LENGTH];
  byte signatureBytes[ECP256_CERT_SIGNATURE_LENGTH];

  if (!deviceId.length() || !notBefore.length() || !notAfter.length() || !serialNumber.length() || !authorityKeyIdentifier.length() || !signature.length() ) {
    DEBUG_ERROR("SEACC::%s input params error.", __FUNCTION__);
    return 0;
  }

  hexStringToBytes(serialNumber, serialNumberBytes, sizeof(serialNumberBytes));
  hexStringToBytes(authorityKeyIdentifier, authorityKeyIdentifierBytes, sizeof(authorityKeyIdentifierBytes));
  hexStringToBytes(signature, signatureBytes, sizeof(signatureBytes));

  if (!cert.begin()) {
    DEBUG_ERROR("SEACC::%s cert begin error", __FUNCTION__);
    return -1;
  }

  cert.setSubjectCommonName(deviceId);
  cert.setIssuerCountryName("US");
  cert.setIssuerOrganizationName("Arduino LLC US");
  cert.setIssuerOrganizationalUnitName("IT");
  cert.setIssuerCommonName("Arduino");
  cert.setSignature(signatureBytes, sizeof(signatureBytes));
  cert.setAuthorityKeyId(authorityKeyIdentifierBytes, sizeof(authorityKeyIdentifierBytes));
  cert.setSerialNumber(serialNumberBytes, sizeof(serialNumberBytes));
  cert.setIssueYear(notBefore.substring(0,4).toInt());
  cert.setIssueMonth(notBefore.substring(5,7).toInt());
  cert.setIssueDay(notBefore.substring(8,10).toInt());
  cert.setIssueHour(notBefore.substring(11,13).toInt());
  cert.setExpireYears(notAfter.substring(0,4).toInt() - notBefore.substring(0,4).toInt());


  if (!SElementCertificate::build(se, cert, static_cast<int>(keySlot))) {
    DEBUG_ERROR("SEACC::%s cert build error", __FUNCTION__);
    return -1;
  }
  return 1;
}
