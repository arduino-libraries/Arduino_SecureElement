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
