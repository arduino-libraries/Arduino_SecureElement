/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef SECURE_ELEMENT_ARDUINO_CLOUD_CERTIFICATE_H_
#define SECURE_ELEMENT_ARDUINO_CLOUD_CERTIFICATE_H_

/******************************************************************************
 * INCLUDE
 ******************************************************************************/

#include <utility/SElementCertificate.h>
#include <utility/SElementArduinoCloud.h>

 /******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class SElementArduinoCloudCertificate : public SElementCertificate
{
public:

  static int write(SecureElement & se, ECP256Certificate & cert, const SElementArduinoCloudSlot certSlot);
  static int read(SecureElement & se, ECP256Certificate & cert, const SElementArduinoCloudSlot certSlot, const SElementArduinoCloudSlot keySlot = SElementArduinoCloudSlot::Key);
  static int signatureCompare(const byte * signatureA, const String & signatureB);
  static int rebuild(SecureElement & se, ECP256Certificate & cert, const String & deviceId,
                    const String & notBefore, const String & notAfter, const String & serialNumber,
                    const String & authorityKeyIdentifier, const String & signature,
                    const SElementArduinoCloudSlot keySlot = SElementArduinoCloudSlot::Key);

private:

  static const char constexpr SEACC_ISSUER_COUNTRY_NAME[] = "US";
  static const char constexpr SEACC_ISSUER_ORGANIZATION_NAME[] = "Arduino LLC US";
  static const char constexpr SEACC_ISSUER_ORGANIZATIONAL_UNIT_NAME[] = "IT";
  static const char constexpr SEACC_ISSUER_COMMON_NAME[] = "Arduino";

};

#endif /* SECURE_ELEMENT_ARDUINO_CLOUD_CERTIFICATE_H_ */