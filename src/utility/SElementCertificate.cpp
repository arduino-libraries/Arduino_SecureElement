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

#include <utility/SElementCertificate.h>

int SElementCertificate::build(SecureElement & se, ECP256Certificate & cert, const int keySlot, bool newPrivateKey, bool selfSign)
{
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];
  byte signature[ECP256_CERT_SIGNATURE_LENGTH];

  if(newPrivateKey) {
    if (!se.generatePrivateKey(keySlot, publicKey)) {
      return 0;
    }
  } else {
    if (!se.generatePublicKey(keySlot, publicKey)) {
      return 0;
    }
  }

  /* Store public key in Certificate */
  if (!cert.setPublicKey(publicKey, ECP256_CERT_PUBLIC_KEY_LENGTH)) {
    return 0;
  }

  /* Build Certificate */
  if (!cert.buildCert()) {
    return 0;
  }

  if (selfSign) {
    byte sha256buf[SE_SHA256_BUFFER_LENGTH];
    se.SHA256(cert.bytes(), cert.length(), sha256buf);

    if (!se.ecSign(keySlot, sha256buf, signature)) {
      return 0;
    }

    /* self sign Certificate */
    return cert.signCert(signature);
  }

  /* sign Certificate */
  return cert.signCert();
}
