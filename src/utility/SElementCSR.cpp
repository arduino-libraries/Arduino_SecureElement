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

#include <utility/SElementCSR.h>

int SElementCSR::build(SecureElement & se, ECP256Certificate & cert, const int keySlot, bool newPrivateKey)
{
  byte publicKey[ECP256_CERT_PUBLIC_KEY_LENGTH];
  byte signature[ECP256_CERT_SIGNATURE_LENGTH];

  if (newPrivateKey) {
    if (!se.generatePrivateKey(keySlot, publicKey)) {
      return 0;
    }
  } else {
    if (!se.generatePublicKey(keySlot, publicKey)) {
      return 0;
    }
  }

  /* Store public key in CSR */
  if (!cert.setPublicKey(publicKey, ECP256_CERT_PUBLIC_KEY_LENGTH)) {
    return 0;
  }
  
  /* Build CSR */
  if (!cert.buildCSR()) {
    return 0;
  }

  /* compute CSR SHA256 */
  byte sha256buf[SE_SHA256_BUFFER_LENGTH];
  se.SHA256(cert.bytes(), cert.length(), sha256buf);

  if (!se.ecSign(keySlot, sha256buf, signature)) {
    return 0;
  }

  /* sign CSR */
  return cert.signCSR(signature);
}