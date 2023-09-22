/*
  SElementCSR.cpp
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