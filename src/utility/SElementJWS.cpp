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

#include <utility/SElementJWS.h>
#include <utility/SElementBase64.h>

String SElementJWS::publicKey(SecureElement & se, int slot, bool newPrivateKey)
{
  if (slot < 0 || slot > 8) {
    return "";
  }

  byte publicKey[64];

  if (newPrivateKey) {
    if (!se.generatePrivateKey(slot, publicKey)) {
      return "";
    }
  } else {
    if (!se.generatePublicKey(slot, publicKey)) {
      return "";
    }
  }

  int length = publicKeyLength();
  byte out[length];

  appendPublicKey(publicKey, out);

  return b64::pemEncode(out, length, "-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----\n");
}

String SElementJWS::sign(SecureElement & se, int slot, const char* header, const char* payload)
{
  if (slot < 0 || slot > 8) {
    return "";
  }

  String encodedHeader = b64::urlEncode((const byte*)header, strlen(header));
  String encodedPayload = b64::urlEncode((const byte*)payload, strlen(payload));

  String toSign;
  toSign.reserve(encodedHeader.length() + 1 + encodedPayload.length());

  toSign += encodedHeader;
  toSign += '.';
  toSign += encodedPayload;


  byte toSignSha256[32];
  byte signature[64];

  se.SHA256((const uint8_t*)toSign.c_str(), toSign.length(), toSignSha256);

  if (!se.ecSign(slot, toSignSha256, signature)) {
    return "";
  }

  String encodedSignature = b64::urlEncode(signature, sizeof(signature));

  String result;
  result.reserve(toSign.length() + 1 + encodedSignature.length());

  result += toSign;
  result += '.';
  result += encodedSignature;

  return result;
}

String SElementJWS::sign(SecureElement & se, int slot, const String& header, const String& payload)
{
  return sign(se, slot, header.c_str(), payload.c_str());
}
