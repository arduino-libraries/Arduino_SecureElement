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
#include <ArduinoECCX08.h>
#include <utility/ASN1Utils.h>
#include <utility/PEMUtils.h>

static String base64urlEncode(const byte in[], unsigned int length)
{
  static const char* CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

  int b;
  String out;

  int reserveLength = 4 * ((length + 2) / 3);
  out.reserve(reserveLength);

  for (unsigned int i = 0; i < length; i += 3) {
    b = (in[i] & 0xFC) >> 2;
    out += CODES[b];

    b = (in[i] & 0x03) << 4;
    if (i + 1 < length) {
      b |= (in[i + 1] & 0xF0) >> 4;
      out += CODES[b];
      b = (in[i + 1] & 0x0F) << 2;
      if (i + 2 < length) {
         b |= (in[i + 2] & 0xC0) >> 6;
         out += CODES[b];
         b = in[i + 2] & 0x3F;
         out += CODES[b];
      } else {
        out += CODES[b];
      }
    } else {
      out += CODES[b];
    }
  }

  while (out.lastIndexOf('=') != -1) {
    out.remove(out.length() - 1);
  }

  return out;
}

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

  int length = ASN1Utils.publicKeyLength();
  byte out[length];

  ASN1Utils.appendPublicKey(publicKey, out);

  return PEMUtils.base64Encode(out, length, "-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----\n");
}

String SElementJWS::sign(SecureElement & se, int slot, const char* header, const char* payload)
{
  if (slot < 0 || slot > 8) {
    return "";
  }

  String encodedHeader = base64urlEncode((const byte*)header, strlen(header));
  String encodedPayload = base64urlEncode((const byte*)payload, strlen(payload));

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

  String encodedSignature = base64urlEncode(signature, sizeof(signature));

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
