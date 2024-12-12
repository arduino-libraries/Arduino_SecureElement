/*
  ArduinoSecureElement - JSON Web Token

  This sketch can be used to generate a JSON Web Token from a private key
  stored in an ECC508/ECC608 or SE050 crypto chip slot.

  If the SecureElement is not configured and locked it prompts
  the user to configure and lock the chip with a default TLS
  configuration.

  The user can also select the slot number to use for the private key.
  A new private key can also be generated in this slot.

  The circuit:
  - A board equipped with ECC508 or ECC608 or SE050 chip

  This example code is in the public domain.
*/

#include <Arduino_SecureElement.h>
#include <Arduino_JSON.h>
#include <utility/SElementJWS.h>

void setup() {
  Serial.begin(9600);
  while (!Serial);

  SecureElement secureElement;

  if (!secureElement.begin()) {
    Serial.println("No SecureElement present!");
    while (1);
  }

  String serialNumber = secureElement.serialNumber();

  Serial.print("SecureElement Serial Number = ");
  Serial.println(serialNumber);
  Serial.println();

  if (!secureElement.locked()) {
    String lock = promptAndReadLine("The SecureElement on your board is not locked, would you like to PERMANENTLY configure and lock it now? (y/N)", "N");
    lock.toLowerCase();

    if (!lock.startsWith("y")) {
      Serial.println("Unfortunately you can't proceed without locking it :(");
      while (1);
    }

    if (!secureElement.writeConfiguration()) {
      Serial.println("Writing SecureElement configuration failed!");
      while (1);
    }

    if (!secureElement.lock()) {
      Serial.println("Locking SecureElement configuration failed!");
      while (1);
    }

    Serial.println("SecureElement locked successfully");
    Serial.println();
  }

  Serial.println("Hi there, in order to generate a PEM public key for your board, we'll need the following information ...");
  Serial.println();

  String slot               = promptAndReadLine("What slot would you like to use? (0 - 4)", "0");
  String generateNewKey     = promptAndReadLine("Would you like to generate a new private key? (Y/n)", "Y");
  String issuer             = promptAndReadLine("Issuer (Device UID)", "");
  String iat                = promptAndReadLine("Issued at (Unix Timestamp)", "");
  String exp                = promptAndReadLine("Expires at (Unix Timestamp)", "");

  Serial.println();

  generateNewKey.toLowerCase();

  SElementJWS jws;

  String publicKeyPem = jws.publicKey(secureElement, slot.toInt(), generateNewKey.startsWith("y"));

  if (!publicKeyPem || publicKeyPem == "") {
    Serial.println("Error generating public key!");
    while (1);
  }

  Serial.println("Here's your public key PEM, enjoy!");
  Serial.println();
  Serial.println(publicKeyPem);

  JSONVar jwtHeader;
  JSONVar jwtClaim;

  jwtHeader["alg"] = "ES256";
  jwtHeader["typ"] = "JWT";

  jwtClaim["iss"] = issuer;
  jwtClaim["iat"] = iat.toInt();
  jwtClaim["exp"] = exp.toInt();

  String token = jws.sign(secureElement, slot.toInt(), JSON.stringify(jwtHeader), JSON.stringify(jwtClaim));

  Serial.println("Here's your JSON Web Token, enjoy!");
  Serial.println();
  Serial.println(token);
}

void loop() {
  // do nothing
}

String promptAndReadLine(const char* prompt, const char* defaultValue) {
  Serial.print(prompt);
  Serial.print(" [");
  Serial.print(defaultValue);
  Serial.print("]: ");

  String s = readLine();

  if (s.length() == 0) {
    s = defaultValue;
  }

  Serial.println(s);

  return s;
}

String readLine() {
  String line;

  while (1) {
    if (Serial.available()) {
      char c = Serial.read();

      if (c == '\r') {
        // ignore
        continue;
      } else if (c == '\n') {
        break;
      }

      line += c;
    }
  }

  return line;
}
