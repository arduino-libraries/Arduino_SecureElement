/*
  Configure and Lock your ATECCX08 SecureElement

  This sketch can be used to apply default configuration and lock
  yout ATECCX08 Secure Element.
  Default configuration can be found here:
  https://github.com/arduino-libraries/ArduinoECCX08/blob/master/src/utility/ECCX08DefaultTLSConfig.h

  SE050 do not have EEPROM configuration and do not need to be locked
  to work correctly. secureElement.locked() always returns true for SE050
  and the sketch does nothing.

  The circuit:
  - A board equipped with ECC508 or ECC608 or SE050 chip

  This example code is in the public domain.
*/

#include <Arduino_SecureElement.h>

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
  } else {
#if defined(SECURE_ELEMENT_IS_ECCX08)
    Serial.println("SecureElement already locked!");
    Serial.println();
#else
    Serial.println("SecureElement does not need to be locked!");
    Serial.println();
#endif
  }

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
