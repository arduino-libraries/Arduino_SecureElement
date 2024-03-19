/*
  SecureElement Random Number

  This sketch uses the ECC508/ECC608 or SE050 to generate a random number
  every second and print it to the Serial Monitor

  If the SecureElement is not configured and locked the ConfigurationLocking
  example should be used before running this sketch to setup the chip with a
  default TLS configuration.

  Circuit:
   - A board equipped with ECC508 or ECC608 or SE050 chip

  This example code is in the public domain.
*/

#include <Arduino_SecureElement.h>

SecureElement secureElement;

void setup() {
  Serial.begin(9600);
  while (!Serial);

  if (!secureElement.begin()) {
    Serial.println("Failed to communicate with SecureElement!");
    while (1);
  }

  if (!secureElement.locked()) {
    Serial.println("The SecureElement is not locked!");
    while (1);
  }
}

void loop() {
  Serial.print("Random number = ");
  Serial.println(secureElement.random(65535));

  delay(1000);
}
