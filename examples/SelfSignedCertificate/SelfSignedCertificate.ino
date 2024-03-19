/*
  ArduinoSecureElement - Self Signed Cert

  This sketch can be used to generate a self signed certificate
  for a private key generated in an ECC508/ECC608 or SE050 crypto chip slot.

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
#include <utility/SElementCertificate.h>

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

  Serial.println("Hi there, in order to generate a new self signed cert for your board, we'll need the following information ...");
  Serial.println();

  String issueYear          = promptAndReadLine("Issue year of the certificate? (2000 - 2031)", "2019");
  String issueMonth         = promptAndReadLine("Issue month of the certificate? (1 - 12)", "1");
  String issueDay           = promptAndReadLine("Issue day of the certificate? (1 - 31)", "1");
  String issueHour          = promptAndReadLine("Issue hour of the certificate? (0 - 23)", "0");
  String expireYears        = promptAndReadLine("How many years the certificate is valid for? (1 - 31)", "31");
  String privateKeySlot     = promptAndReadLine("What slot would you like to use for the private key? (0 - 4)", "0");
  String generateNewKey     = promptAndReadLine("Would you like to generate a new private key? (Y/n)", "Y");

  Serial.println();

  generateNewKey.toLowerCase();

  ECP256Certificate Certificate;

  Certificate.begin();
  Certificate.setIssuerCommonName(secureElement.serialNumber());
  Certificate.setSubjectCommonName(secureElement.serialNumber());
  Certificate.setIssueYear(issueYear.toInt());
  Certificate.setIssueMonth(issueMonth.toInt());
  Certificate.setIssueDay(issueDay.toInt());
  Certificate.setIssueHour(issueHour.toInt());
  Certificate.setExpireYears(expireYears.toInt());

  if (!SElementCertificate::build(secureElement, Certificate, privateKeySlot.toInt(), generateNewKey.startsWith("y"), true /* self signed certificate */)) {
    Serial.println("Error starting certificate generation!");
    while (1);
  }

  String cert = Certificate.getCertPEM();

  if (!cert) {
    Serial.println("Error generating self signed certificate!");
    while (1);
  }

  Serial.println("Here's your self signed cert, enjoy!");
  Serial.println();
  Serial.println(cert);
  Serial.println();

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
