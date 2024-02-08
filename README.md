Arduino_SecureElement
====================

[![Compile Examples](https://github.com/arduino-libraries/Arduino_SecureElement/workflows/Compile%20Examples/badge.svg)](https://github.com/arduino-libraries/Arduino_SecureElement/actions?workflow=Compile+Examples)
[![Arduino Lint](https://github.com/arduino-libraries/Arduino_SecureElement/workflows/Arduino%20Lint/badge.svg)](https://github.com/arduino-libraries/Arduino_SecureElement/actions?workflow=Arduino+Lint)
[![Spell Check](https://github.com/arduino-libraries/Arduino_SecureElement/workflows/Spell%20Check/badge.svg)](https://github.com/arduino-libraries/Arduino_SecureElement/actions?workflow=Spell+Check)

This library allows usage of Arduino boards secure elements in a common and unified way.

## :chains: Dependencies

Arduino_SecureElement depends on: 

* [ArduinoECCX08](https://github.com/espressif/arduino-esp32/tree/master/libraries/Update) for Atmel/Microchip ECC508 and ECC608 crypto chips
* SE05X [nano](https://github.com/arduino/ArduinoCore-renesas/tree/main/libraries/SE05X) or [full](https://github.com/arduino/ArduinoCore-mbed/tree/main/libraries/SE05X) for NXP SE050 crypto chip
* [SATSE]() a software "secure element" implementation, NOT secure at all, for the Arduino UNO R4 WiFi.

## :closed_lock_with_key: Features

Arduino_SecureElement supports a reduced and common subset of operations:

* Random number generation
* SHA256 digest
* ECCurve_NIST_P256 key generation
* ECDSA sign and verify

