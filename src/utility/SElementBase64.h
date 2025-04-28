/*
    This file is part of the Arduino_SecureElement library.

    Copyright (c) 2024 Arduino SA

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <Arduino.h>

namespace arduino { namespace b64 {

    String urlEncode(const byte in[], unsigned int length);
    String pemEncode(const byte in[], unsigned int length, const char* prefix, const char* suffix);

}} // arduino::b64
