/*
  This file is part of the Arduino_SecureElement library.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include <SecureElement.h>

#if defined(SECURE_ELEMENT_IS_SE050)
SecureElementClass &SecureElement(SE05X);
#elif defined(SECURE_ELEMENT_IS_ECCX08)
SecureElementClass &SecureElement(ECCX08);
#elif defined(SECURE_ELEMENT_IS_SOFTSE)
SecureElementClass &SecureElement(SATSE);
#else
#error "Undefined secure element implementation for the current platform"
#endif
