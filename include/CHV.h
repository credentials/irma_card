/**
 * CHV.h
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012.
 */

#ifndef __CHV_H
#define __CHV_H

#include "externals.h"
#include "types.h"

/**
 * Verify a PIN code.
 *
 * @param buffer which contains the code to verify.
 */
void CHV_PIN_verify(PIN* pin, ByteArray buffer);

/**
 * Modify a PIN code.
 *
 * @param buffer which contains the old and new code.
 */
void CHV_PIN_update(PIN* pin, ByteArray buffer);

/**
 * Whether a PIN code has been verified.
 */
#define CHV_verified(pin) ((flags & (pin).flag) != 0)

/**
 * Whether a PIN code is required.
 */
#define CHV_required (((credential->userFlags.protect | credential->issuerFlags.protect) & session.prove.disclose) != 0)

/**
 * The number of tries for a PIN.
 */
#define CHV_PIN_COUNT 3

#define CHV_FLAG_CARD_PIN 0x80
#define CHV_FLAG_CRED_PIN 0x40

#endif // __CHV_H
