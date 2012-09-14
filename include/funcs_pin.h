/**
 * funcs_pin.h
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
 
#ifndef __funcs_pin_H
#define __funcs_pin_H

#include "defs_externals.h"
#include "defs_types.h"

#define PIN_COUNT 3
#define PIN_OK 0x80
#define PIN_REQUIRED 0x80

/**
 * Verify a PIN code
 * 
 * @param buffer which contains the code to verify
 */
void pin_verify(ByteArray buffer);

/**
 * Modify a PIN code
 *
 * @param buffer which contains the old and new code
 */
void pin_modify(ByteArray buffer);

/**
 * Whether a PIN code has been verified
 */
#define pin_verified ((flags & PIN_OK) != 0)

/**
 * Whether a PIN code is required
 */
#define pin_required ((credential->flags & PIN_REQUIRED) != 0)

#endif // __funcs_pin_H
