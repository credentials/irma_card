/**
 * CHV.h
 *
 * This file is part of IRMAcard.
 *
 * IRMAcard is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IRMAcard is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IRMAcard. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) May 2012 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __CHV_H
#define __CHV_H

/**
 * The maximum size of a PIN.
 */
#define CHV_PIN_SIZE 8

/**
 * The number of tries for a PIN.
 */
#define CHV_PIN_COUNT 3

extern unsigned char CHV_flags;


typedef struct {
  unsigned char code[CHV_PIN_SIZE];
  unsigned char minSize;
  unsigned char count;
  unsigned char flag;
} CHV_PIN;

/**
 * Verify a PIN code.
 *
 * @param buffer which contains the code to verify.
 */
void CHV_PIN_verify(CHV_PIN* pin, unsigned char *buffer);

/**
 * Modify a PIN code.
 *
 * @param buffer which contains the old and new code.
 */
void CHV_PIN_update(CHV_PIN* pin, unsigned char *buffer);


/**
 * Whether a PIN code has been verified.
 */
#define CHV_verified(pin) ((CHV_flags & (pin).flag) != 0)

/**
 * Whether a PIN code is required.
 */
#define CHV_required (((credential->userFlags.protect | credential->issuerFlags.protect) & session.prove.disclose) != 0)

#endif // __CHV_H
