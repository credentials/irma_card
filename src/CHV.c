/**
 * CHV.c
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope t_ it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012.
 */

#include "CHV.h"

#include "APDU.h"
#include "debug.h"
#include "memory.h"

#pragma melsession
unsigned char CHV_flags;
#pragma melstatic

/**
 * Verify a PIN code.
 *
 * @param buffer which contains the code to verify.
 */
void CHV_PIN_verify(CHV_PIN *pin, unsigned char *buffer) {
  // Verify if the PIN has not been blocked
  if (pin->count == 0) {
    APDU_ReturnSW(SW_COUNTER_PROVIDED_BY_X(0));
  }

  // Compare the PIN with the stored code
  if (NotEqual(CHV_PIN_SIZE, buffer, pin->code)) {
    debugWarning("PIN verification failed");
    debugInteger("Tries left", pin->count - 1);
    APDU_ReturnSW(SW_COUNTER_PROVIDED_BY_X(0) | --(pin->count));
  } else {
    debugMessage("PIN verified ");
    pin->count = CHV_PIN_COUNT;
    CHV_flags |= pin->flag;
  }
}

/**
 * Modify a PIN code
 *
 * @param buffer which contains the old and new code
 */
void CHV_PIN_update(CHV_PIN *pin, unsigned char *buffer) {
  int i;
  
  // Verify the original PIN
  CHV_PIN_verify(pin, buffer);

  // Verify the new PIN size
  for (i = 0; i < pin->minSize; i++) {
	if (buffer[CHV_PIN_SIZE + i] == 0x00) {
      APDU_ReturnSW(SW_WRONG_LENGTH);
    }
  }

  // Store the new code
  CopyBytes(CHV_PIN_SIZE, pin->code, buffer + CHV_PIN_SIZE);
}
