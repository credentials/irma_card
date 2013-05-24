/**
 * types.debug.h
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
 * Copyright (C) April 2013 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __types_debug_H
#define __types_debug_H

#include "debug.h"
#include "types.h"

/**
 * Print the hash as debug output.
 *
 * @param label associated with the hash in the output.
 * @param value of the hash to be printed.
 */
#define debugHash(label, value) \
  debugValue(label, value, sizeof(Hash))

/**
 * Print the nonce as debug output.
 *
 * @param label associated with the nonce in the output.
 * @param value of the nonce to be printed.
 */
#define debugNonce(label, value) \
  debugValue(label, value, sizeof(Nonce))

/**
 * Print the number as debug output.
 *
 * @param label associated with the number in the output.
 * @param value of the number to be printed.
 */
#define debugNumber(label, value) \
  debugValue(label, value, sizeof(Number))

/**
 * Print an indexed number (from an array) as debug output.
 *
 * @param label associated with the number in the output.
 * @param array containing the number to be printed.
 * @param index of the number in the array.
 */
#define debugIndexedNumber(label, value, index) \
  debugIndexedValue(label, value, sizeof(Number), index)

/**
 * Print the hash value as debug output.
 *
 * @param label associated with the hash value in the output.
 * @param value of the hash to be printed.
 */
#define debugNumbers(label, value, count) \
  debugValues(label, value, sizeof(Number), count)

/**
 * Print an indexed CL message (from an array) as debug output.
 *
 * @param label associated with the CL message in the output.
 * @param array containing the CL message to be printed.
 * @param index of the CL message in the array.
 */
#define debugIndexedCLMessage(label, value, index) \
  debugIndexedValue(label, value, sizeof(CLMessage), index)

/**
 * Print the CL messages (from an array) as debug output.
 *
 * @param label associated with the CL messages in the output.
 * @param array containing the CL messages to be printed.
 * @param count number of CL messages in the array.
 */
#define debugCLMessages(label, value, count) \
  debugValues(label, value, sizeof(CLMessage), count)

#endif // __types_debug_H
