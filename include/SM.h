/**
 * SM.h
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

#ifndef __SM_H
#define __SM_H

/**
 * Unwrap an incomming command APDU from secure messaging
 */
void SM_APDU_unwrap(unsigned char *apdu, unsigned char *buffer, unsigned char *ssc, unsigned char *iv, unsigned char *key_enc, unsigned char *key_mac);

/**
 * Wrap an outgoing response APDU for secure messaging
 */
void SM_APDU_wrap(unsigned char *apdu, unsigned char *buffer, unsigned char *ssc, unsigned char *iv, unsigned char *key_enc, unsigned char *key_mac);

/**
 * Add padding to the input data according to ISO7816-4
 *
 * @param data that needs to be padded
 * @param length of the data that needs to be padded
 * @return the new size of the data including padding
 */
unsigned int SM_ISO7816_4_pad(unsigned char *data, int length);

/**
 * Remove padding from the input data according to ISO7816-4
 *
 * @param data that contains padding
 * @param length of the data including padding
 * @return the new size of the data excluding padding
 */
int SM_ISO7816_4_unpad(unsigned char *data, unsigned int length);

#define SM_ERROR_ISO7816_4_PADDING_INVALID -1

#define SM_ReturnSW(sw) \
  __SW = (sw); \
  if (APDU_wrapped) { SM_wrap(public.apdu.data, public.apdu.session); } \
  __code(SYSTEM, 4)

#define SM_ReturnLa(sw, la) \
  __SW = (sw); \
  __La = (la); h\
  if (APDU_wrapped) { SM_wrap(public.apdu.data, public.apdu.session); } \
  __code(SYSTEM, 4)

#endif // __SM_H
