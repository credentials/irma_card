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

#include "APDU.h"

#include "SM.config.h"

#ifndef SM_CBC_sign
  #error "SM_CBC_sign not defined"
#endif // !SM_CBC_sign

#ifndef SM_CBC_decrypt
  #error "SM_CBC_decrypt not defined"
#endif // !SM_CBC_decrypt

#ifndef SM_CBC_encrypt
  #error "SM_CBC_encrypt not defined"
#endif // !SM_CBC_encrypt

#ifndef SM_KEY_BITS
  #error "SM_KEY_BITS not defined"
#endif // !SM_KEY_BITS

#ifndef SM_IV_BITS
  #error "SM_IV_BITS not defined"
#endif // !SM_IV_BITS

#ifndef SM_MAC_BITS
  #error "SM_MAC_BITS not defined"
#endif // !SM_MAC_BITS

#ifndef SM_SHA_BITS
  #error "SM_SHA_BITS not defined"
#endif // !SM_SHA_BITS

#ifndef SM_SSC_BITS
  #error "SM_SSC_BITS not defined"
#endif // !SM_SSC_BITS

#define SM_BITS_TO_BYTES(bits) ((bits + 7) / 8)

#define SM_IV_BYTES SM_BITS_TO_BYTES(SM_IV_BITS)
#define SM_KEY_BYTES SM_BITS_TO_BYTES(SM_KEY_BITS)
#define SM_MAC_BYTES SM_BITS_TO_BYTES(SM_MAC_BITS)
#define SM_SHA_BYTES SM_BITS_TO_BYTES(SM_SHA_BITS)
#define SM_SSC_BYTES SM_BITS_TO_BYTES(SM_SSC_BITS)

typedef struct {
  unsigned char ssc[SM_SSC_BYTES];
  unsigned char key_enc[SM_KEY_BYTES];
  unsigned char key_mac[SM_KEY_BYTES];
} SM_parameters;

/**
 * Unwrap an incomming command APDU from secure messaging
 */
int SM_APDU_unwrap(unsigned char *apdu, unsigned char *buffer, SM_parameters *params);

/**
 * Wrap an outgoing response APDU for secure messaging
 */
void SM_APDU_wrap(unsigned char *apdu, unsigned char *buffer, SM_parameters *params);

#define SM_ERROR_WRONG_DATA -1
#define SM_ERROR_MAC_INVALID -2
#define SM_ERROR_PADDING_INVALID -3

/**
 * Add padding to the input data according to ISO7816-4
 *
 * @param data that needs to be padded
 * @param length of the data that needs to be padded
 * @return the new size of the data including padding
 */
unsigned int SM_ISO7816_4_pad(unsigned char *data, unsigned int length);

/**
 * Remove padding from the input data according to ISO7816-4
 *
 * @param data that contains padding
 * @param length of the data including padding
 * @return the new size of the data excluding padding
 */
int SM_ISO7816_4_unpad(unsigned char *data, unsigned int *length);

#define SM_ISO7816_4_ERROR_PADDING_INVALID -1

#define SM_ReturnSW(sw) \
  __SW = (sw); \
  if (APDU_wrapped) { SM_APDU_wrap(public.apdu.data, public.apdu.session, &tunnel); } \
  __code(SYSTEM, 4)

#define SM_ReturnLa(sw, la) \
  __SW = (sw); \
  __La = (la); \
  if (APDU_wrapped) { SM_APDU_wrap(public.apdu.data, public.apdu.session, &tunnel); } \
  __code(SYSTEM, 4)

#define SM_return() \
  SM_APDU_wrap(public.apdu.data, public.apdu.session, &tunnel); \
  __code(SYSTEM, 4);

#endif // __SM_H
