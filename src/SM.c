/**
 * SM.c
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

#include "SM.h"

#include "APDU.h"
#include "debug.h"
#include "math.h"
#include "memory.h"

// Secure messaging: initialisation vector
unsigned char SM_IV[SM_IV_BYTES];

/********************************************************************/
/* Secure Messaging functions                                       */
/********************************************************************/

/**
 * Unwrap a command APDU from secure messaging
 */
void SM_APDU_unwrap(unsigned char *apdu, unsigned char *buffer, SM_parameters *params) {
  unsigned char mac[SM_MAC_BYTES];
  int i;
  unsigned int offset = 0;
  unsigned int do87DataLen = 0;
  unsigned int do87Data_p = 0;
  unsigned int do87LenBytes = 0;

  IncrementBytes(SM_SSC_BYTES, params->ssc);

  if (apdu[offset] == 0x87) { // do87
    if (apdu[++offset] > 0x80) {
      do87LenBytes = apdu[offset++] & 0x7f;
    } else {
      do87LenBytes = 1;
    }

    for (i = 0; i < do87LenBytes; i++) {
      do87DataLen += apdu[offset + i] << (do87LenBytes - 1 - i) * 8;
    }
    offset += do87LenBytes;

    if (apdu[offset++] != 0x01) APDU_ReturnSW(SW_WRONG_DATA);
    do87DataLen--; // compensate for 0x01 marker

    // store pointer to data and defer decrypt to after mac check (do8e)
    do87Data_p = offset;
    offset += do87DataLen;
  }

  if (apdu[offset] == 0x97) { // do97
    if (apdu[++offset] != 0x01) APDU_ReturnSW(SW_WRONG_DATA);
    Le = apdu[++offset];
    offset++;
  }

  // do8e
  if (apdu[offset] != 0x8e) APDU_ReturnSW(SW_WRONG_DATA);
  if (apdu[offset + 1] != 8) APDU_ReturnSW(SW_DATA_INVALID);

  // verify mac
  i = 0;

  // SSC
  Copy(SM_SSC_BYTES, buffer, params->ssc);
  i += SM_SSC_BYTES;

  // Header
  buffer[i++] = CLA;
  buffer[i++] = INS;
  buffer[i++] = P1;
  buffer[i++] = P2;

  // Padding
  i = SM_ISO7816_4_pad(apdu, i);

  // Cryptogram (do87 and do97)
  CopyBytes(offset, buffer + i, apdu);
  do87Data_p += i;
  i += offset;

  // Padding
  i = SM_ISO7816_4_pad(buffer, i);

  // Verify the MAC
  SM_CBC_sign(i, SM_IV, params->key_mac, mac, buffer);
  if (NotEqual(SM_MAC_BYTES, mac, apdu + offset + 2)) {
    APDU_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
  }

  // Decrypt data if available
  if (do87DataLen != 0) {
    SM_CBC_decrypt(do87DataLen, buffer + do87Data_p, apdu, SM_IV, SM_KEY_BYTES, params->key_enc);
    i = SM_ISO7816_4_unpad(apdu, do87DataLen);
    if (i < 0) {
      APDU_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
	} else {
      Lc = i;
	}
  }
}

/**
 * Wrap a response APDU for secure messaging
 */
void SM_APDU_wrap(unsigned char *apdu, unsigned char *buffer, SM_parameters *params) {
  unsigned int offset = 0, do87DataLen = __La + 1;
  unsigned char do87DataLenBytes = __La > 0xff ? 2 : 1;
  int i;

  IncrementBytes(SM_SSC_BYTES, params->ssc);

  if(__La > 0) {
    // Padding
    __La = SM_ISO7816_4_pad(apdu, __La);

    // Build do87 header
    buffer[offset++] = 0x87;
    if(do87DataLen < 0x0080) {
      buffer[offset++] = do87DataLen;
    } else {
      buffer[offset++] = 0x0080 + do87DataLenBytes;
      for(i = do87DataLenBytes - 1; i >= 0; i--) {
        buffer[offset++] = do87DataLen >> (i * 8);
      }
    }
    buffer[offset++] = 0x01;

    // Build the do87 data
    SM_CBC_encrypt(__La, apdu, buffer + offset, SM_IV, SM_KEY_BYTES, params->key_enc);
    offset += __La;
  }

  // build do99
  buffer[offset++] = 0x99;
  buffer[offset++] = 0x02;
  buffer[offset++] = __SW >> 8;
  buffer[offset++] = __SW;

  // padding
  i = SM_ISO7816_4_pad(buffer, offset);

  // calculate and write mac
  Copy(SM_SSC_BYTES, buffer - SM_SSC_BYTES, params->ssc);
  SM_CBC_sign(i + SM_SSC_BYTES, SM_IV, params->key_mac, apdu + offset + 2, buffer - SM_SSC_BYTES);

  // write do8e
  buffer[offset++] = 0x8e;
  buffer[offset++] = 0x08;
  __La = offset + 8; // for mac written earlier

  // Put it all in the apdu (the mac is already there)
  CopyBytes(offset, apdu, buffer);
}

/**
 * Add padding to the input data according to ISO7816-4
 *
 * @param data that needs to be padded
 * @param length of the data that needs to be padded
 * @return the new size of the data including padding
 */
unsigned int SM_ISO7816_4_pad(unsigned char *data, unsigned int length) {
  data[length++] = 0x80;
  while (length % 8 != 0) {
    data[length++] = 0x00;
  }
  return length;
}

/**
 * Remove padding from the input data according to ISO7816-4
 *
 * @param data that contains padding
 * @param length of the data including padding
 * @return the new size of the data excluding padding
 */
int SM_ISO7816_4_unpad(unsigned char *data, unsigned int length) {
  while (length > 0 && data[--length] == 0x00);
  if (data[length] != 0x80) {
    debugError("SM_unpad: Invalid padding");
    return SM_ERROR_ISO7816_4_PADDING_INVALID;
  }
  return length;
}

/**
 * Derive session key from a given key seed and mode
 *
 * @param key to be stored
 * @param mode for which a key needs to be derived
 */
void SM_session_key(unsigned int seed_bytes, unsigned char *seed, unsigned char *key, unsigned char mode) {
  int i, j, bits;

  // Derive the session key for mode
  seed[seed_bytes + 0] = 0x00;
  seed[seed_bytes + 1] = 0x00;
  seed[seed_bytes + 2] = 0x00;
  seed[seed_bytes + 3] = mode;
  SHA(SM_SHA_BYTES, key, seed_bytes + 4, seed);

#ifdef SM_DES
  // Compute the parity bits
  for (i = 0; i < SM_KEY_BYTES; i++) {
    for (j = 0, bits = 0; j < 8; j++) {
      bits += (key[i] >> j) & 0x01;
    }
    if (bits % 2 == 0) {
      key[i] ^= 0x01;
    }
  }
#endif // SM_DES
}

/**
 * Derive session keys from a given key seed
 */
void SM_setup(unsigned int seed_bytes, unsigned char *seed, SM_parameters *params) {
  unsigned char key_tmp[SM_SHA_BYTES];

  // Derive the session key for encryption
  SM_session_key(seed_bytes, seed, key_tmp, 0x01);
  Copy(SM_KEY_BYTES, params->key_enc, key_tmp);
  Copy(4, params->ssc, key_tmp + SM_KEY_BYTES);

  // Derive the session key for authentication
  SM_session_key(seed_bytes, seed, key_tmp, 0x02);
  Copy(SM_KEY_BYTES, params->key_mac, key_tmp);
  Copy(4, params->ssc + 4, key_tmp + SM_KEY_BYTES);
}
