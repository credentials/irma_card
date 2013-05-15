/**
 * authentication.c
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

#include "authentication.h"

#include "APDU.h"
#include "encoding.h"
#include "externals.h"
#include "debug.h"
#include "memory.h"
#include "random.h"
#include "SHA.h"
#include "RSA.h"

void authentication_verifyCertificate(RSA_public_key *key, unsigned char *cert) {
  const unsigned char *body;
  unsigned char *signature;
  int body_bytes, signature_bytes;
  unsigned int offset = 0;

  if (cert[offset++] != 0x7F || cert[offset++] != 0x21) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  asn1_decode_length(cert, &offset);
  body = cert + offset;
  if (cert[offset++] != 0x7F || cert[offset++] != 0x4E) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  body_bytes = asn1_decode_length(cert, &offset);
  if (body_bytes < 0) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  offset += body_bytes;
  body_bytes = cert + offset - body;

  if (cert[offset++] != 0x5F || cert[offset++] != 0x37) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  signature_bytes = asn1_decode_length(cert, &offset);
  signature = cert + offset;

  if (RSA_PSS_verify(key, body_bytes, body, signature_bytes, signature) < 0) {
	APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }
}

/**
 * Derive session key from a given key seed and mode
 *
 * @param key to be stored
 * @param mode for which a key needs to be derived
 */
#define seed public.apdu.data
void deriveSessionKey(ByteArray key, Byte mode) {
  int i, j, bits;

  // Derive the session key for mode
  seed[SIZE_KEY_SEED + 3] = mode;
  SHA(SHA_1, key, SIZE_KEY_SEED + 4, seed);

  // Compute the parity bits
  for (i = 0; i < SIZE_KEY; i++) {
    for (j = 0, bits = 0; j < 8; j++) {
      bits += (key[i] >> j) & 0x01;
    }
    if (bits % 2 == 0) {
      key[i] ^= 0x01;
    }
  }
}
#undef seed

/**
 * Derive session keys from a given key seed
 */
#define seed public.apdu.data
void deriveSessionKeys(void) {
  // Clear the seed suffix such that we can add a mode specific part
  Clear(4, seed + SIZE_KEY_SEED);

  // Derive the session key for encryption
  deriveSessionKey(seed + SIZE_KEY_SEED + 4, 0x01);
  Copy(SIZE_KEY, key_enc, seed + SIZE_KEY_SEED + 4);
  Copy(4, ssc, seed + SIZE_KEY_SEED + 4 + SIZE_KEY);

  // Derive the session key for authentication
  deriveSessionKey(seed + SIZE_KEY_SEED + 4, 0x02);
  Copy(SIZE_KEY, key_mac, seed + SIZE_KEY_SEED + 4);
  Copy(4, ssc + 4, seed + SIZE_KEY_SEED + 4 + SIZE_KEY);
}
#undef seed
