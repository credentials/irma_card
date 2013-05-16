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

unsigned char *authentication_verifyCertificate(RSA_public_key *key, unsigned char *cert) {
  TLV tlv;
  unsigned char *body, *signature;
  int body_bytes, signature_bytes;
  unsigned int offset = 0;

  ASN1_decode_tlv(&tlv, cert, &offset);
  if (tlv.tag != 0x7F21) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  body = tlv.value;
  offset = tlv.value - cert;

  ASN1_decode_tlv(&tlv, cert, &offset);
  if (tlv.tag != 0x7F4E) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  body_bytes = cert + offset - body;

  ASN1_decode_tlv(&tlv, cert, &offset);
  if (tlv.tag != 0x5F37) {
	  APDU_ReturnSW(SW_WRONG_DATA);
  }
  signature_bytes = tlv.length;
  signature = tlv.value;

  if (RSA_PSS_verify(key, body_bytes, body, signature_bytes, signature) < 0) {
    APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  return body;
}

void authentication_parseCertificate(unsigned char *cert) {
  unsigned int offset = 0;

}

void authentication_generateChallenge(RSA_public_key *key, unsigned char *nonce, unsigned char *challenge) {
  RandomBytes(nonce, AUTH_CHALLENGE_BYTES);
  RSA_OAEP_encrypt(challenge, key, AUTH_CHALLENGE_BYTES, nonce, 0, NULL);
}

void authentication_authenticateTerminal(unsigned char *response, unsigned char *nonce) {
  if (NotEqual(AUTH_CHALLENGE_BYTES, response, nonce)) {
    APDU_ReturnSW(SW_WRONG_DATA);
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
