/**
 * RSA.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, July 2011.
 */

#include "RSA.h"

#include "string.h"

#include "debug.h"
#include "SHA.h"

static void MGF1(ByteArray seed, unsigned int seed_bytes, ByteArray mask, unsigned int mask_bytes) {
  unsigned int i, n = (mask_bytes + RSA_SHA_BYTES - 1) / RSA_SHA_BYTES;
  Byte hash[RSA_SHA_BYTES];
  Byte data[seed_bytes + 4];

  // Initialise the hash data
  memcpy(data, hash, seed_bytes);

  for (i = 0; i < n; i++) {
    // Prepare hash data
    memcpy(seed + seed_bytes, &i, 4);

    // Compute hash
    SHA(RSA_SHA_BYTES, hash, seed_bytes + 4, seed);

	// Append hash to mask
	memcpy(mask + i * RSA_SHA_BYTES, hash,
	  (i == n - 1) ? RSA_SHA_BYTES : mask_bytes - i*RSA_SHA_BYTES);
  }
}

void OAEP_encode(ByteArray em, unsigned int m_bytes, ByteArray m, unsigned int l_bytes, ByteArray l) {
  Byte DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1];
  Byte seed[RSA_SHA_BYTES];

  // Construct DB
  debugValue("OAEP encode: label", l, l_bytes);
  SHA(RSA_SHA_BYTES, DB, l_bytes, l);
  debugValue("OAEP encode: hash of label", DB, RSA_SHA_BYTES);
  DB[RSA_MOD_BYTES - RSA_SHA_BYTES - m_bytes - 2] = 0x01;
  debugValue("OAEP encode: message", m, m_bytes);
  memcpy(DB + RSA_MOD_BYTES - RSA_SHA_BYTES - m_bytes - 1, m, m_bytes);
  debugValue("OAEP encode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Make a random seed
  RandomBytes(seed, RSA_SHA_BYTES);
  debugValue("OAEP encode: seed", seed, RSA_SHA_BYTES);

  // Construct maskedDB and maskedSeed
  MGF1(seed, RSA_SHA_BYTES, em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  debugValue("OAEP encode: dbMask", em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  ASSIGN_XORN(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, em + 1 + RSA_SHA_BYTES, DB);
  debugValue("OAEP encode: maskedDB", em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  MGF1(em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, em + 1, RSA_SHA_BYTES);
  debugValue("OAEP encode: seedMask", em + 1, RSA_SHA_BYTES);

  ASSIGN_XORN(RSA_SHA_BYTES, em + 1, seed);
  debugValue("OAEP encode: maskedSeed", em + 1, RSA_SHA_BYTES);

  debugValue("OAEP encode: Encoded Message em", em, RSA_MOD_BYTES);
}

int OAEP_decode(ByteArray m, ByteArray em, unsigned int l_bytes, ByteArray l) {
  unsigned int i, m_bytes;
  Byte DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1];
  Byte seed[RSA_SHA_BYTES];

  debugValue("OAEP decode: Encoded Message em", em, RSA_MOD_BYTES);

  // First byte of encoded message must be 0x00
  if(em[0] != 0x00) {
	debugError("First byte of OAEP encoded message is not 0x00");
    return RSA_ERROR_OAEP_DECODE;
  }

  // Extract maskedDB and maskedSeed
  debugValue("OAEP decode: maskedSeed", em + 1, RSA_SHA_BYTES);
  debugValue("OAEP decode: maskedDB", em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Finding seed and DB
  MGF1(em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES-RSA_SHA_BYTES-1, seed, RSA_SHA_BYTES);
  debugValue("OAEP decode: seedMask", seed, RSA_SHA_BYTES);

  ASSIGN_XORN(RSA_SHA_BYTES, seed, em + 1);
  debugValue("OAEP decode: seed", seed, RSA_SHA_BYTES);

  MGF1(RSA_SHA_BYTES, seed, RSA_SHA_BYTES, DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  debugValue("OAEP decode: dbMask", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  ASSIGN_XORN(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, em + 1 + RSA_SHA_BYTES);
  debugValue("OAEP decode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Compute the hash of l
  debugValue("OAEP decode: label", l, l_bytes);
  SHA(RSA_SHA_BYTES, em, l_bytes, l);
  debugValue("OAEP decode: hash of label", em, RSA_SHA_BYTES);

  // Check whether the first RSA_SHA_BYTES bytes of DB equal to lHash
  if (memcmp(em, DB, RSA_SHA_BYTES) != 0) {
	debugError("First RSA_SHA_BYTES of DB do not match with hash of label");
    return RSA_ERROR_OAEP_DECODE;
  }

  // Try to locate the message in DB
  i = RSA_SHA_BYTES;
  while ((DB[i] == 0x00) && (DB[i] != 0x01) && (i < (RSA_MOD_BYTES - RSA_SHA_BYTES - 1 - 1))) i++;

  if ((i == (RSA_MOD_BYTES - RSA_SHA_BYTES - 1 - 1)) || (DB[i] != 0x01)) {
	debugError("Failed to locate the message in DB");
    return RSA_ERROR_OAEP_DECODE;
  }

  // Extract the message, starting after 0x01 byte to the end of DB
  m_bytes = RSA_MOD_BYTES - RSA_SHA_BYTES - 1 - 1 - (i + 1) + 1;
  memcpy(m, DB + i + 1, m_bytes);
  debugValue("OAEP decode: plaintext", m, m_bytes);

  return m_bytes;
}

int PSS_encode(unsigned int m_bytes, ByteArray m, unsigned int em_bytes, ByteArray em, unsigned int salt_bytes) {
  Byte H[RSA_SHA_BYTES];
  Byte salt[s_bytes];
  Byte M[8 + RSA_SHA_BYTES + s_bytes];
  Byte DB[em_bytes - RSA_SHA_BYTES - 1];
  Byte maskedDB[em_bytes - RSA_SHA_BYTES - 1];

  // Compute the hash of m
  debugValue("PSS encode: message", m, m_bytes);
  SHA(RSA_SHA_BYTES, H, m_bytes, m);
  debugValue("PSS encode: hashed message", H, RSA_SHA_BYTES);

  // Generate the salt and construct M
  RandomBytes(salt, s_bytes);
  debugValue("PSS encode: salt", salt, s_bytes);

  memcpy(M + 8, H, RSA_SHA_BYTES);
  memcpy(M + 8 + RSA_SHA_BYTES, salt, s_bytes);
  debugValue("PSS encode: message to be encoded", M, 8 + RSA_SHA_BYTES + s_bytes);

  // Construct DB
  SHA(RSA_SHA_BYTES, H, 8 + RSA_SHA_BYTES + s_bytes, M);
  debugValue("PSS encode: hash of message to be encoded", H, RSA_SHA_BYTES);

  DB[em_bytes - s_bytes - RSA_SHA_BYTES - 2] = 0x01;
  memcpy(DB + em_bytes - s_bytes - RSA_SHA_BYTES - 1, salt, s_bytes);
  debugValue("PSS encode: DB", DB, em_bytes - RSA_SHA_BYTES - 1);

  // Compute maskedDB
  MGF1(RSA_SHA_BYTES, H, RSA_SHA_BYTES, maskedDB, em_bytes - RSA_SHA_BYTES - 1);
  debugValue("PSS encode: dbMask", maskedDB, em_bytes - RSA_SHA_BYTES - 1);

  XORN(em_bytes - RSA_SHA_BYTES - 1, maskedDB, DB);
  debugValue("PSS encode: maskedDB", maskedDB, em_bytes - RSA_SHA_BYTES - 1);

  // Construct the encoded message
  memcpy(em, maskedDB, em_bytes - RSA_SHA_BYTES - 1);
  memcpy(em + em_bytes - RSA_SHA_BYTES - 1, H, RSA_SHA_BYTES);
  em[em_bytes - 1] = 0xbc;
  debugValue("PSS encode: encoded message", em, em_bytes);
}

int PSS_verify(unsigned int RSA_SHA_BYTES, ByteArray m, unsigned int m_bytes, unsigned int s_bytes, ByteArray em, unsigned int em_bytes) {
  Byte H[RSA_SHA_BYTES];
  Byte M[8 + RSA_SHA_BYTES + s_bytes];
  Byte mHash[RSA_SHA_BYTES];
  Byte DB[em_bytes - RSA_SHA_BYTES - 1];
  Byte maskedDB[em_bytes - RSA_SHA_BYTES - 1];

  debugValue("PSS verify: message", m, m_bytes);

  // Compute hash of m
  SHA(RSA_SHA_BYTES, mHash, m_bytes, m);
  debugValue("PSS verify: hash of message", mHash, RSA_SHA_BYTES);

  debugValue("PSS verify: encoded message", em, em_bytes);

  // Verification
  if (em[em_bytes - 1] != 0xbc) {
    return ERR_PSS_INCONSISTENT;
  }

  // Extract maskedDB and H
  memcpy(maskedDB, em, em_bytes-RSA_SHA_BYTES-1);
  debugValue("PSS verify: maskedDB", maskedDB, em_bytes - RSA_SHA_BYTES - 1);

  memcpy(H, em + em_bytes - RSA_SHA_BYTES - 1, RSA_SHA_BYTES);
  debugValue("PSS verify: H", H, RSA_SHA_BYTES);

  // Compute DB
  MGF1(RSA_SHA_BYTES, H, RSA_SHA_BYTES, DB, em_bytes - RSA_SHA_BYTES - 1);
  debugValue("PSS verify: dbMask", DB, em_bytes - RSA_SHA_BYTES - 1);

  XORN(em_bytes - RSA_SHA_BYTES - 1, DB, maskedDB);
  debugValue("PSS verify: DB", DB, em_bytes - RSA_SHA_BYTES - 1);

  if (DB[em_bytes - s_bytes - RSA_SHA_BYTES - 2] != 0x01) {
    return ERR_PSS_INCONSISTENT;
  }

  memcpy(M + 8, mHash, RSA_SHA_BYTES);
  memcpy(M + 8 + RSA_SHA_BYTES, DB + em_bytes - s_bytes - RSA_SHA_BYTES - 1, s_bytes);
  debugValue("PSS verify: recovered message to be encoded", M, 8 + RSA_SHA_BYTES + s_bytes);

  SHA(RSA_SHA_BYTES, mHash, 8 + RSA_SHA_BYTES + s_bytes, M);
  debugValue("PSS verify: hash of recovered message to be encoded", mHash, RSA_SHA_BYTES);

  if (memcmp(H, mHash, RSA_SHA_BYTES) != 0) {
    return ERR_PSS_INCONSISTENT;
  }

  return ERR_PSS_CONSISTENT;
}

int RSA_RAW_encrypt(ByteArray ciphertext, RSA_public_key *key, 
        unsigned int plaintext_bytes, ByteArray plaintext) {

  if (plaintext_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of plaintext");
    return RSA_ERROR_ENCRYPTION;
  }

  crypto_modexp(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, plaintext, ciphertext);
  
  return RSA_MOD_BYTES;
}

int RSA_RAW_decrypt(ByteArray plaintext, RSA_private_key *key, 
        unsigned int ciphertext_bytes, ByteArray ciphertext) {
  
  if (ciphertext_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of ciphertext");
    return RSA_ERROR_DECRYPTION;
  }
  
  crypto_modexp_secure(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, ciphertext, plaintext);
  
  return RSA_MOD_BYTES;
}

void RSA_OAEP_encrypt(ByteArray ciphertext, RSA_public_key *key, 
        unsigned int plaintext_bytes, ByteArray plaintext, 
        unsigned int label_bytes, ByteArray label) {
  debugValue("RSA_OAEP encrypt: label", label, label_bytes);
  debugValue("RSA_OAEP encrypt: plaintext", plaintext, plaintext_bytes);

  // Encode the message
  OAEP_encode(ciphertext, plaintext_bytes, plaintext, label_bytes, label);
  debugValue("RSA_OAEP encrypt: OAEP-encoded message", ciphertext, RSA_MOD_BYTES);

  // Encrypt the encoded message
  RSA_RAW_encrypt(ciphertext, key, RSA_MOD_BYTES, ciphertext);
  debugValue("RSA_OAEP encrypt: ciphertext", ciphertext, RSA_MOD_BYTES);
}

int RSA_OAEP_decrypt(ByteArray plaintext, RSA_private_key *key, 
        unsigned int ciphertext_bytes, ByteArray ciphertext, 
        unsigned int label_bytes, ByteArray label) {
  debugValue("RSA_OAEP decrypt: label", label, label_bytes);
  debugValue("RSA_OAEP decrypt: ciphertext", ciphertext, ciphertext_bytes);

  // Decrypt the encoded message
  RSA_RAW_decrypt(ciphertext, key, RSA_MOD_BYTES, ciphertext);
  debugValue("RSA_OAEP decrypt: OAEP-encoded message", c, RSA_MOD_BYTES);

  // Decode the message
  if ((ciphertext_bytes = OAEP_decode(plaintext, ciphertext, label_bytes, label)) < 0) {
    debugError("RSA_OAEP decrypt: Failed to decode the message");
  } else {  
	debugValue("RSA_OAEP decrypt: plaintext", m, m_bytes);
  }
  
  return ciphertext_bytes;
}

int RSA_PSS_sign(RSA_private_key *key, ByteArray signature, unsigned int message_bytes, ByteArray message, unsigned int salt_bytes) {
  debugValue("RSA_PSS sign: message", message, message_bytes);

  // Encode the message
  PSS_encode(RSA_SHA_BYTES, message, message_bytes, salt_bytes, signature, RSA_MOD_BYTES);
  debugValue("RSA_PSS sign: PSS-encoded message", signature, RSA_MOD_BYTES);

  // Sign the encoded message
  RSA_RAW_sign(signature, key, RSA_MOD_BYTES, signature);
  debugValue("RSA_PSS sign: signature", signature, RSA_MOD_BYTES);
  
  return RSA_MOD_BYTES;
}

int RSA_PSS_verify(RSA_public_key *pk, unsigned int RSA_SHA_BYTES, ByteArray m, unsigned int m_bytes, unsigned int s_bytes, ByteArray s) {
  debugValue("RSA_PSS verify: signature", s, RSA_MOD_BYTES);

  // Extract the encoded message
  RSA_RAW_verify(s, pk, RSA_MOD_BYTES, s);
  debug("RSA_PSS verify: PSS-encoded message", s, RSA_MOD_BYTES);

  // Verify the encoded message
  return PSS_verify(RSA_SHA_BYTES, m, m_bytes, s_bytes, s, RSA_MOD_BYTES);
}
