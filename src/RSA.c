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

#include "debug.h"
#include "memory.h"
#include "arithmetic.h"
#include "random.h"
#include "SHA.h"

/**
 * Mask generation function.
 * 
 * @param seed_bytes actual size of the seed.
 * @param seed buffer containing the seed and space for 4 additional bytes.
 * @param mask_bytes size of the mask to be generated.
 * @param mask buffer to store the generated mask.
 */
static void MGF1(unsigned int seed_bytes, unsigned char *seed, unsigned int mask_bytes, unsigned char *mask) {
  unsigned int i = 0, n = (mask_bytes + RSA_SHA_BYTES - 1) / RSA_SHA_BYTES;
  unsigned char hash[RSA_SHA_BYTES];

  while (i < n - 1 /* exclude the last block */) {
    // Prepare hash data
    Copy(sizeof(unsigned int), seed + seed_bytes + (4 - sizeof(unsigned int)), (unsigned char *) &i);

    // Compute hash
    SHA(RSA_SHA_BYTES, hash, seed_bytes + 4, seed);

	// Append hash to mask
	Copy(RSA_SHA_BYTES, mask + i * RSA_SHA_BYTES, hash);
	
	// Next block
	++i;
  }
  
  // Prepare hash data
  Copy(sizeof(unsigned int), seed + seed_bytes + (4 - sizeof(unsigned int)), (unsigned char *) &i);

  // Compute hash
  SHA(RSA_SHA_BYTES, hash, seed_bytes + 4, seed);

  // Append hash to mask
  CopyBytes(mask_bytes - i * RSA_SHA_BYTES, mask + i * RSA_SHA_BYTES, hash);
}

int OAEP_encode(unsigned char *em, unsigned int m_bytes, const unsigned char *m, unsigned int l_bytes, const unsigned char *l) {
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1 /* Add MGF1 buffer space */ + 4];
  unsigned char seed[RSA_SHA_BYTES /* Add MGF1 buffer space */ + 4];

  // Construct DB
  debugValue("OAEP encode: label", l, l_bytes);
  SHA(RSA_SHA_BYTES, DB, l_bytes, l);
  debugValue("OAEP encode: hash of label", DB, RSA_SHA_BYTES);
  DB[RSA_MOD_BYTES - RSA_SHA_BYTES - m_bytes - 2] = 0x01;
  debugValue("OAEP encode: message", m, m_bytes);
  CopyBytes(m_bytes, DB + RSA_MOD_BYTES - RSA_SHA_BYTES - m_bytes - 1, m);
  debugValue("OAEP encode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Make a random seed
  RandomBytes(seed, RSA_SHA_BYTES);
  debugValue("OAEP encode: seed", seed, RSA_SHA_BYTES);

  // Construct maskedDB and maskedSeed
  MGF1(RSA_SHA_BYTES, seed, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, em + 1 + RSA_SHA_BYTES);
  debugValue("OAEP encode: dbMask", em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, em + 1 + RSA_SHA_BYTES);
  debugValue("OAEP encode: maskedDB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  MGF1(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, RSA_SHA_BYTES, em + 1);
  debugValue("OAEP encode: seedMask", em + 1, RSA_SHA_BYTES);

  XorAssign(RSA_SHA_BYTES, seed, em + 1);
  debugValue("OAEP encode: maskedSeed", em + 1, RSA_SHA_BYTES);

  Copy(RSA_SHA_BYTES, em + 1, seed);
  Copy(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, em + 1 + RSA_SHA_BYTES, DB);
  debugValue("OAEP encode: Encoded Message em", em, RSA_MOD_BYTES);
  
  return RSA_MOD_BYTES;
}

int OAEP_decode(unsigned char *m, unsigned int em_bytes, const unsigned char *em, unsigned int l_bytes, const unsigned char *l) {
  unsigned int i, m_bytes;
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1 /* Add MGF1 buffer space */ + 4];
  unsigned char seed[RSA_SHA_BYTES /* Add MGF1 buffer space */ + 4];

  debugValue("OAEP decode: Encoded Message em", em, em_bytes);

  // First byte of encoded message must be 0x00
  if(em[0] != 0x00) {
	debugError("First byte of OAEP encoded message is not 0x00");
    return RSA_ERROR_OAEP_DECODE;
  }

  // Extract maskedDB and maskedSeed
  debugValue("OAEP decode: maskedSeed", em + 1, RSA_SHA_BYTES);
  Copy(RSA_SHA_BYTES, DB, em + 1 + RSA_SHA_BYTES);
  debugValue("OAEP decode: maskedDB", em + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Finding seed and DB
  MGF1(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, RSA_SHA_BYTES, seed);
  debugValue("OAEP decode: seedMask", seed, RSA_SHA_BYTES);

  XorAssign(RSA_SHA_BYTES, seed, em + 1);
  debugValue("OAEP decode: seed", seed, RSA_SHA_BYTES);

  MGF1(RSA_SHA_BYTES, seed, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB);
  debugValue("OAEP decode: dbMask", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, em + 1 + RSA_SHA_BYTES);
  debugValue("OAEP decode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Compute the hash of l
  debugValue("OAEP decode: label", l, l_bytes);
  SHA(RSA_SHA_BYTES, seed, l_bytes, l);
  debugValue("OAEP decode: hash of label", seed, RSA_SHA_BYTES);

  // Check whether the first RSA_SHA_BYTES bytes of DB equal to lHash
  if (NotEqual(RSA_SHA_BYTES, seed, DB)) {
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
  CopyBytes(m_bytes, m, DB + i + 1);
  debugValue("OAEP decode: plaintext", m, m_bytes);

  return m_bytes;
}

int PSS_encode(unsigned char *em, unsigned int m_bytes, const unsigned char *m) {
  unsigned char M[8 + RSA_SHA_BYTES + RSA_SALT_BYTES];
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1];

  // Compute the hash of m
  debugValue("PSS encode: message", m, m_bytes);
  SHA(RSA_SHA_BYTES, M + 8, m_bytes, m);
  debugValue("PSS encode: hashed message", M + 8, RSA_SHA_BYTES);

  // Generate the salt and construct M
  RandomBytes(M + 8 + RSA_SHA_BYTES, RSA_SALT_BYTES);
  debugValue("PSS encode: salt", M + 8 + RSA_SHA_BYTES, RSA_SALT_BYTES);
  debugValue("PSS encode: message to be encoded", M, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES);

  // Construct DB
  DB[RSA_MOD_BYTES - RSA_SALT_BYTES - RSA_SHA_BYTES - 2] = 0x01;
  Copy(RSA_SALT_BYTES, DB + RSA_MOD_BYTES - RSA_SALT_BYTES - RSA_SHA_BYTES - 1, M + 8 + RSA_SHA_BYTES);
  debugValue("PSS encode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Compute maskedDB
  SHA(RSA_SHA_BYTES, em + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES, M);
  debugValue("PSS encode: hash of message to be encoded", em + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, RSA_SHA_BYTES);

  Copy(RSA_SHA_BYTES, M, em + RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  MGF1(RSA_SHA_BYTES, M, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, em);
  debugValue("PSS encode: dbMask", em, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, em);
  debugValue("PSS encode: maskedDB", em, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Construct the encoded message
  Copy(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, em, DB);
  em[RSA_MOD_BYTES - 1] = 0xbc;
  debugValue("PSS encode: encoded message", em, RSA_MOD_BYTES);
  
  return RSA_MOD_BYTES;
}

int PSS_verify(unsigned int m_bytes, const unsigned char *m, unsigned int em_bytes, const unsigned char *em) {
  unsigned char M[8 + RSA_SHA_BYTES + RSA_SALT_BYTES];
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1];

  debugValue("PSS verify: message", m, m_bytes);

  if (em_bytes != RSA_MOD_BYTES) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }
  debugValue("PSS verify: encoded message", em, em_bytes);

  // Verification
  if (em[RSA_MOD_BYTES - 1] != 0xbc) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }

  // Extract maskedDB and H
  debugValue("PSS verify: maskedDB", em, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  Copy(RSA_SHA_BYTES, M + 8, em + RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  debugValue("PSS verify: H", em + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, RSA_SHA_BYTES);

  // Compute DB
  MGF1(RSA_SHA_BYTES, M + 8, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB);
  debugValue("PSS verify: dbMask", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, em);
  debugValue("PSS verify: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  if (DB[RSA_MOD_BYTES - RSA_SALT_BYTES - RSA_SHA_BYTES - 2] != 0x01) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }

  // Compute hash of m
  SHA(RSA_SHA_BYTES, M + 8, m_bytes, m);
  debugValue("PSS verify: hash of message", M + 8, RSA_SHA_BYTES);

  Copy(RSA_SALT_BYTES, M + 8 + RSA_SHA_BYTES, DB + RSA_MOD_BYTES - RSA_SALT_BYTES - RSA_SHA_BYTES - 1);
  debugValue("PSS verify: recovered message to be encoded", M, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES);

  SHA(RSA_SHA_BYTES, DB, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES, M);
  debugValue("PSS verify: hash of recovered message to be encoded", DB, RSA_SHA_BYTES);

  if (NotEqual(RSA_SHA_BYTES, em + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB)) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }

  return RSA_PSS_CONSISTENT;
}

int RSA_RAW_encrypt(unsigned char *ciphertext, const RSA_public_key *key, 
        unsigned int plaintext_bytes, const unsigned char *plaintext) {

  if (plaintext_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of plaintext");
    return RSA_ERROR_ENCRYPTION;
  }

  ModExp(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, plaintext, ciphertext);
  
  return RSA_MOD_BYTES;
}

int RSA_RAW_decrypt(unsigned char *plaintext, const RSA_private_key *key, 
        unsigned int ciphertext_bytes, const unsigned char *ciphertext) {
  
  if (ciphertext_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of ciphertext");
    return RSA_ERROR_DECRYPTION;
  }
  
  ModExpSecure(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, ciphertext, plaintext);
  
  return RSA_MOD_BYTES;
}

int RSA_OAEP_encrypt(unsigned char *ciphertext, const RSA_public_key *key, 
        unsigned int plaintext_bytes, const unsigned char *plaintext, 
        unsigned int label_bytes, const unsigned char *label) {
  debugValue("RSA_OAEP encrypt: label", label, label_bytes);
  debugValue("RSA_OAEP encrypt: plaintext", plaintext, plaintext_bytes);

  // Encode the message
  OAEP_encode(ciphertext, plaintext_bytes, plaintext, label_bytes, label);
  debugValue("RSA_OAEP encrypt: OAEP-encoded message", ciphertext, RSA_MOD_BYTES);

  // Encrypt the encoded message
  RSA_RAW_encrypt(ciphertext, key, RSA_MOD_BYTES, ciphertext);
  debugValue("RSA_OAEP encrypt: ciphertext", ciphertext, RSA_MOD_BYTES);
  
  return RSA_MOD_BYTES;
}

int RSA_OAEP_decrypt(unsigned char *plaintext, const RSA_private_key *key, 
        unsigned int ciphertext_bytes, unsigned char *ciphertext, 
        unsigned int label_bytes, const unsigned char *label) {
  int plaintext_bytes;
  
  debugValue("RSA_OAEP decrypt: label", label, label_bytes);
  debugValue("RSA_OAEP decrypt: ciphertext", ciphertext, ciphertext_bytes);

  // Decrypt the encoded message
  RSA_RAW_decrypt(ciphertext, key, RSA_MOD_BYTES, ciphertext);
  debugValue("RSA_OAEP decrypt: OAEP-encoded message", ciphertext, RSA_MOD_BYTES);

  // Decode the message
  plaintext_bytes = OAEP_decode(plaintext, RSA_MOD_BYTES, ciphertext, label_bytes, label);
  if (plaintext_bytes < 0) {
    debugError("RSA_OAEP decrypt: Failed to decode the message");
  } else {  
	debugValue("RSA_OAEP decrypt: plaintext", plaintext, ciphertext_bytes);
  }
  
  return plaintext_bytes;
}

int RSA_PSS_sign(const RSA_private_key *key, unsigned char *signature, unsigned int message_bytes, const unsigned char *message) {
  int signature_bytes;

  debugValue("RSA_PSS sign: message", message, message_bytes);

  // Encode the message
  signature_bytes = PSS_encode(signature, message_bytes, message);
  debugValue("RSA_PSS sign: PSS-encoded message", signature, signature_bytes);

  // Sign the encoded message
  signature_bytes = RSA_RAW_sign(signature, key, RSA_MOD_BYTES, signature);
  if (signature_bytes < 0) {
    debugError("RSA_PSS sign: Failed to sign the message");
  } else {
	debugValue("RSA_PSS sign: signature", signature, RSA_MOD_BYTES);
  }
  
  return signature_bytes;
}

int RSA_PSS_verify(const RSA_public_key *key, unsigned int message_bytes, const unsigned char *message, unsigned int signature_bytes, unsigned char *signature) {
  int verify_bytes;

  debugValue("RSA_PSS verify: signature", signature, signature_bytes);

  // Extract the encoded message
  verify_bytes = RSA_RAW_verify(signature, key, signature_bytes, signature);
  if (verify_bytes < 0) {
    debugError("RSA_PSS verify: Failed to verify the message");
  } else {
    debugValue("RSA_PSS verify: PSS-encoded message", signature, verify_bytes);

    // Verify the encoded message
	verify_bytes = PSS_verify(message_bytes, message, verify_bytes, signature);
  }
  
  return verify_bytes;
}
