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

/* PKCS #1 OAEP encoding */
static int OAEP_encode(unsigned char *encoded,
        unsigned int message_bytes, const unsigned char *message,
        unsigned int label_bytes, const unsigned char *label);

/* PKCS #1 OAEP decoding */
static int OAEP_decode(unsigned char *message,
        unsigned int encoded_bytes, const unsigned char *encoded,
        unsigned int label_bytes, const unsigned char *label);

/* PKCS #1 PSS encoding */
static int PSS_encode(unsigned char *encoded,
    unsigned int message_bytes, const unsigned char *message);

/* PKCS #1 PSS verification */
static int PSS_verify(unsigned int message_bytes, const unsigned char *message,
    unsigned int encoded_bytes, const unsigned char *encoded);

/* PKCS #1 Mask generation function 1 */
static void MGF1(unsigned int seed_bytes, unsigned char *seed, 
        unsigned int mask_bytes, unsigned char *mask);

////////////////////////////////////////////////////////////////////////
// RSA encryption scheme                                              //
////////////////////////////////////////////////////////////////////////

/**
 * RSA encryption (as specified by PKCS #1)
 *
 * @param ciphertext produced by this encrypting the plaintext.
 * @param key to be used for this operation.
 * @param plaintext_bytes size in bytes of the plaintext.
 * @param plaintext to be transformed into a ciphertext.
 * @return number of bytes written to ciphertext.
 */
int RSA_RAW_encrypt(unsigned char *ciphertext, const RSA_public_key *key, 
        unsigned int plaintext_bytes, const unsigned char *plaintext) {

  if (plaintext_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of plaintext");
    return RSA_ERROR_RAW_ENCRYPT;
  }

  ModExp(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, plaintext, ciphertext);
  
  return RSA_MOD_BYTES;
}

/**
 * RSA decryption (as specified by PKCS #1)
 *
 * @param plaintext recovered by the decrypting the ciphertext.
 * @param key to be used for this operation.
 * @param ciphertext_bytes size in bytes of the ciphertext.
 * @param ciphertext to be transformed into a plaintext.
 * @return number of bytes written to plaintext.
 */
int RSA_RAW_decrypt(unsigned char *plaintext, const RSA_private_key *key, 
        unsigned int ciphertext_bytes, const unsigned char *ciphertext) {
  
  if (ciphertext_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of ciphertext");
    return RSA_ERROR_RAW_DECRYPT;
  }
  
  ModExpSecure(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, ciphertext, plaintext);
  
  return RSA_MOD_BYTES;
}

/**
 * RSA encryption using OAEP encoding (as specified by PKCS #1)
 * 
 * @param ciphertext produced by this encrypting the plaintext.
 * @param key to be used for this operation.
 * @param label_bytes size in bytes of the label.
 * @param label associated with this text (optional).
 * @param plaintext_bytes size in bytes of the plaintext.
 * @param plaintext to be transformed into a ciphertext.
 * @return number of bytes written to ciphertext.
 */
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

/**
 * RSA decryption using OAEP decoding (as specified by PKCS #1)
 * 
 * Note: the original ciphertext will be overwritten by this function.
 * 
 * @param plaintext recovered by the decrypting the ciphertext.
 * @param key to be used for this operation.
 * @param label_bytes size in bytes of the label.
 * @param label associated with this text (optional).
 * @param ciphertext_bytes size in bytes of the ciphertext.
 * @param ciphertext to be transformed into a plaintext.
 * @return number of bytes written to plaintext.
 */
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

////////////////////////////////////////////////////////////////////////
// RSA signature scheme                                               //
////////////////////////////////////////////////////////////////////////

/**
 * RSA signature generation (as specified by PKCS #1)
 *
 * @param signature produced by signing the message.
 * @param key to be used for this operation.
 * @param message_bytes size in bytes of the message.
 * @param message to be signed.
 * @return number of bytes written to signature.
 */
int RSA_RAW_sign(unsigned char *signature, const RSA_private_key *key, 
        unsigned int message_bytes, const unsigned char *message) {
  
  if (message_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of message");
    return RSA_ERROR_RAW_SIGN;
  }
  
  ModExpSecure(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, message, signature);
  
  return RSA_MOD_BYTES;
}

/**
 * RSA signature verification (as specified by PKCS #1)
 *
 * Note: the signature will be modified/overwritten by this function.
 *
 * @param key to be used for this operation.
 * @param message_bytes size in bytes of the message.
 * @param message that is to be verified.
 * @param signature_bytes size in bytes of the signature.
 * @param signature over the message to be verified.
 * @return whether the message/signature is correct.
 */
int RSA_RAW_verify(const RSA_public_key *key, 
        unsigned int message_bytes, const unsigned char *message, 
        unsigned int signature_bytes, unsigned char *signature) {

  if (signature_bytes != RSA_MOD_BYTES) {
    debugError("Incorrect size of signature");
    return RSA_ERROR_RAW_VERIFY;
  }
  if (message_bytes > signature_bytes) {
    debugError("Incorrect size of message");
    return RSA_ERROR_RAW_VERIFY;
  }
  
  ModExp(RSA_EXP_BYTES, RSA_MOD_BYTES, key->exponent, key->modulus, signature, signature);
  
  if (NotEqual(message_bytes, message, signature + RSA_MOD_BYTES - message_bytes)) {
    return RSA_ERROR_INCONSISTENT;
  }

  return RSA_CONSISTENT;
}

/**
 * RSA signature generation using PSS encoding (as specified by PKCS #1)
 *
 * @param key to be used for this operation.
 * @param signature produced by signing the message.
 * @param message_bytes size in bytes of the message.
 * @param message to be signed.
 * @return number of bytes written to signature.
 */
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

/**
 * RSA signature verification using PSS decoding (as specified by PKCS #1)
 *
 * Note: the signature will be modified/overwritten by this function.
 *
 * @param key to be used for this operation.
 * @param message_bytes size in bytes of the message.
 * @param message that is to be verified.
 * @param signature_bytes size in bytes of the signature.
 * @param signature over the message to be verified.
 * @return whether the message/signature is correct.
 */
int RSA_PSS_verify(const RSA_public_key *key, unsigned int message_bytes, const unsigned char *message, unsigned int signature_bytes, unsigned char *signature) {
  int verify_bytes;

  debugValue("RSA_PSS verify: signature", signature, signature_bytes);

  // Extract the encoded message
  verify_bytes = RSA_RAW_encrypt(signature, key, signature_bytes, signature);
  if (verify_bytes < 0) {
    debugError("RSA_PSS verify: Failed to verify the message");
  } else {
    debugValue("RSA_PSS verify: PSS-encoded message", signature, verify_bytes);

    // Verify the encoded message
    verify_bytes = PSS_verify(message_bytes, message, verify_bytes, signature);
  }
  
  return verify_bytes;
}

////////////////////////////////////////////////////////////////////////
// OAEP encoding scheme                                               //
////////////////////////////////////////////////////////////////////////

/**
 * PKCS #1 OAEP encoding
 */
static int OAEP_encode(unsigned char *encoded, 
        unsigned int message_bytes, const unsigned char *message, 
        unsigned int label_bytes, const unsigned char *label) {
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1 /* Add MGF1 buffer space */ + 4];
  unsigned char seed[RSA_SHA_BYTES /* Add MGF1 buffer space */ + 4];

  // Construct DB
  debugValue("OAEP encode: label", label, label_bytes);
  SHA(RSA_SHA_BYTES, DB, label_bytes, label);
  debugValue("OAEP encode: hash of label", DB, RSA_SHA_BYTES);
  DB[RSA_MOD_BYTES - RSA_SHA_BYTES - message_bytes - 2] = 0x01;
  debugValue("OAEP encode: message", message, message_bytes);
  CopyBytes(message_bytes, DB + RSA_MOD_BYTES - RSA_SHA_BYTES - message_bytes - 1, message);
  debugValue("OAEP encode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Make a random seed
  RandomBytes(seed, RSA_SHA_BYTES);
  debugValue("OAEP encode: seed", seed, RSA_SHA_BYTES);

  // Construct maskedDB and maskedSeed
  MGF1(RSA_SHA_BYTES, seed, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, encoded + 1 + RSA_SHA_BYTES);
  debugValue("OAEP encode: dbMask", encoded + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, encoded + 1 + RSA_SHA_BYTES);
  debugValue("OAEP encode: maskedDB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  MGF1(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, RSA_SHA_BYTES, encoded + 1);
  debugValue("OAEP encode: seedMask", encoded + 1, RSA_SHA_BYTES);

  XorAssign(RSA_SHA_BYTES, seed, encoded + 1);
  debugValue("OAEP encode: maskedSeed", encoded + 1, RSA_SHA_BYTES);

  Copy(RSA_SHA_BYTES, encoded + 1, seed);
  Copy(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, encoded + 1 + RSA_SHA_BYTES, DB);
  debugValue("OAEP encode: encoded message", encoded, RSA_MOD_BYTES);
  
  return RSA_MOD_BYTES;
}

/**
 * PKCS #1 OAEP decoding
 */
static int OAEP_decode(unsigned char *message, 
        unsigned int encoded_bytes, const unsigned char *encoded, 
        unsigned int label_bytes, const unsigned char *label) {
  unsigned int i, message_bytes;
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1 /* Add MGF1 buffer space */ + 4];
  unsigned char seed[RSA_SHA_BYTES /* Add MGF1 buffer space */ + 4];

  debugValue("OAEP decode: encoded message", encoded, encoded_bytes);

  // First byte of encoded message must be 0x00
  if(encoded[0] != 0x00) {
    debugError("First byte of OAEP encoded message is not 0x00");
    return RSA_ERROR_OAEP_DECODE;
  }

  // Extract maskedDB and maskedSeed
  debugValue("OAEP decode: maskedSeed", encoded + 1, RSA_SHA_BYTES);
  Copy(RSA_SHA_BYTES, DB, encoded + 1 + RSA_SHA_BYTES);
  debugValue("OAEP decode: maskedDB", encoded + 1 + RSA_SHA_BYTES, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Finding seed and DB
  MGF1(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, RSA_SHA_BYTES, seed);
  debugValue("OAEP decode: seedMask", seed, RSA_SHA_BYTES);

  XorAssign(RSA_SHA_BYTES, seed, encoded + 1);
  debugValue("OAEP decode: seed", seed, RSA_SHA_BYTES);

  MGF1(RSA_SHA_BYTES, seed, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB);
  debugValue("OAEP decode: dbMask", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, encoded + 1 + RSA_SHA_BYTES);
  debugValue("OAEP decode: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Compute the hash of l
  debugValue("OAEP decode: label", label, label_bytes);
  SHA(RSA_SHA_BYTES, seed, label_bytes, label);
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
  message_bytes = RSA_MOD_BYTES - RSA_SHA_BYTES - 1 - 1 - (i + 1) + 1;
  CopyBytes(message_bytes, message, DB + i + 1);
  debugValue("OAEP decode: recovered message", message, message_bytes);

  return message_bytes;
}

////////////////////////////////////////////////////////////////////////
// PSS encoding scheme                                                //
////////////////////////////////////////////////////////////////////////

/**
 * PKCS #1 PSS encoding
 */
static int PSS_encode(unsigned char *encoded, 
        unsigned int message_bytes, const unsigned char *message) {
  unsigned char M[8 + RSA_SHA_BYTES + RSA_SALT_BYTES];
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1];

  // Compute the hash of m
  debugValue("PSS encode: message", message, message_bytes);
  SHA(RSA_SHA_BYTES, M + 8, message_bytes, message);
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
  SHA(RSA_SHA_BYTES, encoded + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES, M);
  debugValue("PSS encode: hash of message to be encoded", encoded + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, RSA_SHA_BYTES);

  Copy(RSA_SHA_BYTES, M, encoded + RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  MGF1(RSA_SHA_BYTES, M, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, encoded);
  debugValue("PSS encode: dbMask", encoded, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, encoded);
  debugValue("PSS encode: maskedDB", encoded, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  // Construct the encoded message
  Copy(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, encoded, DB);
  encoded[RSA_MOD_BYTES - 1] = 0xbc;
  debugValue("PSS encode: encoded message", encoded, RSA_MOD_BYTES);
  
  return RSA_MOD_BYTES;
}

/**
 * PKCS #1 PSS verification
 */
static int PSS_verify(unsigned int message_bytes, const unsigned char *message, 
        unsigned int encoded_bytes, const unsigned char *encoded) {
  unsigned char M[8 + RSA_SHA_BYTES + RSA_SALT_BYTES];
  unsigned char DB[RSA_MOD_BYTES - RSA_SHA_BYTES - 1];

  debugValue("PSS verify: message", message, message_bytes);

  if (encoded_bytes != RSA_MOD_BYTES) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }
  debugValue("PSS verify: encoded message", encoded, encoded_bytes);

  // Verification
  if (encoded[RSA_MOD_BYTES - 1] != 0xbc) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }

  // Extract maskedDB and H
  debugValue("PSS verify: maskedDB", encoded, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  Copy(RSA_SHA_BYTES, M + 8, encoded + RSA_MOD_BYTES - RSA_SHA_BYTES - 1);
  debugValue("PSS verify: H", encoded + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, RSA_SHA_BYTES);

  // Compute DB
  MGF1(RSA_SHA_BYTES, M + 8, RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB);
  debugValue("PSS verify: dbMask", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  XorAssign(RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB, encoded);
  debugValue("PSS verify: DB", DB, RSA_MOD_BYTES - RSA_SHA_BYTES - 1);

  if (DB[RSA_MOD_BYTES - RSA_SALT_BYTES - RSA_SHA_BYTES - 2] != 0x01) {
    return RSA_ERROR_PSS_INCONSISTENT;
  }

  // Compute hash of m
  SHA(RSA_SHA_BYTES, M + 8, message_bytes, message);
  debugValue("PSS verify: hash of message", M + 8, RSA_SHA_BYTES);

  Copy(RSA_SALT_BYTES, M + 8 + RSA_SHA_BYTES, DB + RSA_MOD_BYTES - RSA_SALT_BYTES - RSA_SHA_BYTES - 1);
  debugValue("PSS verify: recovered message to be encoded", M, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES);

  SHA(RSA_SHA_BYTES, DB, 8 + RSA_SHA_BYTES + RSA_SALT_BYTES, M);
  debugValue("PSS verify: hash of recovered message to be encoded", DB, RSA_SHA_BYTES);

  if (NotEqual(RSA_SHA_BYTES, encoded + RSA_MOD_BYTES - RSA_SHA_BYTES - 1, DB)) {
    debugWarning("PSS verify: verification failed");
    return RSA_ERROR_PSS_INCONSISTENT;
  }

  debugMessage("PSS verify: verification succeeded");
  return RSA_PSS_CONSISTENT;
}

////////////////////////////////////////////////////////////////////////
// Helper functions                                                   //
////////////////////////////////////////////////////////////////////////

/**
 * PKCS #1 Mask generation function 1.
 * 
 * @param seed_bytes actual size of the seed.
 * @param seed buffer containing the seed and space for 4 additional bytes.
 * @param mask_bytes size of the mask to be generated.
 * @param mask buffer to store the generated mask.
 */
static void MGF1(unsigned int seed_bytes, unsigned char *seed, 
        unsigned int mask_bytes, unsigned char *mask) {
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
	  i++;
  }
  
  // Prepare hash data (for the last block)
  Copy(sizeof(unsigned int), seed + seed_bytes + (4 - sizeof(unsigned int)), (unsigned char *) &i);

  // Compute hash 
  SHA(RSA_SHA_BYTES, hash, seed_bytes + 4, seed);

  // Append hash to mask
  CopyBytes(mask_bytes - i * RSA_SHA_BYTES, mask + i * RSA_SHA_BYTES, hash);
}
