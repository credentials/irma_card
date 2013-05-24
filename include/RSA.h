/**
 * RSA.h
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
 * Copyright (C) March 2013 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __RSA_H
#define __RSA_H

#include "RSA.config.h"

#ifndef RSA_EXP_BITS
  #error "RSA_EXP_BITS not defined"
#endif // !RSA_EXP_BITS

#ifndef RSA_MOD_BITS
  #error "RSA_MOD_BITS not defined"
#endif // !RSA_MOD_BITS

#ifndef RSA_SHA_BITS
  #error "RSA_SALT_BITS not defined"
#endif // !RSA_SHA_BITS

#ifndef RSA_SALT_BITS
  #error "RSA_SALT_BITS not defined"
#endif // !RSA_SALT_BITS

#define RSA_BITS_TO_BYTES(bits) ((bits + 7) /8)

#define RSA_EXP_BYTES RSA_BITS_TO_BYTES(RSA_EXP_BITS)
#define RSA_MOD_BYTES RSA_BITS_TO_BYTES(RSA_MOD_BITS)
#define RSA_SHA_BYTES RSA_BITS_TO_BYTES(RSA_SHA_BITS)
#define RSA_SALT_BYTES RSA_BITS_TO_BYTES(RSA_SALT_BITS)

/**
 * RSA key
 */
typedef struct {
  unsigned char modulus[RSA_MOD_BYTES];
  unsigned char exponent[RSA_EXP_BYTES];
} RSA_key;

typedef RSA_key RSA_public_key;
typedef RSA_key RSA_private_key;

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
        unsigned int plaintext_bytes, const unsigned char *plaintext);

#define RSA_ERROR_RAW_ENCRYPT -1

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
        unsigned int ciphertext_bytes, const unsigned char *ciphertext);

#define RSA_ERROR_RAW_DECRYPT -2

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
        unsigned int label_bytes, const unsigned char *label);

/**
 * RSA decryption using OAEP decoding (as specified by PKCS #1)
 *
 * Note: the ciphertext will be modified/overwritten by this function.
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
        unsigned int label_bytes, const unsigned char *label);


#define RSA_ERROR_OAEP_DECRYPT -3
#define RSA_ERROR_OAEP_DECODE -4

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
        unsigned int message_bytes, const unsigned char *message);

#define RSA_ERROR_RAW_SIGN -5

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
        unsigned int signature_bytes, unsigned char *signature);

#define RSA_ERROR_RAW_VERIFY -6
#define RSA_ERROR_INCONSISTENT -7
#define RSA_CONSISTENT 1

/**
 * RSA signature generation using PSS encoding (as specified by PKCS #1)
 *
 * @param key to be used for this operation.
 * @param signature produced by signing the message.
 * @param message_bytes size in bytes of the message.
 * @param message to be signed.
 * @return number of bytes written to signature.
 */
int RSA_PSS_sign(const RSA_private_key *key, unsigned char *signature,
        unsigned int message_bytes, const unsigned char *message);

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
int RSA_PSS_verify(const RSA_public_key *key,
        unsigned int message_bytes, const unsigned char *message,
        unsigned int signature_bytes, unsigned char *signature);

#define RSA_PSS_CONSISTENT 2
#define RSA_ERROR_PSS_INCONSISTENT -8

#endif // __RSA_H
