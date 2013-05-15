/**
 * RSA.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, March 2013.
 */
 
#ifndef __RSA_H
#define __RSA_H

#ifndef RSA_EXP_BITS
  #define RSA_EXP_BITS 1024
#endif // !RSA_EXP_BITS

#ifndef RSA_MOD_BITS
  #define RSA_MOD_BITS 1024
#endif // !RSA_MOD_BITS

#ifndef RSA_SHA_BITS
  #define RSA_SHA_BITS SHA_1_BITS
#endif // !RSA_SHA_BITS

#ifndef RSA_SALT_BITS
  #define RSA_SALT_BITS SHA_1_BITS
#endif // !RSA_SALT_BITS

#define RSA_BITS_TO_BYTES(bits) ((bits + 7) /8)

#define RSA_EXP_BYTES RSA_BITS_TO_BYTES(RSA_EXP_BITS)
#define RSA_MOD_BYTES RSA_BITS_TO_BYTES(RSA_MOD_BITS)
#define RSA_SHA_BYTES RSA_BITS_TO_BYTES(RSA_SHA_BITS)
#define RSA_SALT_BYTES RSA_BITS_TO_BYTES(RSA_SALT_BITS)

typedef struct {
  unsigned char modulus[RSA_MOD_BYTES];
  unsigned char exponent[RSA_EXP_BYTES];
} RSA_key;

typedef RSA_key RSA_public_key;
typedef RSA_key RSA_private_key;

int RSA_RAW_encrypt(unsigned char *ciphertext, const RSA_public_key *key, 
        unsigned int plaintext_bytes, const unsigned char *plaintext);

int RSA_RAW_decrypt(unsigned char *plaintext, const RSA_private_key *key, 
        unsigned int ciphertext_bytes, const unsigned char *ciphertext);

#define RSA_RAW_sign(plaintext, key, ciphertext_bytes, ciphertext) \
  RSA_RAW_decrypt((plaintext), (key), (ciphertext_bytes), (ciphertext))

#define RSA_RAW_verify(ciphertext, key, plaintext_bytes, plaintext) \
  RSA_RAW_encrypt((ciphertext), (key), (plaintext_bytes), (plaintext))

#define RSA_ERROR_ENCRYPTION -1
#define RSA_ERROR_DECRYPTION -2

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
        unsigned int label_bytes, const unsigned char *label);

/**
 * PKCS #1 OAEP encoding
 */
int OAEP_encode(unsigned char *encoded, 
        unsigned int message_bytes, const unsigned char *message, 
        unsigned int label_bytes, const unsigned char *label);

/**
 * PKCS #1 OAEP decoding
 */
int OAEP_decode(unsigned char *message, 
        unsigned int encoded_bytes, const unsigned char *encoded, 
        unsigned int label_bytes, const unsigned char *label);

#define RSA_ERROR_OAEP_DECODE -3


/**
 * PKCS #1 Signature Generation Using PSS encoding method
 */
int RSA_PSS_sign(const RSA_private_key *key, unsigned char *signature,
        unsigned int message_bytes, const unsigned char *message);

/**
 * PKCS #1 Signature Verification
 * 
 * Note: the original ciphertext will be overwritten by this function.
 */
int RSA_PSS_verify(const RSA_public_key *key, 
        unsigned int message_bytes, const unsigned char *message, 
        unsigned int signature_bytes, unsigned char *signature);

/**
 * PKCS #1 PSS encoding
 */
int PSS_encode(unsigned char *encoded, 
		unsigned int message_bytes, const unsigned char *message);
/**
 * PKCS #1 PSS verification
 */
int PSS_verify(unsigned int message_bytes, const unsigned char *message, 
		unsigned int encoded_bytes, const unsigned char *encoded);

#define RSA_PSS_CONSISTENT 1
#define RSA_ERROR_PSS_INCONSISTENT -4

#endif	// __RSA_H
