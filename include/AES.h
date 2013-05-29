/**
 * AES.h
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
 * Copyright (C) May 2013 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __AES_H
#define __AES_H

#include "AES.config.h"

#ifndef AES_KEY_BITS
  #error "AES_KEY_BITS not defined"
#endif // !AES_KEY_BITS

#ifndef AES_BLOCK_BITS
  #error "AES_BLOCK_BITS not defined"
#endif // !AES_BLOCK_BITS

#ifndef AES_IV_BITS
  #error "AES_IV_BITS not defined"
#endif // !AES_IV_BITS

#define AES_BITS_TO_BYTES(bits) ((bits + 7) /8)

#define AES_KEY_BYTES AES_BITS_TO_BYTES(AES_KEY_BITS)
#define AES_BLOCK_BYTES AES_BITS_TO_BYTES(AES_BLOCK_BITS)
#define AES_IV_BYTES AES_BITS_TO_BYTES(AES_IV_BITS)

#include "MULTOS.h"

void AES_CBC_sign(unsigned int message_bytes, const unsigned char *message, unsigned char *signature, unsigned int key_bytes, const unsigned char *key, const unsigned char *iv);

#define AES_CBC_decrypt(cipher_bytes, cipher, plain, key_bytes, key, iv) \
do { \
  __push(AES_IV_BYTES); \
  __push((void *)(iv)); \
  AES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, BLOCK_CIPHER_MODE_CBC); \
} while (0)

#define AES_ECB_decrypt(cipher_bytes, cipher, plain, key_bytes, key) \
do { \
  AES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, BLOCK_CIPHER_MODE_ECB); \
} while (0)

#define AES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, mode) \
  __push((unsigned int)(cipher_bytes)); \
  __push((void *)(key)); \
  __push((unsigned int)(key_bytes)); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_DECIPHER, BLOCK_CIPHER_ALGORITHM_AES, mode);

#define AES_CBC_encrypt(plain_bytes, plain, cipher, key_bytes, key, iv) \
do { \
  __push(AES_IV_BYTES); \
  __push((void *)(iv)); \
  AES_encrypt(plain_bytes, plain, cipher, key_bytes, key, BLOCK_CIPHER_MODE_CBC); \
} while (0)

#define AES_ECB_encrypt(plain_bytes, plain, cipher, key_bytes, key) \
do { \
  AES_encrypt(cipher_bytes, cipher, plain, key_bytes, key, BLOCK_CIPHER_MODE_ECB); \
} while (0)

#define AES_encrypt(plain_bytes, plain, cipher, key_bytes, key, mode) \
  __push((unsigned int)(plain_bytes)); \
  __push((void *)(key)); \
  __push((unsigned int)(key_bytes)); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_ENCIPHER, BLOCK_CIPHER_ALGORITHM_AES, mode);

#endif // __AES_H
