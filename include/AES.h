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

#include "MULTOS.h"

#define AES_KEY_BITS 128
#define AES_IV_BITS 128

#define AES_BITS_TO_BYTES(bits) ((bits + 7) /8)

#define AES_KEY_BYTES AES_BITS_TO_BYTES(AES_KEY_BITS)
#define AES_IV_BYTES AES_BITS_TO_BYTES(AES_IV_BITS)

#define AES_CBC_sign(message_bytes, iv, key, signature, message) \
do { \
  __push((unsigned int)(message_bytes)); \
  __push((void *)(iv)); \
  __push((void *)(key)); \
  __push((void *)(signature)); \
  __push((void *)(message)); \
  __code(PRIM, PRIM_GENERATE_TRIPLE_DES_CBC_SIGNATURE); \
} while (0)

#define AES_CBC_decrypt(cipher_bytes, cipher, plain, iv, key) \
do { \
  __push(AES_IV_BYTES); \
  __push((void *)(iv)); \
  AES_decrypt(cipher_bytes, cipher, plain, iv, key, BLOCK_CIPHER_MODE_CBC); \
} while (0)

#define AES_ECB_decrypt(cipher_bytes, cipher, plain, key) \
do { \
  AES_decrypt(cipher_bytes, cipher, plain, key, BLOCK_CIPHER_MODE_ECB); \
} while (0)

#define AES_decrypt(cipher_bytes, cipher, plain, key, mode) \
  __push((unsigned int)(cipher_bytes)); \
  __push((void *)(key)); \
  __push(AES_KEY_BYTES); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_DECIPHER, BLOCK_CIPHER_ALGORITHM_AES, mode);

#define AES_CBC_encrypt(plain_bytes, plain, cipher, iv, key) \
do { \
  __push(AES_IV_BYTES); \
  __push((void *)(iv)); \
  AES_decrypt(plain_bytes, plain, cipher, iv, key, BLOCK_CIPHER_MODE_CBC); \
} while (0)

#define AES_ECB_encrypt(plain_bytes, plain, cipher, key) \
do { \
  AES_decrypt(cipher_bytes, cipher, plain, key, BLOCK_CIPHER_MODE_ECB); \
} while (0)

#define AES_encrypt(plain_bytes, plain, cipher, key, mode) \
  __push((unsigned int)(plain_bytes)); \
  __push((void *)(key)); \
  __push(AES_KEY_BYTES); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_ENCIPHER, BLOCK_CIPHER_ALGORITHM_AES, BLOCK_CIPHER_MODE_CBC);

#endif // __AES_H
