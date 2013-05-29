/**
 * DES.h
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

#ifndef __DES_H
#define __DES_H

#include "MULTOS.h"

#define DES_2KEY_BITS 128
#define DES_3KEY_BITS 192
#define DES_BLOCK_BITS 64
#define DES_IV_BITS DES_BLOCK_BITS

#define DES_BITS_TO_BYTES(bits) ((bits + 7) /8)

#define DES_2KEY_BYTES DES_BITS_TO_BYTES(DES_2KEY_BITS)
#define DES_3KEY_BYTES DES_BITS_TO_BYTES(DES_3KEY_BITS)
#define DES_BLOCK_BYTES DES_BITS_TO_BYTES(DES_BLOCK_BITS)
#define DES_IV_BYTES DES_BITS_TO_BYTES(DES_IV_BITS)

#define DES_CBC_sign(message_bytes, message, signature, key_bytes, key, iv) \
do { \
  __push((unsigned int)(message_bytes)); \
  __push((void *)(iv)); \
  __push((void *)(key)); \
  __push((void *)(signature)); \
  __push((void *)(message)); \
  __code(PRIM, PRIM_GENERATE_TRIPLE_DES_CBC_SIGNATURE); \
} while (0)

#define DES_CBC_decrypt(cipher_bytes, cipher, plain, key_bytes, key, iv) \
do { \
  __push(DES_IV_BYTES); \
  __push((void *)(iv)); \
  DES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, BLOCK_CIPHER_MODE_CBC); \
} while (0)

#define DES_ECB_decrypt(cipher_bytes, cipher, plain, key_bytes, key) \
do { \
  DES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, BLOCK_CIPHER_MODE_ECB); \
} while (0)

#define DES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, mode) \
  __push((unsigned int)(cipher_bytes)); \
  __push((void *)(key)); \
  __push((unsigned int)(key_bytes)); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_DECIPHER, BLOCK_CIPHER_ALGORITHM_DES, mode);

#define DES_CBC_encrypt(plain_bytes, plain, cipher, key_bytes, key, iv) \
do { \
  __push(DES_IV_BYTES); \
  __push((void *)(iv)); \
  DES_decrypt(plain_bytes, plain, cipher, key_bytes, key, BLOCK_CIPHER_MODE_CBC); \
} while (0)

#define DES_ECB_encrypt(plain_bytes, plain, cipher, key_bytes, key) \
do { \
  DES_decrypt(cipher_bytes, cipher, plain, key_bytes, key, BLOCK_CIPHER_MODE_ECB); \
} while (0)

#define DES_encrypt(plain_bytes, plain, cipher, key_bytes, key, mode) \
  __push((unsigned int)(plain_bytes)); \
  __push((void *)(key)); \
  __push((unsigned int)(key_bytes)); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_ENCIPHER, BLOCK_CIPHER_ALGORITHM_3DES, mode);

#endif // __DES_H
