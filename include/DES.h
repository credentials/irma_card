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

#define BLOCK_MODE_ECB 0x01
#define BLOCK_MODE_CBC 0x02

#define ALGORITHM_DES   0x03
#define ALGORITHM_3DES  0x04

#define DES_CBCSign(message_bytes, iv, key, signature, message) \
do { \
  __push((unsigned int)(message_bytes)); \
  __push((void *)(iv)); \
  __push((void *)(key)); \
  __push((void *)(signature)); \
  __push((void *)(message)); \
  __code(PRIM, PRIM_GENERATE_TRIPLE_DES_CBC_SIGNATURE); \
} while (0)

#define DES_CBCDecipher(cipher_bytes, cipher, plain, iv, key_bytes, key) \
do { \
  __push(0x08); /* iv_bytes = 8 */\
  __push((void *)(iv)); \
  __push((unsigned int)(cipher_bytes)); \
  __push((void *)(key)); \
  __push((unsigned char)(key_bytes)); \
  __push((void *)(plain)); \
  __push((void *)(cipher)); \
  __code(PRIM, PRIM_BLOCK_DECIPHER, ALGORITHM_3DES, BLOCK_MODE_CBC); \
} while (0)


#define DES_CBCEncipher(plain_bytes, plain, cipher, iv, key_bytes, key) \
do { \
  __push(0x08); /* iv_bytes = 8 */\
  __push((void *)(iv)); \
  __push((unsigned int)(plain_bytes)); \
  __push((void *)(key)); \
  __push((unsigned char)(key_bytes)); \
  __push((void *)(cipher)); \
  __push((void *)(plain)); \
  __code(PRIM, PRIM_BLOCK_ENCIPHER, ALGORITHM_3DES, BLOCK_MODE_CBC); \
} while (0)

#endif // __DES_H
