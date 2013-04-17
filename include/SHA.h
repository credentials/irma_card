/**
 * SHA.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, September 2011.
 */
 
#ifndef __SHA_H
#define __SHA_H

#include "MULTOS.h"

#define SHA_1_BITS   160
#define SHA_224_BITS 224
#define SHA_256_BITS 256
#define SHA_384_BITS 384
#define SHA_512_BITS 512

#define SHA_BITS_TO_BYTES(bits) ((bits + 7) /8)

#define SHA_1_BYTES   SHA_BITS_TO_BYTES(SHA_1_BITS)
#define SHA_224_BYTES SHA_BITS_TO_BYTES(SHA_224_BITS)
#define SHA_256_BYTES SHA_BITS_TO_BYTES(SHA_256_BITS)
#define SHA_384_BYTES SHA_BITS_TO_BYTES(SHA_384_BITS)
#define SHA_512_BYTES SHA_BITS_TO_BYTES(SHA_512_BITS)

#define SHA_1   SHA_1_BYTES
#define SHA_224 SHA_224_BYTES
#define SHA_256 SHA_256_BYTES
#define SHA_384 SHA_384_BYTES
#define SHA_512 SHA_512_BYTES

#define SHA(digest_bytes, digest, data_bytes, data) \
do { \
  __push(data_bytes); \
  __push(digest_bytes); \
  __push(digest); \
  __push(data); \
  __code(PRIM, PRIM_SECURE_HASH); \
} while (0)

#endif // __SHA_H
