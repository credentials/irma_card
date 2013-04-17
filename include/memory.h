/**
 * memory.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, April 2013.
 */

#ifndef __MEMORY_H
#define __MEMORY_H

#include "MULTOS.h"

#include <string.h> // for memcmp

#define CopyFlex CopyNonAtomic
#define CopyFixed CopyFixedNonAtomic

#define Copy CopyFixed
#define CopyBytes CopyFlex

#define CopyAtomic(bytes, dest, src) \
do { \
  __push(__typechk(unsigned int, bytes)); \
  __push(dest); \
  __push(src); \
  __code(PRIM, PRIM_COPY); \
} while (0)

#define CopyNonAtomic(bytes, dest, src) \
do { \
  __push(__typechk(unsigned int, bytes)); \
  __push(dest); \
  __push(src); \
  __code(PRIM, PRIM_COPY_NON_ATOMIC); \
} while (0)
  
#define CopyFixedAtomic(bytes, dest, src) \
do { \
  __push(dest); \
  __push(src); \
  __code(PRIM, PRIM_COPY_FIXED, bytes); \
} while (0)

#define CopyFixedNonAtomic(bytes, dest, src) \
do { \
  __push(dest); \
  __push(src); \
  __code(PRIM, PRIM_COPY_FIXED_NON_ATOMIC, bytes); \
} while (0)

#define Compare(bytes, x, y) \
  memcmp(x, y, bytes)

#define Fill(bytes, array, value) \
  memset(array, value, bytes)

#define Clear(bytes, x) \
  __code(CLEARN, x, bytes)

#define TestZero(bytes, value, flag) \
  __code(TESTN, value, bytes); \
  __code(PRIM, PRIM_LOAD_CCR); \
  __code(PRIM, PRIM_BIT_MANIPULATE_BYTE, (1<<7 | 3), 1); \
  __code(STORE, &flag, 1)

#endif // __MEMORY_H
