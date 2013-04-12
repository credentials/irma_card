/**
 * MULTOS.h
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
 
#ifndef __MULTOS_H
#define __MULTOS_H

#include "melasm.h"

/**
 * SHA-1
 * 
 * This primitive calculates the SHA-1 hash digest of a message of 
 * arbitrary length (including 0 bytes).
 * 
 * Stack input:  [ lenMsg | addrHash | addrMsg ]
 * Stack output: []
 * 
 * Each of the input parameters is 2-bytes in size. The value lenMsg is 
 * the size of the input to the SHA-1 algorithm. The second parameter 
 * addrHash is the location where the 20-byte hash digest will be 
 * written. The parameter addrMsg is the location of the input of size 
 * lenMsg.
 */
#define PRIM_SHA1 0xCA

/**
 * Secure Hash
 * 
 * This primitive calculates the SHA-1, SHA-224, SHA-256, SHA-384 or 
 * SHA-512 digest of a message of arbitrary length (including 0 bytes) 
 * in accordance with [FIPS180-3].
 * 
 * Stack input:  [ lenMsg | lenHash | addrHash | addrMsg ]
 * Stack output: []
 * 
 * Each of the input parameters is 2-bytes in size. The value lenMsg is 
 * the size in bytes of the input to the Secure Hash algorithm. The 
 * value lenHash is either 20, 28, 32, 48 or 64 and is the size of the
 * resultant hash digest (computed using the SHA-1, SHA-224, SHA-256, 
 * SHA-384 and SHA-512 algorithms, respectively). Other lengths will 
 * cause an abend. The parameter addrHash is the location where the hash
 * digest will be written. The parameter addrMsg is the location of the 
 * input of size lenMsg.
 */
#define PRIM_SECURE_HASH 0xCF

/**
 * Secure Hash IV
 * 
 * This primitive calculates the SHA-1, SHA-224, SHA-256, SHA-384 or 
 * SHA-512 digest of a message of arbitrary length (including 0 bytes)
 * in accordance with [FIPS180-3] with the ability to pass a previously 
 * calculated intermediate hash value and message remainder (where the 
 * previous message was not block-aligned) to the algorithm.
 * 
 * Stack in:  [ lenMsg | lenHash | addrHash | addrMsg | 
 *             addrIntermediateHash | addrPrevHashedBytes | 
 *             lenMessageRemainder | addrMessageRemainder ]
 * Stack out: [ lenMessageRemainder | addrMessageRemainder ]
 * 
 * Each of the input parameters is 2-bytes in size. The value lenMsg is 
 * the size in bytes of the input to the Secure Hash algorithm. The 
 * value lenHash is either 20, 28, 32, 48 or 64 and is the size of the 
 * resultant hash digest (computed using the SHA-1, SHA-224, SHA-256, 
 * SHA-384 and SHA-512 algorithms, respectively). The parameter addrHash
 * is the location where the hash digest will be written. The parameter 
 * addrMsg is the location of the input message of size lenMsg. The 
 * parameter addrIntermediateHash is the location of the previously 
 * calculated intermediate hash value input to the algorithm and output 
 * from the algorithm. It is 20, 32 or 64 bytes in length dependent upon
 * the algorithm requested. The parameter addrPrevHashedBytes is the 
 * location of the 4 byte (32-bit) counter indicating the number of 
 * bytes previously input to the hashing algorithm, including previous 
 * calculations. The parameter lenMessageRemainder is the number 
 * remaining non-block aligned bytes from a previously hashed message.
 * The parameter addrMessageRemainder is the address of the remaining 
 * non-block aligned bytes of a previously hashed message, of length 
 * lenMessageRemainder.
 * 
 * If the value at addrIntermediateHash is all zeros, then the algorithm
 * shall replace this value with the standard IV value used by the 
 * algorithm, as specified in [FIPS180-3]. 
 * 
 * The 32-bit value at addrPrevHashedBytes is the number of bytes 
 * previously hashed by a call to this primitive or an alternative 
 * calculation method. If the value at this address is zero, the 
 * primitive will start a new hash calculation and ignore the values 
 * contained at addrIntermediateHash and addrMessageRemainder. This 
 * value is updated by the primitive and may serve as input to a 
 * subsequent call to the primitive.
 * 
 * If lenMessageRemainder is zero, the value at addrMessageRemainder 
 * will be ignored, but value at addrIntermediateHash will still be used
 * as the input value to the algorithm. 
 * 
 * Following calculation, the memory at location addrIntermediateHash 
 * shall contain the last intermediate hash value H(n) calculated by the
 * algorithm prior to any truncation when performing a SHA-224 or 
 * SHA-384 algorithm. This value may serve as input to a subsequent call
 * to the primitive. The memory at addrHash will always contain a final 
 * hash value complete with truncation if applicable.
 * 
 * If the message hashed (the value at addrMessageRemainder prepended to
 * the value at addrMsg) is not block aligned (i.e. not a multiple of 
 * either 32 or 64 bytes depending upon the hash algorithm), following 
 * calculation of the intermediate value, the remainder of the message 
 * of length lenMessageRemainder shall be pointed to by 
 * addrMessageRemainder and will be placed on the returned stack. This 
 * memory address may be within the area starting at addrMsg for length 
 * lenMsg or it may be at the address passed to the primitive.
 * 
 * Developers should ensure that there is sufficient memory at address 
 * addrMessageRemainder to contain the message remainder of the 
 * appropriate block size, as the returned message remainder can be 
 * longer than the input message remainder. If a developer does not 
 * allocate such a memory area, then the primitive may overwrite memory 
 * beyond addrMessageRemainder + lenMessageRemainder or abend.
 */
#define PRIM_SECURE_HASH_IV 0xE4

#endif // __MULTOS_H
