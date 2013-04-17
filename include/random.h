/**
 * random.h
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
 
#ifndef __random_H
#define __random_H

/**
 * Generate a random number in the buffer of the given number of bytes
 * 
 * @param buffer to store the generated random number
 * @param bytes number of random bytes to generate
 */
void RandomBytes(unsigned char *buffer, unsigned int bytes);

/**
 * Generate a random number in the buffer of the given number of bits
 * 
 * @param buffer to store the generated random number
 * @param length of the random number to generate
 */
void RandomBits(unsigned char *buffer, unsigned int bytes);

#endif // __random_H
