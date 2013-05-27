/**
 * RSA.config.h
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

#ifndef __SM_config_H
#define __SM_config_H

#include "SHA.h"

#define SM_SHA_BITS SHA_1_BITS
#define SM_SSC_BITS 64

/**
 * Define either SM_AES or SM_DES to use defaults, otherwise specify the
 * custom configuration in the first block
 */
//#define SM_AES
#define SM_DES

#ifndef SM_AES
#ifndef SM_DES

// Comment this line if a custom configuration is provided.
#error "SM_AES or SM_DES must be defined"

#define SM_CBC_sign
#define SM_CBC_decrypt
#define SM_CBC_encrypt

#define SM_KEY_BITS
#define SM_IV_BITS
#define SM_MAC_BITS

#else // !SM_DES

#include "DES.h"

#define SM_CBC_sign DES_CBC_sign
#define SM_CBC_decrypt DES_CBC_decrypt
#define SM_CBC_encrypt DES_CBC_encrypt

#define SM_KEY_BITS DES_2KEY_BITS
#define SM_IV_BITS DES_IV_BITS
#define SM_MAC_BITS DES_BLOCK_BITS

#endif // !SM_DES
#else // !SM_AES

#include "AES.h"

#define SM_CBC_sign AES_CBC_sign
#define SM_CBC_decrypt AES_CBC_decrypt
#define SM_CBC_encrypt AES_CBC_encrypt

#define SM_KEY_BITS AES_KEY_BITS
#define SM_IV_BITS AES_IV_BITS
#define SM_MAC_BITS AES_BLOCK_BITS

#endif // !SM_AES

#endif // __SM_config_H
