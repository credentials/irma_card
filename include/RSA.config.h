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

#ifndef __RSA_config_H
#define __RSA_config_H

#include "SHA.h"

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

#endif // __RSA_config_H
