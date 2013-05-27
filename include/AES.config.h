/**
 * AES.config.h
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

#ifndef __AES_config_H
#define __AES_config_H

#ifndef AES_KEY_BITS
  #define AES_KEY_BITS 128
#endif // !AES_KEY_BITS

#ifndef AES_BLOCK_BITS
  #define AES_BLOCK_BITS 128
#endif // !AES_BLOCK_BITS

#ifndef AES_IV_BITS
  #define AES_IV_BITS AES_BLOCK_BITS
#endif // !AES_IV_BITS

#endif // __AES_config_H
