/**
 * externals.h
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
 * Copyright (C) July 2011 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __externals_H
#define __externals_H

#include "types.h"

// Idemix: protocol public variables
extern PublicData public;

// Idemix: protocol session variables
extern SessionData session;
extern Credential *credential;
extern Byte flags;
extern Byte flag;

// Idemix: master secret
extern CLMessage masterSecret;

// Secure messaging: send sequence counter and session keys
extern Byte ssc[SIZE_SSC];
extern Byte key_enc[SIZE_KEY];
extern Byte key_mac[SIZE_KEY];

// Secure messaging: initialisation vector
extern Byte iv[SIZE_IV];

#endif // __externals_H
