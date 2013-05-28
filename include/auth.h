/**
 * auth.h
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
 * Copyright (C) April 2013 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __authentication_H
#define __authentication_H

#include "RSA.h"

#define POLICY_MAX_SIZE 8
typedef struct {
  unsigned int id;
  unsigned int mask;
} PolEntry;

typedef struct{
  PolEntry list[POLICY_MAX_SIZE];
  unsigned char size;
} Policy;



#define AUTH_CHALLENGE_BYTES 32

int authentication_verifyCertificate(RSA_public_key *key, unsigned char *cert, unsigned char *body);

#define AUTH_CERTIFICATE_WRONG -2
#define AUTH_CERTIFICATE_INVALID -1
#define AUTH_CERTIFICATE_VALID 1

void authentication_parseCertificate(unsigned char *cert);

void authentication_generateChallenge(RSA_public_key *key, unsigned char *nonce, unsigned char *challenge);

void authentication_authenticateTerminal(unsigned char *response, unsigned char *nonce);

#define AUTH_POLICY_ALLOWED 1
#define AUTH_POLICY_NOT_ALLOWED -1

#define AUTH_POLICY_MASK_ISSUANCE 0x0001
#define AUTH_POLICY_MASK_OVERWRITE (AUTH_POLICY_MASK_ISSUANCE | 0x0002)
#define AUTH_POLICY_MASK_SELECTION 0xFFFE

int auth_checkPolicy(const Policy *policy, unsigned int id, unsigned int mask);

#define auth_checkIssuance(policy, id) \
  auth_checkPolicy(policy, id, AUTH_POLICY_MASK_ISSUANCE)

#define auth_checkOverwrite(policy, id) \
  auth_checkPolicy(policy, id, AUTH_POLICY_MASK_OVERWRITE)

#define auth_checkSelection(policy, id, selection) \
  auth_checkPolicy(policy, id, (selection) & AUTH_POLICY_MASK_SELECTION)

#endif // __authentication_H
