/**
 * types.h
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

#ifndef __types_H
#define __types_H

#include "RSA.h"
#include "auth.h"
#include "sizes.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef unsigned int uint;
typedef uint Size;
typedef const char *String;

typedef unsigned char *ByteArray;

typedef unsigned char Hash[SIZE_H];
typedef unsigned char Nonce[SIZE_STATZK];
typedef unsigned char ResponseE[SIZE_E_];
typedef unsigned char ResponseM[SIZE_M_];
typedef unsigned char ResponseV[SIZE_V_];
typedef unsigned char ResponseVPRIME[SIZE_VPRIME_];
typedef unsigned char Number[SIZE_N];
typedef Number Numbers[];

typedef struct {
  ByteArray data;
  Size size;
} Value;
typedef Value *ValueArray;

typedef struct {
  Number n;
  Number Z;
  Number S;
  Number S_;
  Number R[SIZE_L];
} CLPublicKey;

typedef unsigned char CLMessage[SIZE_M];
typedef CLMessage CLMessages[MAX_ATTR];

typedef struct {
  Number A;
  unsigned char e[SIZE_E];
  unsigned char v[SIZE_V];
} CLSignature;

typedef struct {
  Nonce nonce;
  Hash context;
  Hash challenge;
  Number response;
} CLProof;

typedef uint AttributeMask;
typedef uint CredentialIdentifier;

typedef struct {
  AttributeMask protect;
  unsigned char RFU;
} CredentialFlags;

typedef struct {
  CLPublicKey issuerKey;
  CLSignature signature;
  CLMessages attribute;
  CLProof proof;
  unsigned char size;
  CredentialFlags issuerFlags;
  CredentialFlags userFlags;
  CredentialIdentifier id;
} Credential;

typedef struct {
  unsigned char timestamp[SIZE_TIMESTAMP];
  unsigned char terminal[AUTH_TERMINAL_ID_BYTES];
  unsigned char action;
  CredentialIdentifier credential;
  union {
    struct {
      AttributeMask selection;
    } prove;
    unsigned char data[5];
  } details;
} IRMALogEntry;

#define ACTION_ISSUE 0x01;
#define ACTION_PROVE 0x02;
#define ACTION_REMOVE 0x03;

typedef struct {
  unsigned char data[255]; // 255
  unsigned char session[SIZE_PUBLIC - 255]; // SIZE_PUBLIC - 255
} APDU; // SIZE_PUBLIC

typedef struct {
  CredentialIdentifier id;
  Size size;
  CredentialFlags flags;
  Hash context;
  unsigned char timestamp[SIZE_TIMESTAMP];
} IssuanceSetup;

typedef struct {
  Number U; // 128
  union {
    unsigned char data[SIZE_BUFFER_C1]; // 307
    Number number[3]; // 384
  } buffer; // 384
  Value list[5]; // 20
  Nonce nonce; // 10
} IssuanceCommitment; // 128 + 384 + 20 + 10 = 542

typedef struct {
  Hash challenge; // 32
  unsigned char sHat[SIZE_S_]; // 75
  unsigned char vPrime[SIZE_VPRIME]; // 138
  ResponseVPRIME vPrimeHat; // 180
} IssuanceSession; // 32 + 75 + 138 + 180 = 425

typedef struct {
  Number ZPrime; // 128
  Number buffer; // 128
  Number tmp; // 128
} CLSignatureVerification; // 384

typedef struct {
  unsigned char buffer[SIZE_BUFFER_C2]; // 438
} IssuanceProofVerification; // 438

typedef struct {
  Value list[5]; // 20
  Hash challenge; // 32
  Number Q; // 128
  Number AHat; // 128
} IssuanceProofSession; // 20 + 32 + 128 + 128 = 308

typedef struct {
  CredentialIdentifier id;
  AttributeMask selection;
  Hash context;
  unsigned char timestamp[SIZE_TIMESTAMP];
} VerificationSetup;

typedef struct {
  union {
    Nonce nonce; // 10
    Hash challenge; // 20
  } apdu; // 20
  union {
    unsigned char data[SIZE_BUFFER_C1]; // 319
    Number number[2]; // 256
  } buffer; // 319
  Hash context; // 20
  Value list[4]; // 16
  unsigned char rA[SIZE_R_A]; // 138
  Number APrime; // 128
  ResponseV vHat; // 231
  ResponseE eHat; // 45
} VerificationProof; // 20 + 307 + 20 + 16 + 138 + 128 + 231 + 45 = 905

typedef struct {
  Number ZTilde;
  ResponseM mTilde[SIZE_L];
  ResponseV vTilde; // 231
  ResponseE eTilde; // 45
  unsigned char rA[SIZE_R_A]; // 138
  Number SRA;
  Number modexpA;
  Number modexpB;
  Number AeTilde;
  Number SvTilde;
  Number SvAeTilde;
  Number exp[6];
  Number mul[6];
} DebugData;

typedef struct {
  ResponseM mHat[SIZE_L]; // 74*6 (444)
  AttributeMask disclose; // 2
} VerificationSession; // 444 + 2 = 446

typedef struct {
  ByteArray certBody;
  RSA_public_key terminalKey;
  unsigned char challenge[AUTH_CHALLENGE_BYTES];
} TerminalAuthentication;

typedef struct {
  CredentialFlags user;
  CredentialFlags issuer;
} AdminFlags;

typedef struct {
  unsigned char apdu[255];
  unsigned char cert[768];
  unsigned int offset;
} CertificateVerification;

typedef union {
  unsigned char base[1];

  APDU apdu;

  CertificateVerification vfyCert;
  IssuanceSetup issuanceSetup;
  IssuanceCommitment issue;
  IssuanceProofVerification vfyPrf;

  VerificationSetup verificationSetup;
  VerificationProof prove;

  AdminFlags adminFlags;
} PublicData;

typedef union {
  unsigned char base[1];

  TerminalAuthentication auth;
  IssuanceSession issue;
  CLSignatureVerification vfySig;
  IssuanceProofSession vfyPrf;

  VerificationSession prove;
} SessionData;

#endif // __types_H
