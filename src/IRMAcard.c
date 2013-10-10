/**
 * IRMAcard.c
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

// Name everything "IRMAcard"
#pragma attribute("aid", "49 52 4D 41 63 61 72 64")
#pragma attribute("dir", "61 10 4f 6 69 64 65 6D 69 78 50 6 69 64 65 6D 69 78")
#pragma attribute("fci", "6F 08 A5 06 04 04 49 00 07 03")

#include "types.h"
#include "types.debug.h"
#include "APDU.h"
#include "auth.h"
#include "CHV.h"
#include "debug.h"
#include "issuance.h"
#include "math.h"
#include "memory.h"
#include "logging.h"
#include "random.h"
#include "RSA.h"
#include "SM.h"
#include "sizes.h"
#include "utils.h"
#include "verification.h"

/********************************************************************/
/* Public segment (APDU buffer) variable declaration                */
/********************************************************************/
#pragma melpublic

// Idemix: protocol public variables
PublicData public;


/********************************************************************/
/* Session segment (application RAM memory) variable declaration    */
/********************************************************************/
#pragma melsession

// Idemix: protocol session variables
SessionData session;
Credential *credential;

// Secure messaging: session parameters
SM_parameters tunnel;
Terminal terminal;

// State administration
unsigned int state;

#define STATE_ISSUE_CREDENTIAL 0x00FF
#define STATE_ISSUE_SETUP      0x0001
#define STATE_ISSUE_PUBLIC_KEY 0x0002
#define STATE_ISSUE_ATTRIBUTES 0x0004
#define STATE_ISSUE_COMMITTED  0x0008
#define STATE_ISSUE_CHALLENGED 0x0010
#define STATE_ISSUE_SIGNATURE  0x0020
#define STATE_ISSUE_VERIFY     0x0040
#define STATE_ISSUE_FINISHED   0x0080

#define STATE_PROVE_CREDENTIAL 0x0F00
#define STATE_PROVE_SETUP      0x0100
#define STATE_PROVE_COMMITTED  0x0200
#define STATE_PROVE_SIGNATURE  0x0400
#define STATE_PROVE_ATTRIBUTES 0x0800

#define matchState(x) \
  ((state & (x)) != 0)

#define checkState(x) \
  if (!matchState(x)) { APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED); }

#define nextState() \
  state <<= 1


/********************************************************************/
/* Static segment (application EEPROM memory) variable declarations */
/********************************************************************/
#pragma melstatic

// Idemix: credentials and master secret
Credential credentials[MAX_CRED];
CLMessage masterSecret;

// Card holder verification: PIN
CHV_PIN cardPIN = {
  { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00 },
  SIZE_CARD_PIN,
  CHV_PIN_COUNT,
  0x80
};
CHV_PIN credPIN = {
  { 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00 },
  SIZE_CRED_PIN,
  CHV_PIN_COUNT,
  0x40
};

RSA_public_key caKey;
DebugData debug;

// Logging
Log log;
IRMALogEntry *logEntry;

unsigned char d[128];

unsigned char a[128] = { 0x10, 0x3A, 0x55, 0xAF, 0x74, 0x7C, 0xD2, 0xB1, 0x6C, 0xD3, 0x1E, 0xBE, 0x1C, 0x62, 0x2F, 0x3A, 0x25, 0x2B, 0x52, 0x87, 0xBD, 0x6D, 0xCA, 0x0E, 0x04, 0x9D, 0x02, 0x5D, 0x5D, 0x13, 0xE4, 0x02, 0xD0, 0x70, 0x84, 0x7A, 0x8A, 0x52, 0x2B, 0xB6, 0xAD, 0x58, 0xBF, 0xAB, 0xE0, 0xB4, 0x89, 0x07, 0x03, 0xEA, 0xCA, 0x91, 0x05, 0xAF, 0xE9, 0x51, 0xB1, 0xBC, 0xD4, 0x81, 0xC0, 0x40, 0xD0, 0xC1, 0x18, 0xE1, 0x84, 0xC3, 0x5E, 0x98, 0x02, 0x51, 0x3B, 0xB6, 0xE0, 0xC7, 0xDF, 0xF0, 0xF2, 0x71, 0x2D, 0x4C, 0xDE, 0xAF, 0x2B, 0x64, 0xD9, 0x19, 0x6C, 0x41, 0xDA, 0x3B, 0xDC, 0x5C, 0x97, 0x81, 0x7A, 0xE9, 0x63, 0x6F, 0x9A, 0x5C, 0x6B, 0x2A, 0x0C, 0xF9, 0xFE, 0x1F, 0x56, 0x90, 0x53, 0x49, 0x4E, 0x6E, 0xC1, 0xDF, 0x6E, 0x24, 0xB2, 0xE4, 0x2F, 0x39, 0xC4, 0xA0, 0x02, 0xD5, 0x2E, 0xBE };

// 0x00, 0x28, 0xC5, 0x09, 0x07, 0xA6, 0x18, 0x06, 0x7A, 0x21, 0x21, 0xE1, 0xA0, 0xF5, 0x0B, 0xE1, 0x29, 0x11, 0x3B, 0x3D, 0x27, 0x3E, 0x53, 0x62, 0xC6, 0xDC, 0x26, 0x76, 0x5B, 0xFA, 0xDC, 0xEA, 0x14, 0xC7, 0xDE, 0x8E, 0x45, 0x9B, 0x9E, 0x43, 0xF3, 0xDF, 0x9E, 0x32, 0xA1, 0x78, 0x85, 0xEA, 0x9B, 0xED, 0xF2, 0x99, 0xB4, 0x09, 0xFA, 0x51, 0x7C, 0x57, 0x3E, 0x19, 0xA7, 0xE0, 0x82, 0xB4, 0x1D, 0x97, 0x30, 0xAF, 0xCA, 0xA0, 0xC4, 0x7C, 0xAA, 0x07, 0xEB, 0x42, 0x63, 0xBD, 0x68, 0x34, 0xBE, 0x94, 0x6A, 0xB9, 0xD7, 0x4C, 0x60, 0xD6, 0x8A, 0x5D, 0x3D, 0xB3, 0x8A, 0xDE, 0xAB, 0xA1, 0x4C, 0x22, 0xC7, 0x4D, 0xCF, 0x72, 0x1D, 0x70, 0x6F, 0x4D, 0x12, 0x93, 0xC0, 0x35, 0x0D, 0xB2, 0x8C, 0xEF, 0xF2, 0x5E, 0xC5, 0x8F, 0x6A, 0xBA, 0x36, 0xF8, 0xF0, 0xBC, 0xA8, 0x21, 0xD3, 0x7A };

unsigned char b[128] = { 0x4D, 0x57, 0xF5, 0x2B, 0xAD, 0xF6, 0xF1, 0xB1, 0xE1, 0xC1, 0xF4, 0x6A, 0x4F, 0x5B, 0xFF, 0xDA, 0xE9, 0x7F, 0x56, 0x8B, 0x5C, 0xDF, 0x73, 0x77, 0x99, 0x12, 0xC8, 0xA6, 0x7F, 0x4B, 0x6F, 0x59, 0x1E, 0x24, 0xFA, 0x61, 0xBA, 0x68, 0x8E, 0xE9, 0x1F, 0xBF, 0x9A, 0xEC, 0x3A, 0x4B, 0x0C, 0xD6, 0x8F, 0xCE, 0x0F, 0x10, 0xB3, 0x82, 0x06, 0xCC, 0x93, 0xD6, 0xEC, 0xB8, 0xF9, 0x94, 0xB9, 0x42, 0xC8, 0x88, 0xFA, 0x34, 0x5D, 0x5A, 0x53, 0xF8, 0xEF, 0xD7, 0x8E, 0xB5, 0xC9, 0xF3, 0x50, 0xD3, 0x08, 0x28, 0xA4, 0x3B, 0xF1, 0xAD, 0x54, 0x5A, 0xAC, 0x27, 0x3A, 0x03, 0x36, 0x3A, 0xCF, 0xF1, 0x66, 0x48, 0x91, 0xA1, 0xAB, 0x5E, 0x92, 0xD2, 0x24, 0x4F, 0x82, 0xE2, 0xFC, 0xE7, 0x8C, 0x80, 0xA8, 0x4E, 0xEA, 0xA8, 0x33, 0xE5, 0xF2, 0x33, 0x92, 0x4E, 0x4E, 0xE8, 0xD5, 0xE0, 0xB9, 0x8F };

// 0x1E, 0x20, 0x02, 0x16, 0xE4, 0x2A, 0xBF, 0x66, 0x01, 0x2B, 0xC1, 0xB0, 0x4E, 0x6B, 0x68, 0x40, 0x05, 0xBD, 0xF9, 0x55, 0x9C, 0xE3, 0x57, 0xFE, 0xA5, 0xD6, 0x2C, 0x93, 0x18, 0x68, 0xD5, 0x81, 0x61, 0xDF, 0x82, 0x23, 0x57, 0xA9, 0x72, 0xBB, 0x67, 0x21, 0x32, 0xEA, 0xDB, 0x5E, 0xA1, 0xDD, 0xF7, 0x4C, 0x52, 0xB5, 0xB9, 0xF4, 0x22, 0x03, 0x0A, 0xB8, 0x31, 0xC8, 0x5E, 0x50, 0xAA, 0xE0, 0xB7, 0x7F, 0x15, 0xE9, 0xC7, 0x60, 0x77, 0x5D, 0x15, 0xC7, 0xDD, 0x4F, 0x0F, 0xDF, 0xB6, 0x05, 0x5A, 0x78, 0xE5, 0x32, 0xA5, 0x8C, 0xF7, 0x0D, 0x2A, 0x9A, 0xF4, 0xE1, 0xE2, 0xC3, 0x9A, 0xDC, 0x2C, 0x9B, 0xEA, 0x1F, 0x84, 0x50, 0xED, 0x66, 0x58, 0x62, 0xB2, 0xB6, 0xD1, 0xEA, 0xBC, 0xC9, 0xE5, 0x4A, 0xD2, 0x87, 0x62, 0x26, 0xCB, 0x14, 0xF7, 0xDD, 0x85, 0x43, 0x22, 0xA4, 0x2E, 0x99 };

unsigned char c[128] = { 0x00, 0x28, 0xC5, 0x09, 0x07, 0xA6, 0x18, 0x06, 0x7A, 0x21, 0x21, 0xE1, 0xA0, 0xF5, 0x0B, 0xE1, 0x29, 0x11, 0x3B, 0x3D, 0x27, 0x3E, 0x53, 0x62, 0xC6, 0xDC, 0x26, 0x76, 0x5B, 0xFA, 0xDC, 0xEA, 0x14, 0xC7, 0xDE, 0x8E, 0x45, 0x9B, 0x9E, 0x43, 0xF3, 0xDF, 0x9E, 0x32, 0xA1, 0x78, 0x85, 0xEA, 0x9B, 0xED, 0xF2, 0x99, 0xB4, 0x09, 0xFA, 0x51, 0x7C, 0x57, 0x3E, 0x19, 0xA7, 0xE0, 0x82, 0xB4, 0x1D, 0x97, 0x30, 0xAF, 0xCA, 0xA0, 0xC4, 0x7C, 0xAA, 0x07, 0xEB, 0x42, 0x63, 0xBD, 0x68, 0x34, 0xBE, 0x94, 0x6A, 0xB9, 0xD7, 0x4C, 0x60, 0xD6, 0x8A, 0x5D, 0x3D, 0xB3, 0x8A, 0xDE, 0xAB, 0xA1, 0x4C, 0x22, 0xC7, 0x4D, 0xCF, 0x72, 0x1D, 0x70, 0x6F, 0x4D, 0x12, 0x93, 0xC0, 0x35, 0x0D, 0xB2, 0x8C, 0xEF, 0xF2, 0x5E, 0xC5, 0x8F, 0x6A, 0xBA, 0x36, 0xF8, 0xF0, 0xBC, 0xA8, 0x21, 0xD3, 0x7A };

// 0x3E, 0x43, 0x89, 0xBB, 0x53, 0x13, 0xAC, 0xFC, 0xFE, 0x85, 0x7B, 0x9E, 0x49, 0x8E, 0xEC, 0xEE, 0x23, 0xA6, 0xA1, 0xCE, 0x74, 0x27, 0xB3, 0x69, 0xFD, 0xBF, 0x05, 0xFA, 0xD7, 0x8A, 0x28, 0xE8, 0xF7, 0x43, 0x8C, 0x3A, 0xB3, 0x5E, 0xA7, 0x2F, 0x2E, 0xE3, 0x3B, 0xBD, 0xD6, 0xE5, 0x98, 0xE0, 0x3B, 0x41, 0x69, 0xD5, 0xC3, 0x6B, 0x2C, 0x2F, 0x75, 0x4A, 0x38, 0x6B, 0x9A, 0x98, 0x3D, 0x80, 0xFB, 0x5E, 0x96, 0xD3, 0xBF, 0x53, 0x27, 0xF7, 0xEF, 0xC8, 0x22, 0x42, 0x25, 0x90, 0xEE, 0xAB, 0x39, 0x93, 0xD7, 0x21, 0xEF, 0x87, 0x23, 0xA7, 0x6C, 0xCA, 0xE5, 0xC4, 0x96, 0x3A, 0xCF, 0xC0, 0x60, 0xE9, 0xBB, 0xEA, 0xF6, 0x83, 0xE5, 0x76, 0xCE, 0x97, 0x74, 0xEE, 0x54, 0xAA, 0xCD, 0x9E, 0x30, 0x8A, 0x74, 0xF4, 0x91, 0xB0, 0xE6, 0x9A, 0xF3, 0x6E, 0xC4, 0x8F, 0x74, 0x41, 0xF4, 0x83 };

unsigned char n[128] = { 0x88, 0xCC, 0x7B, 0xD5, 0xEA, 0xA3, 0x90, 0x06, 0xA6, 0x3D, 0x1D, 0xBA, 0x18, 0xBD, 0xAF, 0x00, 0x13, 0x07, 0x25, 0x59, 0x7A, 0x0A, 0x46, 0xF0, 0xBA, 0xCC, 0xEF, 0x16, 0x39, 0x52, 0x83, 0x3B, 0xCB, 0xDD, 0x40, 0x70, 0x28, 0x1C, 0xC0, 0x42, 0xB4, 0x25, 0x54, 0x88, 0xD0, 0xE2, 0x60, 0xB4, 0xD4, 0x8A, 0x31, 0xD9, 0x4B, 0xCA, 0x67, 0xC8, 0x54, 0x73, 0x7D, 0x37, 0x89, 0x0C, 0x7B, 0x21, 0x18, 0x4A, 0x05, 0x3C, 0xD5, 0x79, 0x17, 0x66, 0x81, 0x09, 0x3A, 0xB0, 0xEF, 0x0B, 0x8D, 0xB9, 0x4A, 0xFD, 0x18, 0x12, 0xA7, 0x8E, 0x1E, 0x62, 0xAE, 0x94, 0x26, 0x51, 0xBB, 0x90, 0x9E, 0x6F, 0x5E, 0x5A, 0x2C, 0xEF, 0x60, 0x04, 0x94, 0x6C, 0xCA, 0x3F, 0x66, 0xEC, 0x21, 0xCB, 0x9A, 0xC0, 0x1F, 0xF9, 0xD3, 0xE8, 0x8F, 0x19, 0xAC, 0x27, 0xFC, 0x77, 0xB1, 0x90, 0x3F, 0x14, 0x10, 0x49 };

/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void processInitialisation(void);
void processIssuance(void);
void processVerification(void);
void processAdministration(void);

void main(void) {
  // Check whether the APDU has been wrapped for secure messaging
  if (APDU_wrapped) {
    if (!CheckCase(4)) {
      SM_ReturnSW(SW_WRONG_LENGTH);
    }

    switch (SM_APDU_unwrap(public.apdu.data, public.apdu.session, &tunnel)) {
      case SM_ERROR_WRONG_DATA:
        SM_ReturnSW(SW_DATA_INVALID);
      case SM_ERROR_MAC_INVALID:
      case SM_ERROR_PADDING_INVALID:
        SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
      default:
        debugValue("Unwrapped APDU", public.apdu.data, Lc);
    }
  }

  switch (CLA & (0xFF ^ (CLA_SECURE_MESSAGING | CLA_COMMAND_CHAINING))) {

    //////////////////////////////////////////////////////////////////
    // Generic functionality                                        //
    //////////////////////////////////////////////////////////////////

    case CLA_ISO7816:
      // Process the instruction
      switch (INS) {

        case 0xFF:
          Copy(128, d, a);
          ModMul(128, d, b, n);
          Copy(128, public.apdu.data, d);
          if (Equal(128, d, c)) {
            APDU_ReturnSWLa(0x9000, 128);
          } else {
            APDU_ReturnSWLa(0x6E00, 128);
          }
          break;

        //////////////////////////////////////////////////////////////
        // Authentication                                           //
        //////////////////////////////////////////////////////////////

        case INS_PERFORM_SECURITY_OPERATION:
          if (!CheckCase(3)) {
            APDU_returnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 != 0x00BE) {
            APDU_returnSW(SW_WRONG_P1P2);
          }
          if (public.vfyCert.offset + Lc > 768) {
            APDU_returnSW(SW_COMMAND_NOT_ALLOWED);
          }

          // Add the incoming data to the buffer.
          CopyBytes(Lc, public.vfyCert.cert + public.vfyCert.offset, public.apdu.data);
          public.vfyCert.offset += Lc;

          // Verify the certificate.
          if (!APDU_chained) {
            public.vfyCert.offset = 0;
            if (authentication_verifyCertificate(&caKey, public.vfyCert.cert, session.auth.certBody) < 0) {
              APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
            }
            authentication_parseCertificate(session.auth.certBody);
          }
          APDU_return();

        case INS_GET_CHALLENGE:
          if (!CheckCase(1)) {
            APDU_returnSW(SW_WRONG_LENGTH);
          }

          authentication_generateChallenge(&(session.auth.terminalKey), session.auth.challenge, public.apdu.data);
          APDU_returnLa(RSA_MOD_BYTES);

        case INS_INTERNAL_AUTHENTICATE:
          // Perform card authentication & secure messaging setup
          break;

        //////////////////////////////////////////////////////////////
        // Card holder verification                                 //
        //////////////////////////////////////////////////////////////

        case INS_VERIFY:
          debugMessage("INS_VERIFY");
          APDU_checkLength(SIZE_PIN_MAX);
          APDU_checkP1(0x00);

          switch (P2) {
            case P2_CARD_PIN:
              CHV_PIN_verify(&cardPIN, public.apdu.data);
              break;

            case P2_CRED_PIN:
              CHV_PIN_verify(&credPIN, public.apdu.data);
              break;

            default:
              debugWarning("Unknown parameter");
              APDU_returnSW(SW_WRONG_P1P2);
          }
          APDU_return();

        case INS_CHANGE_REFERENCE_DATA:
          debugMessage("INS_CHANGE_REFERENCE_DATA");
          APDU_checkLength(2*SIZE_PIN_MAX);
          APDU_checkP1(0x00);

          switch (P2) {
            case P2_CARD_PIN:
              CHV_PIN_update(&cardPIN, public.apdu.data);
              break;

            case P2_CRED_PIN:
              CHV_PIN_update(&credPIN, public.apdu.data);
              break;

            default:
              debugWarning("Unknown parameter");
              APDU_returnSW(SW_WRONG_P1P2);
          }
          APDU_return();

        //////////////////////////////////////////////////////////////
        // Unknown instruction byte (INS)                           //
        //////////////////////////////////////////////////////////////

        default:
          debugWarning("Unknown instruction");
          APDU_returnSW(SW_INS_NOT_SUPPORTED);
      }

    //////////////////////////////////////////////////////////////////
    // Idemix functionality                                         //
    //////////////////////////////////////////////////////////////////

    case CLA_IRMACARD:
      switch (INS & 0xF0) {
        case 0x00:
          processInitialisation();
          SM_return();
        case 0x10:
          processIssuance();
          SM_return();
        case 0x20:
          processVerification();
          SM_return();
        case 0x30:
          processAdministration();
          APDU_return();
        default:
          debugWarning("Unknown instruction");
          debugInteger("INS", INS);
          APDU_returnSW(SW_INS_NOT_SUPPORTED);
      }

    //////////////////////////////////////////////////////////////////
    // Unknown class byte (CLA)                                     //
    //////////////////////////////////////////////////////////////////

    default:
      debugWarning("Unknown class");
      debugInteger("CLA", CLA);
      APDU_returnSW(SW_CLA_NOT_SUPPORTED);
  }
}


void processInitialisation(void) {
  unsigned char flag;

  switch (INS) {
    case INS_GENERATE_SECRET:
      debugMessage("INS_GENERATE_SECRET");
#ifndef TEST
      if (!(APDU_wrapped || CheckCase(1))) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }

      // Prevent reinitialisation of the master secret
      TestZero(SIZE_M, masterSecret, flag);
      if (flag == 0) {
        debugWarning("Master secret is already generated");
        APDU_returnSW(SW_COMMAND_NOT_ALLOWED_AGAIN);
      }

      // Generate a random value for the master secret
      RandomBits(masterSecret, LENGTH_M);
#else // TEST
      if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_M)) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }

      // Use the test value for the master secret
      Copy(SIZE_M, masterSecret, public.apdu.data);
#endif // TEST
      debugValue("Initialised master secret", masterSecret, SIZE_M);
      APDU_returnSW(SW_NO_ERROR);

    case INS_AUTHENTICATION_SECRET:
      debugMessage("INS_AUTHENTICATION_SECRET");
      if (P2 != 0x00) {
          APDU_returnSW(SW_WRONG_P1P2);
      }
      switch (P1) {
        case P1_AUTH_EXPONENT + 2:
          debugMessage("P1_AUTHENTICATION_EXPONENT");
          if (!((APDU_wrapped || CheckCase(3)) && Lc == RSA_EXP_BYTES)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          Copy(RSA_EXP_BYTES, caKey.exponent, public.apdu.data);
          debugValue("Initialised rsaExponent", caKey.exponent, RSA_EXP_BYTES);
          break;

        case P1_AUTH_MODULUS + 2:
          debugMessage("P1_AUTHENTICATION_MODULUS");
          if (!((APDU_wrapped || CheckCase(3)) && Lc == RSA_MOD_BYTES)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          Copy(RSA_MOD_BYTES, caKey.modulus, public.apdu.data);
          debugValue("Initialised rsaModulus", caKey.modulus, RSA_MOD_BYTES);
          break;

        default:
          debugWarning("Unknown parameter");
          APDU_ReturnSW(SW_WRONG_P1P2);
      }
      APDU_ReturnSW(SW_NO_ERROR);

    default:
      debugWarning("Unknown instruction");
      debugInteger("INS", INS);
      APDU_returnSW(SW_INS_NOT_SUPPORTED);
  }
}


void startIssuance(void) {
  unsigned char i;

  // Ensure that the master secret is initiaised
  IfZeroBytes(SIZE_M, masterSecret, RandomBits(masterSecret, LENGTH_M));

  // Start a new issuance session
  credential = NULL;

  // Check policy
  if (!auth_checkIssuance(&terminal, public.issuanceSetup.id)) {
    APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
  }

  // Locate a credential slot
  for (i = 0; i < MAX_CRED; i++) {
    // Reuse the existing credential slot.
    if (credentials[i].id == public.issuanceSetup.id) {
      debugMessage("Credential already exists");
      if (!auth_checkOverwrite(&terminal, public.issuanceSetup.id)) {
        debugWarning("Overwrite not allowed");
        APDU_returnSW(SW_COMMAND_NOT_ALLOWED_AGAIN);
      } else {
        credential = &credentials[i];
        break;
      }

    // Use a new credential slot
    } else if (credentials[i].id == 0 && credential == NULL) {
      debugMessage("Found empty slot");
      credential = &credentials[i];
    }
  }

  // No credential slot selected, out of space
  if (credential == NULL) {
    debugWarning("Cannot issue another credential");
    APDU_returnSW(SW_COMMAND_NOT_ALLOWED);
  }

  // Initialise the credential
  credential->id = public.issuanceSetup.id;
  credential->size = public.issuanceSetup.size;
  credential->issuerFlags = public.issuanceSetup.flags;
  Copy(SIZE_H, credential->proof.context, public.issuanceSetup.context);
  debugHash("Initialised context", credential->proof.context);

  // Create new log entry
  logEntry = (IRMALogEntry*) log_new_entry(&log);
  Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.issuanceSetup.timestamp);
  Copy(AUTH_TERMINAL_ID_BYTES, logEntry->terminal, terminal.id);
  logEntry->action = ACTION_ISSUE;
  logEntry->credential = credential->id;

  // Initialise the issuance state
  state = STATE_ISSUE_SETUP;
}

void processIssuance(void) {

  // Issuance requires the terminal to be authenticated.
  /* Implicit due to the fact that we've got a secure tunnel. */

  // Issuance requires the credential PIN to be verified.
  if (!CHV_verified(credPIN)) {
    APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  // Special case: start issuance
  if (INS == INS_ISSUE_CREDENTIAL) {
    debugMessage("INS_ISSUE_CREDENTIAL");
    APDU_checkLength(sizeof(IssuanceSetup));

    startIssuance();

    APDU_return();

  // All other issuance commands
  } else {

    // A credential should be selected for issuance
    if (credential == NULL || !matchState(STATE_ISSUE_CREDENTIAL)) {
      APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
    }

    switch (INS) {
      case INS_ISSUE_PUBLIC_KEY:
        debugMessage("INS_ISSUE_PUBLIC_KEY");
        if (matchState(STATE_ISSUE_SETUP)) {
          nextState();
        }
        checkState(STATE_ISSUE_PUBLIC_KEY);
        APDU_checkLength(SIZE_N);

        switch (P1) {
          case P1_PUBLIC_KEY_N:
            debugMessage("P1_PUBLIC_KEY_N");
            Copy(SIZE_N, credential->issuerKey.n, public.apdu.data);
            debugNumber("Initialised isserKey.n", credential->issuerKey.n);
            break;

          case P1_PUBLIC_KEY_Z:
            debugMessage("P1_PUBLIC_KEY_Z");
            Copy(SIZE_N, credential->issuerKey.Z, public.apdu.data);
            debugNumber("Initialised isserKey.Z", credential->issuerKey.Z);
            break;

          case P1_PUBLIC_KEY_S:
            debugMessage("P1_PUBLIC_KEY_S");
            Copy(SIZE_N, credential->issuerKey.S, public.apdu.data);
            debugNumber("Initialised isserKey.S", credential->issuerKey.S);
            ComputeS_(credential, public.issue.buffer.data);
            debugNumber("Initialised isserKey.S_", credential->issuerKey.S_);
            break;

          case P1_PUBLIC_KEY_R:
            debugMessage("P1_PUBLIC_KEY_R");
            APDU_checkP2upper(credential->size + 1);
            Copy(SIZE_N, credential->issuerKey.R[P2], public.apdu.data);
            debugIndexedNumber("Initialised isserKey.R", credential->issuerKey.R, P2);
            break;

          default:
            debugWarning("Unknown parameter");
            debugInteger("P1", P1);
            APDU_returnSW(SW_WRONG_P1P2);
        }
        APDU_return();

      case INS_ISSUE_ATTRIBUTES:
        debugMessage("INS_ISSUE_ATTRIBUTES");
        if (matchState(STATE_ISSUE_PUBLIC_KEY) && issuance_checkPublicKey(credential)) {
          nextState();
        }
        checkState(STATE_ISSUE_ATTRIBUTES);
        APDU_checkLength(SIZE_M);
        APDU_checkP1range(1, credential->size);
        IfZero(SIZE_M, public.apdu.data,
          debugWarning("Attribute cannot be empty");
          APDU_returnSW(SW_WRONG_DATA);
        );

        Copy(SIZE_M, credential->attribute[P1 - 1], public.apdu.data);
        debugIndexedCLMessage("Initialised attribute", credential->attribute, P1 - 1);
        APDU_return();

      case INS_ISSUE_COMMITMENT:
        debugMessage("INS_ISSUE_COMMITMENT");
        if (!matchState(STATE_ISSUE_ATTRIBUTES) && !issuance_checkAttributes(credential)) {
          APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
        }
        APDU_checkLength(SIZE_STATZK);

        Copy(SIZE_STATZK, public.issue.nonce, public.apdu.data);
        debugNonce("Initialised nonce", public.issue.nonce);
        constructCommitment(credential, &masterSecret[0]);
        debugNumber("Returned U", public.apdu.data);

        nextState();
        APDU_returnLa(SIZE_N);

      case INS_ISSUE_COMMITMENT_PROOF:
        debugMessage("INS_ISSUE_COMMITMENT_PROOF");
        checkState(STATE_ISSUE_COMMITTED);
        APDU_checkLength(0);

        switch (P1) {
          case P1_PROOF_C:
            debugMessage("P1_COMMITMENT_PROOF_C");
            Copy(SIZE_H, public.apdu.data, session.issue.challenge);
            debugHash("Returned c", public.apdu.data);
            APDU_returnLa(SIZE_H);

          case P1_PROOF_VPRIMEHAT:
            debugMessage("P1_COMMITMENT_PROOF_VPRIMEHAT");
            Copy(SIZE_VPRIME_, public.apdu.data, session.issue.vPrimeHat);
            debugValue("Returned vPrimeHat", public.apdu.data, SIZE_VPRIME_);
            APDU_returnLa(SIZE_VPRIME_);

          case P1_PROOF_SHAT:
            debugMessage("P1_COMMITMENT_PROOF_SHAT");
            Copy(SIZE_S_, public.apdu.data, session.issue.sHat);
            debugValue("Returned s_A", public.apdu.data, SIZE_S_);
            APDU_returnLa(SIZE_S_);

          default:
            debugWarning("Unknown parameter");
            debugInteger("P1", P1);
            APDU_returnSW(SW_WRONG_P1P2);
        }

      case INS_ISSUE_CHALLENGE:
        debugMessage("INS_ISSUE_CHALLENGE");
        checkState(STATE_ISSUE_COMMITTED);
        APDU_checkLength(0);

        Copy(SIZE_STATZK, public.apdu.data, credential->proof.nonce);
        debugNonce("Returned nonce", public.apdu.data);

        nextState();
        APDU_returnLa(SIZE_STATZK);

      case INS_ISSUE_SIGNATURE:
        debugMessage("INS_ISSUE_SIGNATURE");
        if (matchState(STATE_ISSUE_CHALLENGED)) {
          nextState();
        }
        checkState(STATE_ISSUE_SIGNATURE);

        switch(P1) {
          case P1_SIGNATURE_A:
            debugMessage("P1_SIGNATURE_A");
            APDU_checkLength(SIZE_N);
            Copy(SIZE_N, credential->signature.A, public.apdu.data);
            debugNumber("Initialised signature.A", credential->signature.A);
            break;

          case P1_SIGNATURE_E:
            debugMessage("P1_SIGNATURE_E");
            APDU_checkLength(SIZE_E);
            Copy(SIZE_E, credential->signature.e, public.apdu.data);
            debugValue("Initialised signature.e", credential->signature.e, SIZE_E);
            break;

          case P1_SIGNATURE_V:
            debugMessage("P1_SIGNATURE_V");
            APDU_checkLength(SIZE_V);
            constructSignature(credential);
            debugValue("Initialised signature.v", credential->signature.v, SIZE_V);
            break;

          case P1_SIGNATURE_PROOF_C:
            debugMessage("P1_SIGNATURE_PROOF_C");
            APDU_checkLength(SIZE_H);
            Copy(SIZE_H, credential->proof.challenge, public.apdu.data);
            debugHash("Initialised c", credential->proof.challenge);
            break;

          case P1_SIGNATURE_PROOF_S_E:
            debugMessage("P1_SIGNATURE_PROOF_S_E");
            APDU_checkLength(SIZE_N);
            Copy(SIZE_N, credential->proof.response, public.apdu.data);
            debugNumber("Initialised s_e", credential->proof.response);
            break;

          default:
            debugWarning("Unknown parameter");
            APDU_returnSW(SW_WRONG_P1P2);
        }
        APDU_return();

      case INS_ISSUE_VERIFY:
        if (matchState(STATE_ISSUE_SIGNATURE) && issuance_checkSignature(credential)) {
          nextState();
        }
        checkState(STATE_ISSUE_VERIFY);

        if (!verifySignature(credential, &masterSecret[0], &session.vfySig)) {
          debugWarning("Signature invalid");
          APDU_returnSW(SW_DATA_INVALID);
        }
        if (!verifyProof(credential, &session.vfyPrf, &public.vfyPrf)) {
          debugWarning("Proof invalid");
          APDU_returnSW(SW_DATA_INVALID);
        }

        nextState();
        APDU_return();

      default:
        debugWarning("Unknown instruction");
        debugInteger("INS", INS);
        APDU_returnSW(SW_INS_NOT_SUPPORTED);
    }
  }
}

void startVerification(void) {
  unsigned char i;

  // Start a new verification session
  credential = NULL;
  ClearBytes(sizeof(VerificationSession), &(session.prove));

  // Check policy
  if (!auth_checkSelection(&terminal, public.verificationSetup.id, public.verificationSetup.selection)) {
    APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
  }

  // Lookup the credential slot
  for (i = 0; i < MAX_CRED; i++) {
    if (credentials[i].id == public.verificationSetup.id) {
      credential = &credentials[i];
    }
  }

  // No credential slot selected,
  if (credential == NULL) {
    debugWarning("Credential not found");
    APDU_returnSW(SW_REFERENCED_DATA_NOT_FOUND);
  }

  // Check selection validity
  if (verifySelection(credential, public.verificationSetup.selection) < 0) {
    credential = NULL;
    APDU_returnSW(SW_WRONG_DATA);
  }

  // Check PIN protection
  if (verifyProtection(credential, public.verificationSetup.selection) && !CHV_verified(credPIN)) {
    credential = NULL;
    APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  // Initialise the session
  session.prove.disclose = public.verificationSetup.selection;
  Copy(SIZE_H, public.prove.context, public.verificationSetup.context);
  debugHash("Initialised context", public.prove.context);

  // Create new log entry
  logEntry = (IRMALogEntry*) log_new_entry(&log);
  Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.verificationSetup.timestamp);
  Copy(AUTH_TERMINAL_ID_BYTES, logEntry->terminal, terminal.id);
  logEntry->action = ACTION_PROVE;
  logEntry->credential = credential->id;
  logEntry->details.prove.selection = session.prove.disclose;

  state = STATE_PROVE_CREDENTIAL;
}

void processVerification(void) {

  // Verification requires the terminal to be authenticated.
  /* Implicit due to the fact that we've got a secure tunnel. */

  // Special case: start verification
  if (INS == INS_PROVE_CREDENTIAL) {
    debugMessage("INS_PROVE_CREDENTIAL");
    APDU_checkLength(sizeof(VerificationSetup));

    startVerification();

    APDU_return();

  // All other verification commands
  } else {

    // A credential should be selected for verification
    if (credential == NULL || !matchState(STATE_PROVE_CREDENTIAL)) {
      APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
    }

    switch (INS) {
      case INS_PROVE_COMMITMENT:
        debugMessage("INS_PROVE_COMMITMENT");
        checkState(STATE_PROVE_SETUP);
        APDU_checkLength(SIZE_STATZK);

        constructProof(credential, &masterSecret[0]);
        debugHash("Returned c", public.apdu.data);

        nextState();
        APDU_returnLa(SIZE_H);

      case INS_PROVE_SIGNATURE:
        debugMessage("INS_PROVE_SIGNATURE");
        if (matchState(STATE_PROVE_COMMITTED)) {
          nextState();
        }
        checkState(STATE_PROVE_SIGNATURE);

        switch(P1) {
          case P1_SIGNATURE_A:
            debugMessage("P1_SIGNATURE_A");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, public.prove.APrime);
            debugNumber("Returned A'", public.apdu.data);
            APDU_returnLa(SIZE_N);

          case P1_SIGNATURE_E:
            debugMessage("P1_SIGNATURE_E");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_E_, public.apdu.data, public.prove.eHat);
            debugValue("Returned e^", public.apdu.data, SIZE_E_);
            APDU_returnLa(SIZE_E_);

          case P1_SIGNATURE_V:
            debugMessage("P1_SIGNATURE_V");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_V_, public.apdu.data, public.prove.vHat);
            debugValue("Returned v^", public.apdu.data, SIZE_V_);
            APDU_returnLa(SIZE_V_);

          default:
            debugWarning("Unknown parameter");
            APDU_returnSW(SW_WRONG_P1P2);
        }

      case INS_PROVE_ATTRIBUTE:
        debugMessage("INS_PROVE_ATTRIBUTE");
        if (matchState(STATE_PROVE_SIGNATURE)) {
          nextState();
        }
        checkState(STATE_PROVE_ATTRIBUTES);
        APDU_checkLength(0);
        if (P1 > credential->size) {
          APDU_returnSW(SW_WRONG_P1P2);
        }

        if (disclosed(P1)) {
          Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
          debugValue("Returned attribute", public.apdu.data, SIZE_M);
          APDU_returnLa(SIZE_M);
        } else {
          Copy(SIZE_M_, public.apdu.data, session.prove.mHat[P1]);
          debugValue("Returned response", public.apdu.data, SIZE_M_);
          APDU_returnLa(SIZE_M_);
        }

      case INS_PROVE_DEBUG:
        switch(P1) {
          case 0x01:
            debugMessage("P1_DEBUG_ZTilde");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.ZTilde);
            APDU_returnLa(SIZE_N);

          case 0x02:
            debugMessage("P1_DEBUG_RA");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_R_A, public.apdu.data, debug.rA);
            APDU_returnLa(SIZE_R_A);

          case 0x03:
            debugMessage("P1_DEBUG_ETILDE");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_E_, public.apdu.data, debug.eTilde);
            APDU_returnLa(SIZE_E_);

          case 0x04:
            debugMessage("P1_DEBUG_VTILDE");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_V_, public.apdu.data, debug.vTilde);
            APDU_returnLa(SIZE_V_);

          case 0x05:
            debugMessage("P1_DEBUG_MTILDE");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_M_, public.apdu.data, debug.mTilde[P2]);
            APDU_returnLa(SIZE_M_);

          case 0x06:
            debugMessage("P1_DEBUG_A");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, credential->signature.A);
            APDU_returnLa(SIZE_N);

          case 0x07:
            debugMessage("P1_DEBUG_SRA");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.SRA);
            APDU_returnLa(SIZE_N);

          case 0x08:
            debugMessage("P1_DEBUG_S_");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, credential->issuerKey.S_);
            APDU_returnLa(SIZE_N);

          case 0x09:
            debugMessage("P1_DEBUG_S_");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.modexpA);
            APDU_returnLa(SIZE_N);

          case 0x0A:
            debugMessage("P1_DEBUG_S_");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.modexpB);
            APDU_returnLa(SIZE_N);

          case 0x0B:
            debugMessage("P1_DEBUG_S_");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.AeTilde);
            APDU_returnLa(SIZE_N);

          case 0x0C:
            debugMessage("P1_DEBUG_S_");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.SvTilde);
            APDU_returnLa(SIZE_N);

          case 0x0D:
            debugMessage("P1_DEBUG_S_");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.SvAeTilde);
            APDU_returnLa(SIZE_N);

          case 0x0E:
            debugMessage("P1_DEBUG_EXP");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.exp[P2]);
            APDU_returnLa(SIZE_N);

          case 0x0F:
            debugMessage("P1_DEBUG_MUL");
            if (!(APDU_wrapped || CheckCase(1))) {
              APDU_returnSW(SW_WRONG_LENGTH);
            }

            Copy(SIZE_N, public.apdu.data, debug.mul[P2]);
            APDU_returnLa(SIZE_N);

          default:
            debugWarning("Unknown parameter");
            APDU_returnSW(SW_WRONG_P1P2);
        }


      default:
        // TODO: unknown
        APDU_returnSW(SW_INS_NOT_SUPPORTED);
    }
  }
}

void processAdministration(void) {
  unsigned char i;

  if (!CHV_verified(cardPIN)) {
    APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  switch (INS) {
    case INS_ADMIN_CREDENTIALS:
      debugMessage("INS_ADMIN_CREDENTIALS");
      if (!CheckCase(1)) {
        APDU_ReturnSW(SW_WRONG_LENGTH);
      }

      for (i = 0; i < MAX_CRED; i++) {
        ((short*) public.apdu.data)[i] = credentials[i].id;
      }

      APDU_returnLa(2*MAX_CRED);

    case INS_ADMIN_CREDENTIAL:
      debugMessage("INS_ADMIN_CREDENTIAL");
      if (!CheckCase(1)) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }
      if (P1P2 == 0) {
        APDU_returnSW(SW_WRONG_P1P2);
      }

      // Lookup the given credential ID and select it if it exists
      for (i = 0; i < MAX_CRED; i++) {
        if (credentials[i].id == P1P2) {
          credential = &credentials[i];
          APDU_returnSW(SW_NO_ERROR);
        }
      }
      APDU_returnSW(SW_REFERENCED_DATA_NOT_FOUND);

    case INS_ADMIN_ATTRIBUTE:
      debugMessage("INS_ADMIN_ATTRIBUTE");
      if (credential == NULL) {
        APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
      }
      if (!CheckCase(1)) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }
      if (P1 == 0 || P1 > credential->size) {
        APDU_returnSW(SW_WRONG_P1P2);
      }

      Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
      debugValue("Returned attribute", public.apdu.data, SIZE_M);
      APDU_returnLa(SIZE_M);
      break;

    case INS_ADMIN_REMOVE:
      debugMessage("INS_ADMIN_REMOVE");
      if (credential == NULL) {
        APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
      }
      if (!((APDU_wrapped || CheckCase(1)) ||
          ((APDU_wrapped || CheckCase(3)) && (Lc == SIZE_TIMESTAMP)))) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }
      if (P1P2 == 0) {
        APDU_returnSW(SW_WRONG_P1P2);
      }

      // Verify the given credential ID and remove it if it matches
      if (credential->id == P1P2) {
        ClearCredential(credential);
        debugInteger("Removed credential", P1P2);

        // Create new log entry
        logEntry = (IRMALogEntry*) log_new_entry(&log);
        Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.apdu.data);
        Copy(AUTH_TERMINAL_ID_BYTES, logEntry->terminal, terminal.id);
        logEntry->action = ACTION_REMOVE;
        logEntry->credential = P1P2;

        APDU_return();
      }

      APDU_returnSW(SW_REFERENCED_DATA_NOT_FOUND);

    case INS_ADMIN_FLAGS:
      debugMessage("INS_ADMIN_FLAGS");
      if (credential == NULL) {
        APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
      }
      if (!(CheckCase(1) || (CheckCase(3) && (Lc == sizeof(CredentialFlags))))) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }

      if (Lc > 0) {
        credential->userFlags = public.adminFlags.user;
        debugValue("Updated flags", (ByteArray) credential->userFlags.protect, sizeof(CredentialFlags));
        APDU_return();
      } else {
        public.adminFlags.user = credential->userFlags;
        public.adminFlags.issuer = credential->issuerFlags;
        debugValue("Returned flags", public.apdu.data, 2 * sizeof(CredentialFlags));
        APDU_returnLa(2 * sizeof(CredentialFlags));
      }

    case INS_ADMIN_LOG:
      debugMessage("INS_ADMIN_LOG");
      if (!CheckCase(1)) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }

      for (i = 0; i < 255 / sizeof(LogEntry); i++) {
        memcpy(public.apdu.data + i*sizeof(LogEntry), log_get_entry(&log, P1 + i), sizeof(LogEntry));
      }
      APDU_returnLa((255 / sizeof(LogEntry)) * sizeof(LogEntry));

    //////////////////////////////////////////////////////////////
    // Unknown instruction byte (INS)                           //
    //////////////////////////////////////////////////////////////

    default:
      debugWarning("Unknown instruction");
      debugInteger("CLA", CLA);
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      debugInteger("P2", P2);
      debugInteger("Lc", Lc);
      debugValue("data", public.apdu.data, Lc);
      APDU_ReturnSW(SW_INS_NOT_SUPPORTED);
      break;
  }
}
