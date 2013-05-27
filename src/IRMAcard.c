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
#include "authentication.h"
#include "CHV.h"
#include "debug.h"
#include "issuance.h"
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
SessionData session; // 389
Credential *credential; // + 2 = 669
Byte flags; // + 1 = 670

// Secure messaging: session parameters
SM_parameters tunnel;
Byte terminal[SIZE_TERMINAL_ID];

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

// Authentication
RSA_public_key cardKey;
RSA_public_key caKey;

// Logging
Log log;
IRMALogEntry *logEntry;

/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
  unsigned char flag;
  int i;

  // Check whether the APDU has been wrapped for secure messaging
  if (APDU_wrapped) {
    if (!CheckCase(4)) {
      SM_ReturnSW(SW_WRONG_LENGTH);
    }

    i = SM_APDU_unwrap(public.apdu.data, public.apdu.session, &tunnel);
    switch (i) {
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

        //////////////////////////////////////////////////////////////
        // Authentication                                           //
        //////////////////////////////////////////////////////////////

        case INS_PERFORM_SECURITY_OPERATION:
          if (!CheckCase(3)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 != 0x00BE) {
            APDU_ReturnSW(SW_WRONG_P1P2);
          }
          if (public.vfyCert.offset + Lc > 768) {
            APDU_ReturnSW(SW_COMMAND_NOT_ALLOWED);
          }

          // Add the incoming data to the buffer.
          CopyBytes(Lc, public.vfyCert.cert + public.vfyCert.offset, public.apdu.data);
          public.vfyCert.offset += Lc;

          // Verify the certificate.
          if (!APDU_chained) {
            public.vfyCert.offset = 0;
            if (authentication_verifyCertificate(&caKey, public.vfyCert.cert, session.auth.certBody) < 0) {
              APDU_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
            }
            authentication_parseCertificate(session.auth.certBody);
          }
          APDU_ReturnSW(SW_NO_ERROR);

        case INS_GET_CHALLENGE:
          if (!CheckCase(1)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          authentication_generateChallenge(&(session.auth.terminalKey), session.auth.challenge, public.apdu.data);
          APDU_ReturnLa(SW_NO_ERROR, RSA_MOD_BYTES);

/*        case INS_EXTERNAL_AUTHENTICATE:
          if (!CheckCase(3) && Lc != sizeof(Nonce)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          authentication_authenticateTerminal(public.apdu.data, session.auth.challenge);
          APDU_ReturnSW(SW_NO_ERROR);
*/
        case INS_INTERNAL_AUTHENTICATE:
          // Perform card authentication & secure messaging setup
          break;

        //////////////////////////////////////////////////////////////
        // Card holder verification                                 //
        //////////////////////////////////////////////////////////////

        case INS_VERIFY:
          debugMessage("INS_VERIFY");
          if (P1 != 0x00) {
              APDU_ReturnSW(SW_WRONG_P1P2);
          }
          if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_PIN_MAX)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }
          switch (P2) {
            case P2_CARD_PIN:
              CHV_PIN_verify(&cardPIN, public.apdu.data);
              break;

            case P2_CRED_PIN:
              CHV_PIN_verify(&credPIN, public.apdu.data);
              break;

            default:
              debugWarning("Unknown parameter");
              APDU_ReturnSW(SW_WRONG_P1P2);
          }
          APDU_ReturnSW(SW_NO_ERROR);

        case INS_CHANGE_REFERENCE_DATA:
          debugMessage("INS_CHANGE_REFERENCE_DATA");
          if (P1 != 0x00) {
              APDU_ReturnSW(SW_WRONG_P1P2);
          }
          if (!((APDU_wrapped || CheckCase(3)) && Lc == 2*SIZE_PIN_MAX)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }
          switch (P2) {
            case P2_CARD_PIN:
              CHV_PIN_update(&cardPIN, public.apdu.data);
              break;

            case P2_CRED_PIN:
              CHV_PIN_update(&credPIN, public.apdu.data);
              break;

            default:
              debugWarning("Unknown parameter");
              APDU_ReturnSW(SW_WRONG_P1P2);
          }
          APDU_ReturnSW(SW_NO_ERROR);

        //////////////////////////////////////////////////////////////
        // Unknown instruction byte (INS)                           //
        //////////////////////////////////////////////////////////////

        default:
          debugWarning("Unknown instruction");
          APDU_ReturnSW(SW_INS_NOT_SUPPORTED);
      }

    //////////////////////////////////////////////////////////////////
    // Idemix functionality                                         //
    //////////////////////////////////////////////////////////////////

    case CLA_IRMACARD:
      // Process the instruction
      switch (INS) {

        //////////////////////////////////////////////////////////////
        // Initialisation instructions                              //
        //////////////////////////////////////////////////////////////

        case INS_GENERATE_SECRET:
          debugMessage("INS_GENERATE_SECRET");
#ifndef TEST
          if (!(APDU_wrapped || CheckCase(1))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          // Prevent reinitialisation of the master secret
          TestZero(SIZE_M, masterSecret, flag);
          if (flag == 0) {
            debugWarning("Master secret is already generated");
            APDU_ReturnSW(SW_COMMAND_NOT_ALLOWED_AGAIN);
          }

          // Generate a random value for the master secret
          RandomBits(masterSecret, LENGTH_M);
#else // TEST
          if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_M)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          // Use the test value for the master secret
          Copy(SIZE_M, masterSecret, public.apdu.data);
#endif // TEST
          debugValue("Initialised master secret", masterSecret, SIZE_M);
          APDU_ReturnSW(SW_NO_ERROR);

        case INS_AUTHENTICATION_SECRET:
          debugMessage("INS_AUTHENTICATION_SECRET");
          if (P2 != 0x00) {
              APDU_ReturnSW(SW_WRONG_P1P2);
          }
          switch (P1) {
            case P1_AUTH_EXPONENT:
              debugMessage("P1_AUTHENTICATION_EXPONENT");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == RSA_EXP_BYTES)) {
                APDU_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(RSA_EXP_BYTES, cardKey.exponent, public.apdu.data);
              debugValue("Initialised rsaExponent", cardKey.exponent, RSA_EXP_BYTES);
              break;

            case P1_AUTH_MODULUS:
              debugMessage("P1_AUTHENTICATION_MODULUS");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == RSA_MOD_BYTES)) {
                APDU_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(RSA_MOD_BYTES, cardKey.modulus, public.apdu.data);
              debugValue("Initialised rsaModulus", cardKey.modulus, RSA_MOD_BYTES);
              break;

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

        //////////////////////////////////////////////////////////////
        // Personalisation / Issuance instructions                  //
        //////////////////////////////////////////////////////////////

        case INS_ISSUE_CREDENTIAL:
          debugMessage("INS_ISSUE_CREDENTIAL");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(3)) &&
              (Lc == sizeof(CredentialIdentifier) + sizeof(Hash) + sizeof(Size) + sizeof(CredentialFlags)
              || Lc == sizeof(CredentialIdentifier) + sizeof(Hash) + sizeof(Size) + sizeof(CredentialFlags) + SIZE_TIMESTAMP))) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 != 0) {
            SM_ReturnSW(SW_WRONG_P1P2);
          }

          // Prevent reissuance of a credential
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == public.issuanceSetup.id) {
              debugWarning("Credential already exists");
              SM_ReturnSW(SW_COMMAND_NOT_ALLOWED_AGAIN);
            }
          }

          // Create a new credential
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == 0) {
              credential = &credentials[i];
              credential->id = public.issuanceSetup.id;
              credential->size = public.issuanceSetup.size;
              credential->issuerFlags = public.issuanceSetup.flags;
              Copy(SIZE_H, credential->proof.context, public.issuanceSetup.context);
              debugHash("Initialised context", credential->proof.context);

              // Create new log entry
              logEntry = (IRMALogEntry*) log_new_entry(&log);
              Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.issuanceSetup.timestamp);
              Copy(SIZE_TERMINAL_ID, logEntry->terminal, terminal);
              logEntry->action = ACTION_ISSUE;
              logEntry->credential = credential->id;

              SM_ReturnSW(SW_NO_ERROR);
            }
          }

          // Out of space (all credential slots are occupied)
          debugWarning("Cannot issue another credential");
          SM_ReturnSW(SW_COMMAND_NOT_ALLOWED);

        case INS_ISSUE_PUBLIC_KEY:
          debugMessage("INS_ISSUE_PUBLIC_KEY");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }

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
              if (P2 > MAX_ATTR) {
                SM_ReturnSW(SW_WRONG_P1P2);
              }
              Copy(SIZE_N, credential->issuerKey.R[P2], public.apdu.data);
              debugIndexedNumber("Initialised isserKey.R", credential->issuerKey.R, P2);
              break;

            default:
              debugWarning("Unknown parameter");
              SM_ReturnSW(SW_WRONG_P1P2);
          }
          SM_ReturnSW(SW_NO_ERROR);

        case INS_ISSUE_ATTRIBUTES:
          debugMessage("INS_ISSUE_ATTRIBUTES");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_M)) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > credential->size) {
            SM_ReturnSW(SW_WRONG_P1P2);
          }
          TestZero(SIZE_M, public.apdu.data, flag);
          if (flag != 0) {
            debugWarning("Attribute cannot be empty");
            SM_ReturnSW(SW_WRONG_DATA);
          }

          Copy(SIZE_M, credential->attribute[P1 - 1], public.apdu.data);
          debugIndexedCLMessage("Initialised attribute", credential->attribute, P1 - 1);
          SM_ReturnSW(SW_NO_ERROR);

        case INS_ISSUE_COMMITMENT:
          debugMessage("INS_ISSUE_COMMITMENT");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }

          Copy(SIZE_STATZK, public.issue.nonce, public.apdu.data);
          debugNonce("Initialised nonce", public.issue.nonce);
          constructCommitment(credential, &masterSecret[0]);
          debugNumber("Returned U", public.apdu.data);
          SM_ReturnLa(SW_NO_ERROR, SIZE_N);

        case INS_ISSUE_COMMITMENT_PROOF:
          debugMessage("INS_ISSUE_COMMITMENT_PROOF");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }

          switch (P1) {
            case P1_PROOF_C:
              debugMessage("P1_COMMITMENT_PROOF_C");
              Copy(SIZE_H, public.apdu.data, session.issue.challenge);
              debugHash("Returned c", public.apdu.data);
              SM_ReturnLa(SW_NO_ERROR, SIZE_H);

            case P1_PROOF_VPRIMEHAT:
              debugMessage("P1_COMMITMENT_PROOF_VPRIMEHAT");
              Copy(SIZE_VPRIME_, public.apdu.data, session.issue.vPrimeHat);
              debugValue("Returned vPrimeHat", public.apdu.data, SIZE_VPRIME_);
              SM_ReturnLa(SW_NO_ERROR, SIZE_VPRIME_);

            case P1_PROOF_SHAT:
              debugMessage("P1_COMMITMENT_PROOF_SHAT");
              Copy(SIZE_S_, public.apdu.data, session.issue.sHat);
              debugValue("Returned s_A", public.apdu.data, SIZE_S_);
              SM_ReturnLa(SW_NO_ERROR, SIZE_S_);

            default:
              debugWarning("Unknown parameter");
              SM_ReturnSW(SW_WRONG_P1P2);
          }

        case INS_ISSUE_CHALLENGE:
          debugMessage("INS_ISSUE_CHALLENGE");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }

          Copy(SIZE_STATZK, public.apdu.data, credential->proof.nonce);
          debugNonce("Returned nonce", public.apdu.data);
          SM_ReturnLa(SW_NO_ERROR, SIZE_STATZK);

        case INS_ISSUE_SIGNATURE:
          debugMessage("INS_ISSUE_SIGNATURE");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }

          switch(P1) {
            case P1_SIGNATURE_A:
              debugMessage("P1_SIGNATURE_A");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_N, credential->signature.A, public.apdu.data);
              debugNumber("Initialised signature.A", credential->signature.A);
              break;

            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_E)) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_E, credential->signature.e, public.apdu.data);
              debugValue("Initialised signature.e", credential->signature.e, SIZE_E);
              break;

            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_V)) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              constructSignature(credential);
              debugValue("Initialised signature.v", credential->signature.v, SIZE_V);
              break;

            case P1_SIGNATURE_VERIFY:
              debugMessage("P1_SIGNATURE_VERIFY");
              if (!(APDU_wrapped || CheckCase(1))) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              verifySignature(credential, &masterSecret[0], &session.vfySig);
              debugMessage("Verified signature");
              break;

            default:
              debugWarning("Unknown parameter");
              SM_ReturnSW(SW_WRONG_P1P2);
          }
          SM_ReturnSW(SW_NO_ERROR);

        case INS_ISSUE_SIGNATURE_PROOF:
          debugMessage("INS_ISSUE_SIGNATURE_PROOF");
          if (!CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }

          switch(P1) {
            case P1_PROOF_C:
              debugMessage("P1_SIGNATURE_PROOF_C");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_H)) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_H, credential->proof.challenge, public.apdu.data);
              debugHash("Initialised c", credential->proof.challenge);
              break;

            case P1_PROOF_S_E:
              debugMessage("P1_SIGNATURE_PROOF_S_E");
              if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_N, credential->proof.response, public.apdu.data);
              debugNumber("Initialised s_e", credential->proof.response);
              break;

            case P1_PROOF_VERIFY:
              debugMessage("P1_SIGNATURE_PROOF_VERIFY");
              if (!(APDU_wrapped || CheckCase(1))) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              verifyProof(credential, &session.vfyPrf, &public.vfyPrf);
              debugMessage("Verified proof");
              break;

            default:
              debugWarning("Unknown parameter");
              SM_ReturnSW(SW_WRONG_P1P2);
          }
          SM_ReturnSW(SW_NO_ERROR);

        //////////////////////////////////////////////////////////////
        // Disclosure / Proving instructions                        //
        //////////////////////////////////////////////////////////////

        case INS_PROVE_CREDENTIAL:
          debugMessage("INS_PROVE_CREDENTIAL");
          if (!((APDU_wrapped || CheckCase(3)) &&
              (Lc == 2 + SIZE_H + 2 || Lc == 2 + SIZE_H + 2 + SIZE_TIMESTAMP || Lc == 2 + SIZE_H + 2 + SIZE_TIMESTAMP + SIZE_TERMINAL_ID))) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 != 0) {
            SM_ReturnSW(SW_WRONG_P1P2);
          }

          // Cleanup session
          ClearBytes(sizeof(VerificationSession), &(session.prove));

          // FIXME: should be done during auth.
          Copy(SIZE_TERMINAL_ID, terminal, public.verificationSetup.terminal);

          // Lookup the given credential ID and select it if it exists
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == public.verificationSetup.id) {
              credential = &credentials[i];

              if (verifySelection(credential, public.verificationSetup.selection) < 0) {
                credential = NULL;
                SM_ReturnSW(SW_WRONG_DATA);
              } else {
                session.prove.disclose = public.verificationSetup.selection;
              }

              if (CHV_required && !CHV_verified(credPIN)) {
                credential = NULL;
                SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
              }

              Copy(SIZE_H, public.prove.context, public.verificationSetup.context);
              debugHash("Initialised context", public.prove.context);

              // Create new log entry
              logEntry = (IRMALogEntry*) log_new_entry(&log);
              Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.verificationSetup.timestamp);
              Copy(SIZE_TERMINAL_ID, logEntry->terminal, terminal);
              logEntry->action = ACTION_PROVE;
              logEntry->credential = credential->id;
              logEntry->details.prove.selection = session.prove.disclose;

              SM_ReturnSW(SW_NO_ERROR);
            }
          }
          SM_ReturnSW(SW_REFERENCED_DATA_NOT_FOUND);

        case INS_PROVE_COMMITMENT:
          debugMessage("INS_PROVE_COMMITMENT");
          if (CHV_required && !CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }

          constructProof(credential, &masterSecret[0]);
          debugHash("Returned c", public.apdu.data);
          SM_ReturnLa(SW_NO_ERROR, SIZE_H);

        case INS_PROVE_SIGNATURE:
          debugMessage("INS_PROVE_SIGNATURE");
          if (CHV_required && !CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }

          switch(P1) {
            case P1_SIGNATURE_A:
              debugMessage("P1_SIGNATURE_A");
              if (!(APDU_wrapped || CheckCase(1))) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_N, public.apdu.data, public.prove.APrime);
              debugNumber("Returned A'", public.apdu.data);
              SM_ReturnLa(SW_NO_ERROR, SIZE_N);

            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!(APDU_wrapped || CheckCase(1))) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_E_, public.apdu.data, public.prove.eHat);
              debugValue("Returned e^", public.apdu.data, SIZE_E_);
              SM_ReturnLa(SW_NO_ERROR, SIZE_E_);

            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!(APDU_wrapped || CheckCase(1))) {
                SM_ReturnSW(SW_WRONG_LENGTH);
              }

              Copy(SIZE_V_, public.apdu.data, public.prove.vHat);
              debugValue("Returned v^", public.apdu.data, SIZE_V_);
              SM_ReturnLa(SW_NO_ERROR, SIZE_V_);

            default:
              debugWarning("Unknown parameter");
              SM_ReturnSW(SW_WRONG_P1P2);
          }

        case INS_PROVE_ATTRIBUTE:
          debugMessage("INS_PROVE_ATTRIBUTE");
          if (CHV_required && !CHV_verified(credPIN)) {
            SM_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            SM_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            SM_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1 > credential->size) {
            SM_ReturnSW(SW_WRONG_P1P2);
          }

          if (disclosed(P1)) {
            Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
            debugValue("Returned attribute", public.apdu.data, SIZE_M);
            SM_ReturnLa(SW_NO_ERROR, SIZE_M);
          } else {
            Copy(SIZE_M_, public.apdu.data, session.prove.mHat[P1]);
            debugValue("Returned response", public.apdu.data, SIZE_M_);
            SM_ReturnLa(SW_NO_ERROR, SIZE_M_);
          }


        //////////////////////////////////////////////////////////////
        // Administration instructions                              //
        //////////////////////////////////////////////////////////////

        case INS_ADMIN_CREDENTIALS:
          debugMessage("INS_ADMIN_CREDENTIALS");
          if (!CHV_verified(cardPIN)) {
            APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          for (i = 0; i < MAX_CRED; i++) {
            ((short*) public.apdu.data)[i] = credentials[i].id;
          }

          APDU_ReturnLa(SW_NO_ERROR, 2*MAX_CRED);
          break;

        case INS_ADMIN_CREDENTIAL:
          debugMessage("INS_ADMIN_CREDENTIAL");
          if (!CHV_verified(cardPIN)) {
            APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            APDU_ReturnSW(SW_WRONG_P1P2);
          }

          // Lookup the given credential ID and select it if it exists
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == P1P2) {
              credential = &credentials[i];
              APDU_ReturnSW(SW_NO_ERROR);
            }
          }
          APDU_ReturnSW(SW_REFERENCED_DATA_NOT_FOUND);
          break;

        case INS_ADMIN_ATTRIBUTE:
          debugMessage("INS_ADMIN_ATTRIBUTE");
          if (!CHV_verified(cardPIN)) {
            APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            APDU_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > credential->size) {
            APDU_ReturnSW(SW_WRONG_P1P2);
          }

          Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
          debugValue("Returned attribute", public.apdu.data, SIZE_M);
          APDU_ReturnLa(SW_NO_ERROR, SIZE_M);
          break;

        case INS_ADMIN_REMOVE:
          debugMessage("INS_ADMIN_REMOVE");
          if (!CHV_verified(cardPIN)) {
            APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            APDU_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(1)) ||
              ((APDU_wrapped || CheckCase(3)) && (Lc == SIZE_TIMESTAMP)))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            APDU_ReturnSW(SW_WRONG_P1P2);
          }

          // Verify the given credential ID and remove it if it matches
          if (credential->id == P1P2) {
            ClearCredential(credential);
            debugInteger("Removed credential", P1P2);

            // Create new log entry
            logEntry = (IRMALogEntry*) log_new_entry(&log);
            Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.apdu.data);
            Copy(SIZE_TERMINAL_ID, logEntry->terminal, terminal);
            logEntry->action = ACTION_REMOVE;
            logEntry->credential = P1P2;

            APDU_ReturnSW(SW_NO_ERROR);
          }

          APDU_ReturnSW(SW_REFERENCED_DATA_NOT_FOUND);
          break;

        case INS_ADMIN_FLAGS:
          debugMessage("INS_ADMIN_FLAGS");
          if (!CHV_verified(cardPIN)) {
            APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            APDU_ReturnSW(SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((APDU_wrapped || CheckCase(1)) ||
              ((APDU_wrapped || CheckCase(3)) && (Lc == sizeof(CredentialFlags))))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          if (Lc > 0) {
            credential->userFlags = public.adminFlags.user;
            debugValue("Updated flags", (ByteArray) credential->userFlags.protect, sizeof(CredentialFlags));
            APDU_ReturnSW(SW_NO_ERROR);
          } else {
            public.adminFlags.user = credential->userFlags;
            public.adminFlags.issuer = credential->issuerFlags;
            debugValue("Returned flags", public.apdu.data, 2 * sizeof(CredentialFlags));
            APDU_ReturnLa(SW_NO_ERROR, 2 * sizeof(CredentialFlags));
          }

        case INS_ADMIN_LOG:
          debugMessage("INS_ADMIN_LOG");
          if (!CHV_verified(cardPIN)) {
            APDU_ReturnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!(APDU_wrapped || CheckCase(1))) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          for (i = 0; i < 255 / sizeof(LogEntry); i++) {
            memcpy(public.apdu.data + i*sizeof(LogEntry), log_get_entry(&log, P1 + i), sizeof(LogEntry));
          }
          APDU_ReturnLa(SW_NO_ERROR, (255 / sizeof(LogEntry)) * sizeof(LogEntry));
          break;

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
      break;

    //////////////////////////////////////////////////////////////////
    // Unknown class byte (CLA)                                     //
    //////////////////////////////////////////////////////////////////

    default:
      debugWarning("Unknown class");
      debugInteger("CLA", CLA);
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      debugInteger("P2", P2);
      debugInteger("Lc", Lc);
      debugValue("data", public.apdu.data, Lc);
      APDU_ReturnSW(SW_CLA_NOT_SUPPORTED);
      break;
  }
}
