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

#define STATE_PROVE_CREDENTIAL 0x0100

#define matchState(x) \
  (state != (x))

#define checkState(x) \
  if (!matchState(x)) { APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED); }

#define nextState() \
  state <<= 1

// Secure messaging: session parameters
SM_parameters tunnel;
Terminal terminal;

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

// Logging
Log log;
IRMALogEntry *logEntry;

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

void processIssuance(void) {
  unsigned char flag, i;

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

    state = STATE_ISSUE_SETUP;

    APDU_return();

  // All other issuance commands
  } else {

    // A credential should be selected for issuance
    if (credential == NULL || (state & STATE_ISSUE_CREDENTIAL) == 0) {
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

void processVerification(void) {
  unsigned char i;

  // Verification requires the terminal to be authenticated.
  /* Implicit due to the fact that we've got a secure tunnel. */

  // Special case: start verification
  if (INS == INS_PROVE_CREDENTIAL) {
    debugMessage("INS_PROVE_CREDENTIAL");
    APDU_checkLength(sizeof(VerificationSetup));

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

    APDU_return();

  // All other verification commands
  } else {

    // A credential should be selected for verification
    if (credential == NULL || (state & STATE_PROVE_CREDENTIAL) == 0) {
      APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
    }

    switch (INS) {
      case INS_PROVE_COMMITMENT:
        debugMessage("INS_PROVE_COMMITMENT");
        APDU_checkLength(SIZE_STATZK);
        constructProof(credential, &masterSecret[0]);
        debugHash("Returned c", public.apdu.data);
        APDU_returnLa(SIZE_H);

      case INS_PROVE_SIGNATURE:
        debugMessage("INS_PROVE_SIGNATURE");

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
        if (!(APDU_wrapped || CheckCase(1))) {
          APDU_returnSW(SW_WRONG_LENGTH);
        }
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
