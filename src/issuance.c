/**
 * issuance.c
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

#include "issuance.h"

#include "debug.h"
#include "math.h"
#include "memory.h"
#include "random.h"
#include "sizes.h"
#include "types.h"
#include "types.debug.h"
#include "utils.h"

extern PublicData public;
extern SessionData session;

/********************************************************************/
/* Issuing functions                                                */
/********************************************************************/

/**
 * Construct a commitment (round 1)
 *
 * @param issuerKey (S, R, n)
 * @param proof (nonce, context)
 * @param masterSecret
 * @param number for U
 * @param number for UTilde
 * @param vPrime in signature.v + SIZE_V - SIZE_VPRIME
 * @param vPrimeTilde in vHat
 * @param vPrimeHat in vHat
 * @param mTilde[0] in mHat[0]
 * @param s_A in mHat[0]
 * @param nonce
 * @param buffer for hash of SIZE_BUFFER_C1
 * @param (buffer for SpecialModularExponentiation of SIZE_N)
 */
void constructCommitment(Credential *credential, unsigned char *masterSecret) {

  // Generate random vPrime
  RandomBits(session.issue.vPrime, LENGTH_VPRIME);
  debugValue("vPrime", session.issue.vPrime, SIZE_VPRIME);

  // Compute U = S^vPrime * R[0]^m[0] mod n
  ModExpSpecial(credential, SIZE_VPRIME, session.issue.vPrime, public.issue.U,
    public.issue.buffer.number[0]);
  debugNumber("U = S^vPrime mod n", public.issue.U);
  ModExpSecure(SIZE_M, SIZE_N, masterSecret, credential->issuerKey.n,
    credential->issuerKey.R[0], public.issue.buffer.number[0]);
  debugNumber("buffer = R[0]^m[0] mod n", public.issue.buffer.number[0]);
  ModMul(SIZE_N, public.issue.U, public.issue.buffer.number[0],
    credential->issuerKey.n);
  debugNumber("U = U * buffer mod n", public.issue.U);

  // Compute P1:
  // - Generate random vPrimeTilde, mTilde[0]
  RandomBits(session.issue.vPrimeHat, LENGTH_VPRIME_);
  debugValue("vPrimeTilde", session.issue.vPrimeHat, SIZE_VPRIME_);
  RandomBits(session.issue.sHat, LENGTH_S_);
  debugValue("sTilde", session.issue.sHat, SIZE_S_);

  // - Compute UTilde = S^vPrimeTilde * R[0]^sTilde mod n
  ModExpSpecial(credential, SIZE_VPRIME_, session.issue.vPrimeHat,
    public.issue.buffer.number[0], public.issue.buffer.number[1]);
  debugNumber("UTilde = S^vPrimeTilde mod n", public.issue.buffer.number[0]);
  ModExp(SIZE_S_, SIZE_N, session.issue.sHat, credential->issuerKey.n,
    credential->issuerKey.R[0], public.issue.buffer.number[1]);
  debugNumber("buffer = R[0]^sTilde mod n", public.issue.buffer.number[1]);
  ModMul(SIZE_N, public.issue.buffer.number[0],
    public.issue.buffer.number[1], credential->issuerKey.n);
  debugNumber("UTilde = UTilde * buffer mod n", public.issue.buffer.number[0]);

  // - Compute challenge c = H(context | U | UTilde | nonce)
  public.issue.list[0].data = credential->proof.context;
  public.issue.list[0].size = SIZE_H;
  public.issue.list[1].data = public.issue.U;
  public.issue.list[1].size = SIZE_N;
  public.issue.list[2].data = public.issue.buffer.number[0];
  public.issue.list[2].size = SIZE_N;
  public.issue.list[3].data = public.issue.nonce;
  public.issue.list[3].size = SIZE_STATZK;
  ComputeHash(public.issue.list, 4, session.issue.challenge,
    public.issue.buffer.data, SIZE_BUFFER_C1);
  debugHash("c", session.issue.challenge);

  // - Compute response vPrimeHat = vPrimeTilde + c * vPrime
  crypto_compute_vPrimeHat();
  debugValue("vPrimeHat", session.issue.vPrimeHat, SIZE_VPRIME_);

  // - Compute response sHat = sTilde + c * s
  crypto_compute_sHat();
  debugValue("sHat", session.issue.sHat, SIZE_S_);

  // Generate random n_2
  RandomBits(credential->proof.nonce, LENGTH_STATZK);
  debugNonce("nonce", credential->proof.nonce);
}

/**
 * Construct the signature (round 3, part 1)
 *
 *   A, e, v = v' + v''
 *
 * @param v' in session.issue.vPrime of size SIZE_VPRIME
 * @param v'' in public.apdu.data of size SIZE_V
 * @param signature (A, e, v) in credential->signature
 */
void constructSignature(Credential *credential) {
  unsigned char flag;

  // Compute v = v' + v'' using add with carry
  debugValue("v'", session.issue.vPrime, SIZE_VPRIME);
  debugValue("v''", public.apdu.data, SIZE_V);
  __push(credential->signature.v + SIZE_V/2);
  __push(BLOCKCAST(1 + SIZE_V/2)(session.issue.vPrime + SIZE_VPRIME - SIZE_V/2 - 1));
  __push(BLOCKCAST(1 + SIZE_V/2)(public.apdu.data + SIZE_V/2));
  __code(ADDN, 1 + SIZE_V/2);
  __code(POPN, 1 + SIZE_V/2);
  __code(STOREI, 1 + SIZE_V/2);

  IfCarry(
    debugMessage("Addition with carry, adding 1");
    __code(INCN, public.apdu.data, SIZE_V/2);
  );

  // First push some zero's to compensate for the size difference
  __push(credential->signature.v);
  __code(PUSHZ, SIZE_V - SIZE_VPRIME);
  __push(BLOCKCAST(SIZE_VPRIME - SIZE_V/2 - 1)(session.issue.vPrime));
  __push(BLOCKCAST(SIZE_V/2)(public.apdu.data));
  __code(ADDN, SIZE_V/2);
  __code(POPN, SIZE_V/2);
  __code(STOREI, SIZE_V/2);
  debugValue("v = v' + v''", credential->signature.v, SIZE_V);
}

/**
 * (OPTIONAL) Verify the signature (round 3, part 2)
 *
 *   Z =?= A^e * S^v * R where R = R[i]^m[i] forall i
 *
 * @param signature (A, e, v) in credential->signature
 * @param issuerKey (Z, S, R, n) in credential->issuerKey
 * @param attributes (m[0]...m[l]) in credential->attribute
 * @param masterSecret
 */
int verifySignature(Credential *credential, unsigned char *masterSecret, CLSignatureVerification *session) {
  unsigned char i;

  // Clear the memory before starting computations
  ClearBytes(sizeof(CLSignatureVerification), session);

  // Compute Z' = S^v mod n
  ModExpSpecial(credential, SIZE_V, credential->signature.v, session->ZPrime, session->buffer);
  debugNumber("Z' = S^v mod n", session->buffer);

  // Compute Z' = S^v * A^e mod n
  ModExp(SIZE_E, SIZE_N, credential->signature.e, credential->issuerKey.n, credential->signature.A, session->buffer);
  debugNumber("buffer = A^e mod n", session->buffer);
  ModMul(SIZE_N, session->ZPrime, session->buffer, credential->issuerKey.n);
  debugNumber("Z' = Z' * buffer mod n", session->ZPrime);

  // Compute Z' = S^v * A^e * R[i]^m[i] mod n forall i
  ModExpSecure(SIZE_M, SIZE_N, masterSecret, credential->issuerKey.n, credential->issuerKey.R[0], session->buffer);
  debugNumber("buffer = R[0]^ms mod n", session->buffer);
  ModMul(SIZE_N, session->ZPrime, session->buffer, credential->issuerKey.n);
  debugNumber("Z' = Z' * buffer mod n", session->ZPrime);
  for (i = 0; i < credential->size; i++) {
    ModExp(SIZE_M, SIZE_N, credential->attribute[i], credential->issuerKey.n, credential->issuerKey.R[i + 1], session->buffer);
    debugNumber("buffer = R[i]^m[i] mod n", session->buffer);
    ModMul(SIZE_N, session->ZPrime, session->buffer, credential->issuerKey.n);
    debugNumber("Z' = Z' * buffer mod n", session->ZPrime);
  }

  // Verify Z =?= Z'
  if (NotEqual(SIZE_N, credential->issuerKey.Z, session->ZPrime)) {
    // TODO: clear already stored things?
    debugError("verifySignature(): verification of signature failed");
    return ISSUANCE_ERROR_SIGNATURE_INVALID;
  } else {
    return ISSUANCE_SIGNATURE_VALID;
  }
}

/**
 * (OPTIONAL) Verify the proof (round 3, part 3)
 *
 *   c =?= H(context, A^e, A, nonce, A^(c + s_e * e))
 *
 * @param signature (A, e) in credential->signature
 * @param issuerKey (n) in credential->issuerKey
 * @param proof (nonce, context, challenge, response) in credential->proof
 */
int verifyProof(Credential *credential, IssuanceProofSession *session, IssuanceProofVerification *public) {

  // Clear the memory before starting computations
  ClearBytes(sizeof(IssuanceProofVerification), public);
  ClearBytes(sizeof(IssuanceProofSession), session);

  // Compute Q = A^e mod n
  ModExp(SIZE_E, SIZE_N, credential->signature.e, credential->issuerKey.n, credential->signature.A, session->Q);
  debugNumber("Q = A^e mod n", session->Q);

  // Compute AHat = A^(c + s_e * e) = Q^s_e * A^c mod n
  ModExp(SIZE_N, SIZE_N, credential->proof.response, credential->issuerKey.n, session->Q, public->buffer);
  debugNumber("buffer = Q^s_e mod n", public->buffer);
  ModExp(SIZE_H, SIZE_N, credential->proof.challenge, credential->issuerKey.n, credential->signature.A, session->AHat);
  debugNumber("AHat = A^c mod n", session->AHat);
  ModMul(SIZE_N, session->AHat, public->buffer, credential->issuerKey.n);
  debugNumber("AHat = AHat * buffer", session->AHat);

  // Compute challenge c' = H(context | Q | A | nonce | AHat)
  session->list[0].data = credential->proof.context;
  session->list[0].size = SIZE_H;
  session->list[1].data = session->Q;
  session->list[1].size = SIZE_N;
  session->list[2].data = credential->signature.A;
  session->list[2].size = SIZE_N;
  session->list[3].data = credential->proof.nonce;
  session->list[3].size = SIZE_STATZK;
  session->list[4].data = session->AHat;
  session->list[4].size = SIZE_N;
  ComputeHash(session->list, 5, session->challenge, public->buffer, SIZE_BUFFER_C2);
  debugHash("c'", session->challenge);

  // Verify c =?= c'
  if (NotEqual(SIZE_H, credential->proof.challenge, session->challenge)) {
    // TODO: clear already stored things?
    debugError("verifyProof(): verification of P2 failed");
    return ISSUANCE_ERROR_PROOF_INVALID;
  } else {
    return ISSUANCE_PROOF_VALID;
  }
}

int issuance_checkPublicKey(Credential *credential) {
  unsigned char i;

  IfZeroBytes(SIZE_N, credential->issuerKey.n, return ISSUANCE_PUBLIC_KEY_INCOMPLETE);
  IfZeroBytes(SIZE_N, credential->issuerKey.S, return ISSUANCE_PUBLIC_KEY_INCOMPLETE);
  IfZeroBytes(SIZE_N, credential->issuerKey.Z, return ISSUANCE_PUBLIC_KEY_INCOMPLETE);
  for (i = 0; i < credential->size + 1; i++) {
    IfZeroBytes(SIZE_N, credential->issuerKey.R[i], return ISSUANCE_PUBLIC_KEY_INCOMPLETE);
  }

  return ISSUANCE_PUBLIC_KEY_COMPLETE;
}

int issuance_checkAttributes(Credential *credential) {
  unsigned char i;

  for (i = 0; i < credential->size; i++) {
    IfZeroBytes(SIZE_N, credential->attribute[i], return ISSUANCE_ATTRIBUTES_INCOMPLETE);
  }

  return ISSUANCE_ATTRIBUTES_COMPLETE;
}

int issuance_checkSignature(Credential *credential) {
  IfZeroBytes(SIZE_N, credential->signature.A, return ISSUANCE_SIGNATURE_INCOMPLETE);
  IfZeroBytes(SIZE_E, credential->signature.e, return ISSUANCE_SIGNATURE_INCOMPLETE);
  IfZeroBytes(SIZE_V, credential->signature.v, return ISSUANCE_SIGNATURE_INCOMPLETE);

  IfZeroBytes(SIZE_H, credential->proof.challenge, return ISSUANCE_SIGNATURE_INCOMPLETE);
  IfZeroBytes(SIZE_H, credential->proof.context, return ISSUANCE_SIGNATURE_INCOMPLETE);
  IfZeroBytes(SIZE_STATZK, credential->proof.nonce, return ISSUANCE_SIGNATURE_INCOMPLETE);
  IfZeroBytes(SIZE_N, credential->proof.response, return ISSUANCE_SIGNATURE_INCOMPLETE);

  return ISSUANCE_SIGNATURE_COMPLETE;
}
