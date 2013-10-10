/**
 * verification.c
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

#include "verification.h"

#include "debug.h"
#include "math.h"
#include "memory.h"
#include "random.h"
#include "sizes.h"
#include "types.h"
#include "utils.h"

extern PublicData public;
extern SessionData session;
extern DebugData debug;

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

/**
 * Select the attributes to be disclosed.
 *
 * @param selection bitmask of attributes to be disclosed.
 */
int verifySelection(Credential *credential, unsigned int selection) {

  // Never disclose the master secret.
  if ((selection & 0x0001) != 0) {
    debugError("selectAttributes(): master secret cannot be disclosed");
    return VERIFICATION_ERROR_MASTER_SECRET;
  }

  // Always disclose the expiry attribute.
  if ((selection & 0x0002) == 0) {
    debugError("selectAttributes(): expiry attribute must be disclosed");
    return VERIFICATION_ERROR_EXPIRY;
  }

  // Do not allow non-existant attributes.
  if ((selection & (0xFFFF << credential->size + 1)) != 0) {
    debugError("selectAttributes(): selection contains non-existant attributes");
    return VERIFICATION_ERROR_NOT_FOUND;
  }

  debugInteger("Attribute disclosure selection", selection);
  return VERIFICATION_SELECTION_VALID;
}

unsigned int realSize(unsigned char *buffer, unsigned int size) {
  while (*buffer == 0) {
    buffer++;
    size--;
  }

  return size;
}

/**
 * Construct a proof.
 */
void constructProof(Credential *credential, unsigned char *masterSecret) {
  unsigned char i;
  unsigned int rA_size;
  unsigned int rA_offset;
  rA_size = realSize(credential->signature.v, SIZE_V) - 1 - realSize(credential->signature.e, SIZE_E);
  if (rA_size > SIZE_R_A) { rA_size = SIZE_R_A; }
  rA_offset = SIZE_R_A - rA_size;

  // Generate random values for m~[i], e~, v~ and rA
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      // IMPORTANT: Correction to the length of mTilde to prevent overflows
      RandomBits(session.prove.mHat[i], LENGTH_M_ - 1);
      Copy(SIZE_M_, debug.mTilde[i], session.prove.mHat[i]);
    }
  }
  debugValues("mTilde", session.prove.mHat, SIZE_M_, SIZE_L);
  // IMPORTANT: Correction to the length of eTilde to prevent overflows
  RandomBits(public.prove.eHat, LENGTH_E_ - 1);
  Copy(SIZE_E_, debug.eTilde, public.prove.eHat);
  debugValue("eTilde", public.prove.eHat, SIZE_E_);
  // IMPORTANT: Correction to the length of vTilde to prevent overflows
  FakeRandomBits(public.prove.vHat, LENGTH_V_ - 1);
  for (i = 0; i < 0; i++) {
    public.prove.vHat[i] = 0x00;
  }
  Copy(SIZE_V_, debug.vTilde, public.prove.vHat);
  debugValue("vTilde", public.prove.vHat, SIZE_V_);
  // IMPORTANT: Correction to the length of rA to prevent negative values
  FakeRandomBits(public.prove.rA + rA_offset, rA_size * 8 - 1);
  for (i = 0; i < rA_offset; i++) {
    public.prove.rA[i] = 0x00; // Set first byte(s) of rA, since it's not set by RandomBits command
  }
  Copy(SIZE_R_A, debug.rA, public.prove.rA);
  debugValue("rA", public.prove.rA, SIZE_R_A);

  // Compute A' = A * S^r_A
  ModExpSpecial(credential, SIZE_R_A, public.prove.rA, public.prove.APrime, public.prove.buffer.number[0]);
  debugValue("A' = S^r_A mod n", public.prove.APrime, SIZE_N);
  ModMul(SIZE_N, public.prove.APrime, credential->signature.A, credential->issuerKey.n);
  debugValue("A' = A' * A mod n", public.prove.APrime, SIZE_N);

  // Compute ZTilde = A'^eTilde * S^vTilde * (R[i]^mTilde[i] foreach i not in D)
  ModExpSpecial(credential, SIZE_V_, public.prove.vHat, public.prove.buffer.number[0], public.prove.buffer.number[1]);
  debugValue("ZTilde = S^vTilde", public.prove.buffer.number[0], SIZE_N);
  Copy(SIZE_N, debug.SvTilde, public.prove.buffer.number[0]);
  ModExp(SIZE_E_, SIZE_N, public.prove.eHat, credential->issuerKey.n, public.prove.APrime, public.prove.buffer.number[1]);
  debugValue("buffer = A'^eTilde", public.prove.buffer.number[1], SIZE_N);
  Copy(SIZE_N, debug.AeTilde, public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);
  debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
  Copy(SIZE_N, debug.SvAeTilde, public.prove.buffer.number[0]);
  Clear(SIZE_N, debug.exp[0]);
  Clear(SIZE_N, debug.exp[1]);
  Clear(SIZE_N, debug.exp[2]);
  Clear(SIZE_N, debug.exp[3]);
  Clear(SIZE_N, debug.exp[4]);
  Clear(SIZE_N, debug.exp[5]);
  Clear(SIZE_N, debug.mul[0]);
  Clear(SIZE_N, debug.mul[1]);
  Clear(SIZE_N, debug.mul[2]);
  Clear(SIZE_N, debug.mul[3]);
  Clear(SIZE_N, debug.mul[4]);
  Clear(SIZE_N, debug.mul[5]);
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      ModExp(SIZE_M_, SIZE_N, session.prove.mHat[i], credential->issuerKey.n, credential->issuerKey.R[i], public.prove.buffer.number[1]);
      Copy(SIZE_N, debug.exp[i], public.prove.buffer.number[1]);
      debugValue("R_i^m_i", public.prove.buffer.number[1], SIZE_N);
      ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);
      Copy(SIZE_N, debug.mul[i], public.prove.buffer.number[0]);
      debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
    }
  }
  Copy(SIZE_N, debug.ZTilde, public.prove.buffer.number[0]);

  // Compute challenge c = H(context | A' | ZTilde | nonce)
  public.prove.list[0].data = public.prove.context;
  public.prove.list[0].size = SIZE_H;
  public.prove.list[1].data = public.prove.APrime;
  public.prove.list[1].size = SIZE_N;
  public.prove.list[2].data = public.prove.buffer.number[0];
  public.prove.list[2].size = SIZE_N;
  public.prove.list[3].data = public.prove.apdu.nonce;
  public.prove.list[3].size = SIZE_STATZK;
  ComputeHash(public.prove.list, 4, public.prove.apdu.challenge, public.prove.buffer.data, SIZE_BUFFER_C1);
  debugValue("c", public.prove.apdu.challenge, SIZE_H);

  crypto_compute_ePrime(); // Compute e' = e - 2^(l_e' - 1)
  debugValue("e' = e - 2^(l_e' - 1)", credential->signature.e + SIZE_E - SIZE_EPRIME, SIZE_EPRIME);

  crypto_compute_eHat(); // Compute e^ = e~ + c e'
  debugValue("e^ = e~ + c*e'", public.prove.eHat, SIZE_E_);

  crypto_compute_vPrime(); // Compute v' = v - e r_A
  debugValue("v' = v - e*r_A", public.prove.buffer.data, SIZE_V);

  crypto_compute_vHat(); // Compute v^ = v~ + c v'
  debugValue("vHat", public.prove.vHat, SIZE_V_);

  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_compute_mHat(i); // Compute m_i^ = m_i~ + c m_i
    }
  }
  debugValues("mHat", session.prove.mHat, SIZE_M_, SIZE_L);

  // return eHat, vHat, mHat[i], c, A'
}
