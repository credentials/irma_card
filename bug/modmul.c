/**
 * modmul.c
 *
 * Copyright (C) September 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

// Name everything "IRMAcard"
#pragma attribute("aid", "49 52 4D 41 63 61 72 64")
#pragma attribute("dir", "61 10 4f 6 69 64 65 6D 69 78 50 6 69 64 65 6D 69 78")

#include <ISO7816.h>
#include <multosarith.h>
#include <multoscomms.h>
#include <multoscrypto.h>
#include <string.h>

/********************************************************************/
/* Public segment (APDU buffer) variable declaration                */
/********************************************************************/
#pragma melpublic

unsigned char apdu[128];


/********************************************************************/
/* Static segment (application EEPROM memory) variable declarations */
/********************************************************************/
#pragma melstatic

unsigned char d[128];

unsigned char a[128] = { 0x10, 0x3A, 0x55, 0xAF, 0x74, 0x7C, 0xD2, 0xB1, 0x6C, 0xD3, 0x1E, 0xBE, 0x1C, 0x62, 0x2F, 0x3A, 0x25, 0x2B, 0x52, 0x87, 0xBD, 0x6D, 0xCA, 0x0E, 0x04, 0x9D, 0x02, 0x5D, 0x5D, 0x13, 0xE4, 0x02, 0xD0, 0x70, 0x84, 0x7A, 0x8A, 0x52, 0x2B, 0xB6, 0xAD, 0x58, 0xBF, 0xAB, 0xE0, 0xB4, 0x89, 0x07, 0x03, 0xEA, 0xCA, 0x91, 0x05, 0xAF, 0xE9, 0x51, 0xB1, 0xBC, 0xD4, 0x81, 0xC0, 0x40, 0xD0, 0xC1, 0x18, 0xE1, 0x84, 0xC3, 0x5E, 0x98, 0x02, 0x51, 0x3B, 0xB6, 0xE0, 0xC7, 0xDF, 0xF0, 0xF2, 0x71, 0x2D, 0x4C, 0xDE, 0xAF, 0x2B, 0x64, 0xD9, 0x19, 0x6C, 0x41, 0xDA, 0x3B, 0xDC, 0x5C, 0x97, 0x81, 0x7A, 0xE9, 0x63, 0x6F, 0x9A, 0x5C, 0x6B, 0x2A, 0x0C, 0xF9, 0xFE, 0x1F, 0x56, 0x90, 0x53, 0x49, 0x4E, 0x6E, 0xC1, 0xDF, 0x6E, 0x24, 0xB2, 0xE4, 0x2F, 0x39, 0xC4, 0xA0, 0x02, 0xD5, 0x2E, 0xBE };

unsigned char b[128] = { 0x4D, 0x57, 0xF5, 0x2B, 0xAD, 0xF6, 0xF1, 0xB1, 0xE1, 0xC1, 0xF4, 0x6A, 0x4F, 0x5B, 0xFF, 0xDA, 0xE9, 0x7F, 0x56, 0x8B, 0x5C, 0xDF, 0x73, 0x77, 0x99, 0x12, 0xC8, 0xA6, 0x7F, 0x4B, 0x6F, 0x59, 0x1E, 0x24, 0xFA, 0x61, 0xBA, 0x68, 0x8E, 0xE9, 0x1F, 0xBF, 0x9A, 0xEC, 0x3A, 0x4B, 0x0C, 0xD6, 0x8F, 0xCE, 0x0F, 0x10, 0xB3, 0x82, 0x06, 0xCC, 0x93, 0xD6, 0xEC, 0xB8, 0xF9, 0x94, 0xB9, 0x42, 0xC8, 0x88, 0xFA, 0x34, 0x5D, 0x5A, 0x53, 0xF8, 0xEF, 0xD7, 0x8E, 0xB5, 0xC9, 0xF3, 0x50, 0xD3, 0x08, 0x28, 0xA4, 0x3B, 0xF1, 0xAD, 0x54, 0x5A, 0xAC, 0x27, 0x3A, 0x03, 0x36, 0x3A, 0xCF, 0xF1, 0x66, 0x48, 0x91, 0xA1, 0xAB, 0x5E, 0x92, 0xD2, 0x24, 0x4F, 0x82, 0xE2, 0xFC, 0xE7, 0x8C, 0x80, 0xA8, 0x4E, 0xEA, 0xA8, 0x33, 0xE5, 0xF2, 0x33, 0x92, 0x4E, 0x4E, 0xE8, 0xD5, 0xE0, 0xB9, 0x8F };

unsigned char c[128] = { 0x00, 0x28, 0xC5, 0x09, 0x07, 0xA6, 0x18, 0x06, 0x7A, 0x21, 0x21, 0xE1, 0xA0, 0xF5, 0x0B, 0xE1, 0x29, 0x11, 0x3B, 0x3D, 0x27, 0x3E, 0x53, 0x62, 0xC6, 0xDC, 0x26, 0x76, 0x5B, 0xFA, 0xDC, 0xEA, 0x14, 0xC7, 0xDE, 0x8E, 0x45, 0x9B, 0x9E, 0x43, 0xF3, 0xDF, 0x9E, 0x32, 0xA1, 0x78, 0x85, 0xEA, 0x9B, 0xED, 0xF2, 0x99, 0xB4, 0x09, 0xFA, 0x51, 0x7C, 0x57, 0x3E, 0x19, 0xA7, 0xE0, 0x82, 0xB4, 0x1D, 0x97, 0x30, 0xAF, 0xCA, 0xA0, 0xC4, 0x7C, 0xAA, 0x07, 0xEB, 0x42, 0x63, 0xBD, 0x68, 0x34, 0xBE, 0x94, 0x6A, 0xB9, 0xD7, 0x4C, 0x60, 0xD6, 0x8A, 0x5D, 0x3D, 0xB3, 0x8A, 0xDE, 0xAB, 0xA1, 0x4C, 0x22, 0xC7, 0x4D, 0xCF, 0x72, 0x1D, 0x70, 0x6F, 0x4D, 0x12, 0x93, 0xC0, 0x35, 0x0D, 0xB2, 0x8C, 0xEF, 0xF2, 0x5E, 0xC5, 0x8F, 0x6A, 0xBA, 0x36, 0xF8, 0xF0, 0xBC, 0xA8, 0x21, 0xD3, 0x7A };

unsigned char n[128] = { 0x88, 0xCC, 0x7B, 0xD5, 0xEA, 0xA3, 0x90, 0x06, 0xA6, 0x3D, 0x1D, 0xBA, 0x18, 0xBD, 0xAF, 0x00, 0x13, 0x07, 0x25, 0x59, 0x7A, 0x0A, 0x46, 0xF0, 0xBA, 0xCC, 0xEF, 0x16, 0x39, 0x52, 0x83, 0x3B, 0xCB, 0xDD, 0x40, 0x70, 0x28, 0x1C, 0xC0, 0x42, 0xB4, 0x25, 0x54, 0x88, 0xD0, 0xE2, 0x60, 0xB4, 0xD4, 0x8A, 0x31, 0xD9, 0x4B, 0xCA, 0x67, 0xC8, 0x54, 0x73, 0x7D, 0x37, 0x89, 0x0C, 0x7B, 0x21, 0x18, 0x4A, 0x05, 0x3C, 0xD5, 0x79, 0x17, 0x66, 0x81, 0x09, 0x3A, 0xB0, 0xEF, 0x0B, 0x8D, 0xB9, 0x4A, 0xFD, 0x18, 0x12, 0xA7, 0x8E, 0x1E, 0x62, 0xAE, 0x94, 0x26, 0x51, 0xBB, 0x90, 0x9E, 0x6F, 0x5E, 0x5A, 0x2C, 0xEF, 0x60, 0x04, 0x94, 0x6C, 0xCA, 0x3F, 0x66, 0xEC, 0x21, 0xCB, 0x9A, 0xC0, 0x1F, 0xF9, 0xD3, 0xE8, 0x8F, 0x19, 0xAC, 0x27, 0xFC, 0x77, 0xB1, 0x90, 0x3F, 0x14, 0x10, 0x49 };

/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
    
  // Process the instruction
  switch (INS) {

    case 0xFF:
      COPYN(128, d, a);
      ModularMultiplication(128, d, b, n);
      COPYN(128, apdu, d);
      if (memcmp(d, c, 128) == 0) {
        ExitSWLa(0x9000, 128);
      } else {
        ExitSWLa(0x6E00, 128);
      }
      break;

    //////////////////////////////////////////////////////////////
    // Unknown instruction byte (INS)                           //
    //////////////////////////////////////////////////////////////

    default:
      ExitSW(ISO7816_SW_INS_NOT_SUPPORTED);
  }
}