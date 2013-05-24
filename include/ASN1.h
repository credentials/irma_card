/**
 * ASN1.h
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

#ifndef __ASN1_H
#define __ASN1_H

/**
 * TLV data type which contains the tag, length and value, as well as a
 * pointer to the raw data and the size in bytes of the TLV object.
 */
typedef struct {
  unsigned int tag;
  unsigned int length;
  unsigned char *value;
  unsigned char *data;
  unsigned int bytes;
} TLV;

/**
 * Encode the given number (of length bytes) into an ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * @param number_bytes length of the value stored in number
 * @param number the value to be encoded
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
unsigned int ASN1_encode_int(unsigned int number_bytes, const unsigned char *number, unsigned char *buffer, unsigned int offset);

/**
 * Encode the given sequence (of length bytes) into an ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * Note: In order for the result to be a valid DER object, the value for
 * this sequence must be in the buffer at the given offset.
 *
 * @param length of the sequence stored in the buffer
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
unsigned int ASN1_encode_seq(unsigned int length, unsigned char *buffer, unsigned int offset);

int ASN1_decode_tlv(TLV *tlv, const unsigned char *buffer, unsigned int *offset);

int ASN1_decode_tag(unsigned int *tag, const unsigned char *buffer, unsigned int *offset);

/**
 * Decode the length from a ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * Note: this function updates the offset value while decoding the
 * length, hence in the end the offset points to the value of the ASN.1
 * encoded DER object.
 *
 * @param buffer containing the DER object
 * @param offset in the buffer at which the length should be read
 * @return the length of the DER object in the buffer
 */
int ASN1_decode_length(unsigned int *length, const unsigned char *buffer, unsigned int *offset);

int ASN1_find_tlv(TLV *tlv, unsigned int tag, const unsigned char *buffer, unsigned int offset);

#define ASN1_constructed_tlv(tlv) (((tlv)->tag & 0x2000) != 0)

#endif // __ASN1_H
