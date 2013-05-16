/**
 * encoding.c
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope t_ it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, July 2011.
 */

#include "encoding.h"

#include "debug.h"
#include "memory.h"

/********************************************************************/
/* Helper functions                                                 */
/********************************************************************/

/**
 * Encode the given length using ASN.1 DER formatting.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * @param length value to be encoded
 * @param buffer to store the DER formatted length
 * @param offset in front of which the length should be stored
 * @return the offset of the encoded length in the buffer
 */
int asn1_encode_length(int length, unsigned char *buffer, int offset) {
  unsigned char prefix = 0x80;

  // Use the short form when the length is between 0 and 127
  if (length < 0x80) {
    buffer[--offset] = (unsigned char) length;

  // Use the long form when the length is 128 or greater
  } else {
    while (length > 0) {
      buffer[--offset] = (unsigned char) length;
      length >>= 8;
      prefix++;
    }

    buffer[--offset] = prefix;
  }

  return offset;
}

/**
 * Encode the given number (of length bytes) into an ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * @param number the value to be encoded
 * @param length of the value stored in number
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
int asn1_encode_int(unsigned char *number, int length,
                    unsigned char *buffer, int offset) {
  int skip = 0;

  // Determine the number of zero (0x00) bytes to skip
  while(number[skip] == 0x00 && skip < length - 1) {
    skip++;
  }

  // Store the value
  length -= skip;
  offset -= length;
  CopyBytes(length, buffer + offset, number + skip);

  // If needed, add a 0x00 byte for correct two-complements encoding
  if ((buffer[offset] & 0x80) != 0x00) {
    debugMessage("Correcting value for two-complements encoding");
    buffer[--offset] = 0x00;
    length++;
  }

  // Store the length
  offset = asn1_encode_length(length, buffer, offset);

  // Store the tag
  buffer[--offset] = 0x02; // ASN.1 INTEGER

  return offset;
}

/**
 * Encode the given sequence (of length bytes) into an ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * Note: In order for the result to be a valid DER object, the value for
 * this sequence must be in the buffer at the given offset.
 *
 * @param length of the sequence stored in the buffer (in bytes)
 * @param size of the sequence stored in the buffer (number of items)
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
int asn1_encode_seq(int length, int size, unsigned char *buffer, int offset) {
  // Store the length
  offset = asn1_encode_length(length, buffer, offset);

  // Store the tag
  buffer[--offset] = 0x30; // ASN.1 SEQUENCE

  return offset;
}

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
int asn1_decode_length(const unsigned char *buffer, unsigned int *offset) {
  unsigned char prefix = buffer[(*offset)++];

  if (prefix < 0x80) {
    return prefix;
  } else {
    switch (prefix & 0x7F) {
      case 1:
        return buffer[(*offset)++];
      case 2:
        return buffer[(*offset)++] << 8 | buffer[(*offset)++];
      default:
       return -1;
    }
  }
}