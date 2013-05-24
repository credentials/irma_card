/**
 * ASN1.c
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

#include "ASN1.h"

#include "debug.h"
#include "memory.h"

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
int ASN1_encode_length(int length, unsigned char *buffer, int offset) {
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
unsigned int ASN1_encode_int(unsigned int number_bytes, const unsigned char *number,
                    unsigned char *buffer, unsigned int offset) {
  int skip = 0;

  // Determine the number of zero (0x00) bytes to skip
  while(number[skip] == 0x00 && skip < number_bytes - 1) {
    skip++;
  }

  // Store the value
  number_bytes -= skip;
  offset -= number_bytes;
  CopyBytes(number_bytes, buffer + offset, number + skip);

  // If needed, add a 0x00 byte for correct two-complements encoding
  if ((buffer[offset] & 0x80) != 0x00) {
    debugMessage("Correcting value for two-complements encoding");
    buffer[--offset] = 0x00;
    number_bytes++;
  }

  // Store the length
  offset = ASN1_encode_length(number_bytes, buffer, offset);

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
unsigned int ASN1_encode_seq(unsigned int length, unsigned char *buffer, unsigned int offset) {
  // Store the length
  offset = ASN1_encode_length(length, buffer, offset);

  // Store the tag
  buffer[--offset] = 0x30; // ASN.1 SEQUENCE

  return offset;
}

int ASN1_decode_tlv(TLV *tlv, const unsigned char *buffer, unsigned int *offset) {
  // Read the tag from the buffer
  if (ASN1_decode_tag(&(tlv->tag), buffer, offset) < 0) {
    return -1;
  }

  // Read the length from the buffer
  if (ASN1_decode_length(&(tlv->length), buffer, offset) < 0) {
    return -1;
  }

  // Read the value from the buffer
  tlv->value = (unsigned char *) buffer;
  offset += tlv->length;

  return 1;
}

int ASN1_decode_tag(unsigned int *tag, const unsigned char *buffer, unsigned int *offset) {
  // Case 1: the tag consists of just one byte.
  if ((buffer[*offset] & 0x1F) == 0) {
    *tag = buffer[(*offset)++];

  } else {
    // Case 2: the tag consists of two bytes.
    if ((buffer[*offset + 1] & 0x80) == 0) {
      *tag = buffer[(*offset)++] << 8 | buffer[(*offset)++];

    // Case 3: the tag consists of more than two bytes.
    } else {
      debugError("ASN1 decode: tag of 3 bytes detected");
      return -1;
    }
  }

  return 1;
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
int ASN1_decode_length(unsigned int *length, const unsigned char *buffer, unsigned int *offset) {
  unsigned char prefix = buffer[(*offset)++];

  if (prefix < 0x80) {
    *length = prefix;
  } else {
    switch (prefix & 0x7F) {
      case 1:
        *length = buffer[(*offset)++];
      case 2:
        *length = buffer[(*offset)++] << 8 | buffer[(*offset)++];
      default:
       return -1;
    }
  }

  return 1;
}

int ASN1_find_tlv(TLV *tlv, unsigned int tag, const unsigned char *buffer, unsigned int offset) {
  int status = ASN1_decode_tlv(tlv, buffer, &offset);

  // Check the decoded tlv.
  while (status > 0 && tlv->tag != tag) {

    // If it's a constructed tlv, continue decoding it's value.
    if (ASN1_constructed_tlv(tlv)) {
      status = ASN1_find_tlv(tlv, tag, tlv->value, 0);

    // Otherwise continue decoding the buffer.
    } else {
      status = ASN1_decode_tlv(tlv, buffer, &offset);
    }
  }

  if (status > 0 && tlv->tag == tag) {
    return 1;
  } else {
    return -1;
  }
}
