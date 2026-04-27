/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.lattejava.jwt.internal.der;

import java.io.*;
import java.util.*;

/**
 * @author Daniel DeGroff
 */
@SuppressWarnings("unused")
public class ObjectIdentifier {
  /**
   * Elliptic curve / 256 bit / secp256r1 / prime256v1 X9.62/SECG curve over a 256 bit prime field
   */
  public static final String ECDSA_P256 = "1.2.840.10045.3.1.7";
  /**
   * Elliptic curve / 384 bit / secp384r1 / prime384v1 NIST/SECG curve over a 384 bit prime field
   */
  public static final String ECDSA_P384 = "1.3.132.0.34";
  /**
   * Elliptic curve / 512 bit / secp521r1 / prime521v1 NIST/SECG curve over a 521 bit prime field
   */
  public static final String ECDSA_P521 = "1.3.132.0.35";
  /**
   * Elliptic Curve Public Key cryptography
   */
  public static final String EC_ENCRYPTION = "1.2.840.10045.2.1";
  /**
   * Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519
   */
  public static final String EdDSA_25519 = "1.3.101.112";
  /**
   * Edwards-curve Digital Signature Algorithm (EdDSA) Ed448
   */
  public static final String EdDSA_448 = "1.3.101.113";
  /**
   * RSA Public Key cryptography Signature Scheme with Appendix - Probabilistic Signature Scheme
   */
  public static final String RSASSA_PSS_ENCRYPTION = "1.2.840.113549.1.1.10";
  /**
   * RSA Public Key cryptography
   */
  public static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
  /**
   * RSA Encryption / SHA-256 / SHA256withRSA
   */
  public static final String RSA_SHA256 = "1.2.840.113549.1.1.11";
  /**
   * RSA Encryption / SHA-384 / SHA384withRSA
   */
  public static final String RSA_SHA384 = "1.2.840.113549.1.1.12";
  /**
   * RSA Encryption / SHA-512 / SHA512withRSA
   */
  public static final String RSA_SHA512 = "1.2.840.113549.1.1.13";
  /**
   * Secure Hash Algorithm that uses a 256-bit key (SHA256)
   */
  public static final String SHA256 = "2.16.840.1.101.3.4.2.1";
  /**
   * Secure Hash Algorithm that uses a 384-bit key (SHA384)
   */
  public static final String SHA384 = "2.16.840.1.101.3.4.2.2";
  /**
   * Secure Hash Algorithm that uses a 512-bit key (SHA512)
   */
  public static final String SHA512 = "2.16.840.1.101.3.4.2.3";
  /**
   * X.520 commonName (CN) — DN attribute type.
   */
  public static final String X_520_DN_COMMON_NAME = "2.5.4.3";
  /**
   * X.520 country (C) — DN attribute type.
   */
  public static final String X_520_DN_COUNTRY = "2.5.4.6";
  /**
   * X.520 localityName (L) — DN attribute type.
   */
  public static final String X_520_DN_LOCALITY = "2.5.4.7";
  /**
   * X.520 organizationName (O) — DN attribute type.
   */
  public static final String X_520_DN_ORGANIZATION = "2.5.4.10";
  /**
   * X.520 organizationalUnitName (OU) — DN attribute type.
   */
  public static final String X_520_DN_ORGANIZATIONAL_UNIT = "2.5.4.11";
  /**
   * X.520 stateOrProvinceName (ST) — DN attribute type.
   */
  public static final String X_520_DN_STATE = "2.5.4.8";
  /**
   * The raw byte array of this Object Identifier.
   */
  public final byte[] value;

  /**
   * The string form of the byte array after it has been decoded.
   */
  private String decoded;

  public ObjectIdentifier(byte[] value) {
    this.value = value;
  }

  /**
   * Encode a dot-notation OID string (e.g. {@code "1.2.840.113549.1.1.11"}) to its DER value bytes (without the
   * surrounding tag/length).
   *
   * <p>Encoding rules per X.690 §8.19: the first two arcs are combined as
   * {@code 40*a + b}; subsequent arcs are encoded base-128 with the high bit set on every byte except the last
   * (variable length, including the three-byte case for arcs &gt;= 16384).</p>
   *
   * @param oid the dot-notation OID string
   * @return the DER value bytes (caller wraps with the OID tag and length)
   * @throws IllegalArgumentException if {@code oid} is malformed
   */
  public static byte[] encode(String oid) {
    Objects.requireNonNull(oid, "oid");
    String[] arcs = oid.split("\\.");
    if (arcs.length < 2) {
      throw new IllegalArgumentException("OID must have at least [2] arcs but found [" + oid + "]");
    }
    long first;
    long second;
    try {
      first = Long.parseLong(arcs[0]);
      second = Long.parseLong(arcs[1]);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Invalid arc in OID [" + oid + "]", e);
    }
    if (first < 0 || first > 2) {
      throw new IllegalArgumentException("First OID arc must be [0], [1], or [2] but found [" + oid + "]");
    }
    if (second < 0 || (first < 2 && second > 39)) {
      throw new IllegalArgumentException("Second OID arc out of range [" + oid + "]");
    }

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeBase128(out, 40L * first + second);
    for (int i = 2; i < arcs.length; i++) {
      long arc;
      try {
        arc = Long.parseLong(arcs[i]);
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Invalid arc in OID [" + oid + "]", e);
      }
      if (arc < 0) {
        throw new IllegalArgumentException("Negative arc in OID [" + oid + "]");
      }
      writeBase128(out, arc);
    }
    return out.toByteArray();
  }

  /**
   * Write a single arc value as base-128 with the continuation bit (0x80) set on every byte except the last
   * (least-significant). Single-byte values 0..127 emit a single byte with the high bit cleared. Two-byte values
   * 128..16383 emit two bytes; three-byte values 16384..2097151 emit three bytes; etc.
   */
  private static void writeBase128(ByteArrayOutputStream out, long value) {
    if (value < 0x80L) {
      out.write((int) (value & 0x7F));
      return;
    }
    // Find the number of base-128 bytes required.
    int bytesNeeded = 0;
    long tmp = value;
    while (tmp > 0) {
      bytesNeeded++;
      tmp >>>= 7;
    }
    for (int i = bytesNeeded - 1; i >= 0; i--) {
      int septet = (int) ((value >>> (7 * i)) & 0x7F);
      if (i != 0) {
        septet |= 0x80;
      }
      out.write(septet);
    }
  }

  /**
   * Decode the byte array for this Object Identifier.
   *
   * @return a string representation of the OID.
   * @throws DerDecodingException if the byte array is not encoded properly.
   */
  public String decode() throws DerDecodingException {
    if (decoded == null) {
      _decode();
    }

    return decoded;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ObjectIdentifier that)) return false;
    return Arrays.equals(value, that.value) &&
        Objects.equals(decoded, that.decoded);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(decoded);
    result = 31 * result + Arrays.hashCode(value);
    return result;
  }

  @Override
  public String toString() {
    try {
      return decode();
    } catch (DerDecodingException e) {
      return "Failed to _decode this object, unable to produce a string.";
    }
  }

  private void _decode() throws DerDecodingException {
    StringBuilder sb = new StringBuilder(value.length * 4);
    int index = 0;

    for (int i = 0; i < value.length; i++) {
      // We are not currently handling OIDs that have a node larger than 4 bytes
      if (i - index + 1 > 4) {
        throw new DerDecodingException("Object identifier node larger than [4] bytes is not supported");
      }

      byte b = value[i];

      // Skip multi-byte length leading bytes, we'll handle them on the next pass
      if ((b & 128) != 0) {
        continue;
      }

      // Add a separator between nodes
      if (index != 0) {
        sb.append('.');
      }

      // Use an int to build the next node value, it may be made up of multiple bytes
      int node = 0;

      // Make at least one pass, optionally catch up the index to the cursor 'i' if we skipped a byte
      for (int j = index; j <= i; ++j) {
        node = node << 7;
        node = node | value[j] & 127;
      }

      // The first two nodes are encoded in a single byte when the node is less than 0x50 (80 decimal)
      if (index == 0) {
        if (node < 0x50) {
          sb.append(node / 40)
            .append('.')
            .append(node % 40);
        } else {
          sb.append("2.")
            .append(node - 80);
        }
      } else {
        sb.append(node);
      }

      index = i + 1;
    }

    decoded = sb.toString();
  }
}
