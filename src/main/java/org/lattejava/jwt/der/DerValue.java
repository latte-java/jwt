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

package org.lattejava.jwt.der;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class DerValue {
  /**
   * Year boundary at which UTCTime gives way to GeneralizedTime per RFC 5280 §4.1.2.5.
   * Dates strictly before 2050-01-01T00:00:00Z encode as UTCTime (2-digit year);
   * dates on or after that instant encode as GeneralizedTime (4-digit year).
   */
  public static final Instant TIME_ENCODING_BOUNDARY = Instant.parse("2050-01-01T00:00:00Z");

  private static final DateTimeFormatter UTC_TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

  private static final DateTimeFormatter GENERALIZED_TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

  private final DerInputStream value;

  public Tag tag;

  public DerValue(Tag tag, byte[] value) {
    this.tag = tag;
    this.value = new DerInputStream(value);
  }

  public DerValue(int tag, byte[] value) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(value);
  }

  public DerValue(BigInteger integer) {
    this.tag = new Tag(Tag.Integer);
    this.value = new DerInputStream(integer.toByteArray());
  }

  public DerValue(int tag, DerOutputStream os) {
    this.tag = new Tag(tag);
    this.value = new DerInputStream(os.toByteArray());
  }

  public DerValue(Tag tag, DerOutputStream os) {
    this.tag = tag;
    this.value = new DerInputStream(os.toByteArray());
  }

  /**
   * Create a BIT STRING DerValue. The DER encoding for BIT STRING prepends a single
   * &quot;number of unused bits&quot; byte; for raw byte content this is always
   * <code>0x00</code> (every bit is significant).
   *
   * @param bytes the raw bit-string content (without the leading unused-bits byte)
   * @return a {@code DerValue} carrying tag {@link Tag#BitString} and the prepended pad byte
   */
  public static DerValue newBitString(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    byte[] padded = new byte[bytes.length + 1];
    padded[0] = 0x00;
    System.arraycopy(bytes, 0, padded, 1, bytes.length);
    return new DerValue(Tag.BitString, padded);
  }

  /**
   * Create a UTCTime DerValue (2-digit year, valid 1950-2049 per X.690 §11.8).
   *
   * @param instant the UTC instant
   * @return a {@code DerValue} carrying tag {@link Tag#UTCTime}
   */
  public static DerValue newUTCTime(Instant instant) {
    Objects.requireNonNull(instant, "instant");
    String formatted = UTC_TIME_FORMATTER.format(instant);
    return new DerValue(Tag.UTCTime, formatted.getBytes(StandardCharsets.US_ASCII));
  }

  /**
   * Create a GeneralizedTime DerValue (4-digit year). Per RFC 5280, used for dates
   * &gt;= 2050-01-01.
   *
   * @param instant the UTC instant
   * @return a {@code DerValue} carrying tag {@link Tag#GeneralizedTime}
   */
  public static DerValue newGeneralizedTime(Instant instant) {
    Objects.requireNonNull(instant, "instant");
    String formatted = GENERALIZED_TIME_FORMATTER.format(instant);
    return new DerValue(Tag.GeneralizedTime, formatted.getBytes(StandardCharsets.US_ASCII));
  }

  /**
   * Create a NULL DerValue (zero-length body).
   *
   * @return a {@code DerValue} carrying tag {@link Tag#Null} and no body
   */
  public static DerValue newNull() {
    return new DerValue(Tag.Null, new byte[0]);
  }

  /**
   * Create a PrintableString DerValue. The caller is responsible for ensuring the
   * input is restricted to the PrintableString alphabet (RFC 5280 §4.1.2.4).
   *
   * @param s the string to encode
   * @return a {@code DerValue} carrying tag {@link Tag#PrintableString}
   */
  public static DerValue newASCIIString(String s) {
    Objects.requireNonNull(s, "s");
    return new DerValue(Tag.PrintableString, s.getBytes(StandardCharsets.US_ASCII));
  }

  /**
   * Create a UTF8String DerValue.
   *
   * @param s the string to encode
   * @return a {@code DerValue} carrying tag {@link Tag#UTFString}
   */
  public static DerValue newUTF8String(String s) {
    Objects.requireNonNull(s, "s");
    return new DerValue(Tag.UTFString, s.getBytes(StandardCharsets.UTF_8));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DerValue derValue)) return false;
    return tag == derValue.tag &&
        Arrays.equals(value.toByteArray(), derValue.value.toByteArray());
  }

  public BigInteger getBigInteger(boolean signed) {
    return signed ? new BigInteger(value.toByteArray()) : new BigInteger(1, value.toByteArray());
  }

  public BigInteger getBigInteger() {
    return getBigInteger(true);
  }

  public String getBitString() {
    if (tag.value != Tag.BitString) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    byte[] bytes = value.toByteArray();

    // Strip off the ignore byte and decode the Bit String
    int ignoreByte = bytes[0];
    for (int i = 1; i < bytes.length; i++) {
      if (i == bytes.length - 1 && ignoreByte != 0) {
        // If ignore byte is not 0, then on the last byte ignore the last n bits
        int b = (bytes[i] & 0xFF) >> ignoreByte;
        sb.append(String.format("%" + (8 - ignoreByte) + "s", (Integer.toBinaryString(b))).replace(' ', '0'));
      } else {
        sb.append(String.format("%8s", (Integer.toBinaryString(bytes[i] & 0xFF))).replace(' ', '0'));
      }
    }

    return sb.toString();
  }

  /**
   * Read the BIT STRING content as raw bytes, stripping the leading
   * &quot;number of unused bits&quot; pad byte. Caller must ensure the bit string
   * encodes whole bytes only (the pad byte must be 0).
   *
   * @return the raw bytes (without pad byte)
   * @throws IllegalStateException if this DerValue is not a BIT STRING
   * @throws IllegalArgumentException if the leading pad byte is non-zero
   */
  public byte[] getBitStringBytes() {
    if (tag.value != Tag.BitString) {
      throw new IllegalStateException("Not a BIT STRING (tag=" + tag + ")");
    }
    byte[] bytes = value.toByteArray();
    if (bytes.length == 0) {
      throw new IllegalStateException("Empty BIT STRING value (missing pad byte)");
    }
    if (bytes[0] != 0) {
      throw new IllegalArgumentException("BIT STRING contains " + bytes[0] + " unused bits; expected whole-byte content");
    }
    byte[] out = new byte[bytes.length - 1];
    System.arraycopy(bytes, 1, out, 0, out.length);
    return out;
  }

  public int getLength() {
    return value.length;
  }

  public ObjectIdentifier getOID() throws IOException {
    return value.getOID();
  }

  public BigInteger getPositiveBigInteger() {
    return getBigInteger(false);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(tag);
    result = 31 * result + Arrays.hashCode(value.toByteArray());
    return result;
  }

  public byte[] toByteArray() {
    return value.toByteArray();
  }

  @Override
  public String toString() {
    if (tag.tagClass == TagClass.ContextSpecific) {
      return tag.toString();
    }

    return tag.getName() + ", length=" + value.length;
  }
}
