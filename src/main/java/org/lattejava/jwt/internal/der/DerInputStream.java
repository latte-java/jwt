/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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
public class DerInputStream {
  public final ByteArrayInputStream data;

  public final int length;

  public DerInputStream(DerValue dervalue) {
    this(dervalue.toByteArray());
  }

  public DerInputStream(byte[] bytes) {
    data = new ByteArrayInputStream(bytes);
    length = bytes.length;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DerInputStream that)) return false;
    return length == that.length &&
        Arrays.equals(toByteArray(), that.toByteArray());
  }

  public ObjectIdentifier getOID() throws DerDecodingException {
    int tag = data.read();
    if (tag != Tag.ObjectIdentifier) {
      throw new DerDecodingException("Expected Object Identifier tag [" + Tag.ObjectIdentifier + " / " + Tag.hexString(Tag.ObjectIdentifier) + "] "
          + "but found [" + tag + " / " + Tag.hexString(tag) + "]");
    }

    int length = readLength();
    if (length > data.available()) {
      throw new DerDecodingException("Expected [" + length + "] bytes available to read Object Identifier but found [" + data.available() + "]");
    }

    byte[] buf = new byte[length];
    //noinspection ResultOfMethodCallIgnored
    data.read(buf, 0, length);
    return new ObjectIdentifier(buf);
  }

  public DerValue[] getSequence() throws DerDecodingException {
    int tag = data.read();
    if (tag != Tag.Sequence) {
      throw new DerDecodingException("Expected Sequence tag [" + Tag.Sequence + " / " + Tag.hexString(Tag.Sequence) + "] "
          + "but found [" + tag + " / " + Tag.hexString(tag) + "]");
    }

    int length = readLength();
    if (length > data.available()) {
      throw new DerDecodingException("DER length exceeds available data");
    }
    byte[] sequence = copyBytes(length);
    return getValuesFromBytes(sequence);
  }

  @Override
  public int hashCode() {
    return Objects.hash(toByteArray(), length);
  }

  public DerValue readDerValue() throws DerDecodingException {
    int tag = data.read();
    int length = readLength();
    if (length > data.available()) {
      throw new DerDecodingException("DER length exceeds available data");
    }
    byte[] bytes = copyBytes(length);
    return new DerValue(tag, bytes);
  }

  public byte[] toByteArray() {
    try {
      // Zero-length buffer needs no read; ByteArrayInputStream.read returns -1 at EOF
      // even when the requested length is zero.
      if (length == 0) {
        return new byte[0];
      }
      byte[] buffer = new byte[length];
      data.reset();
      int actualLength = data.read(buffer);
      if (actualLength != length) {
        throw new IOException("Expected to read [" + length + "] bytes but read [" + actualLength + "]");
      }
      return buffer;
    } catch (IOException e) {
      // Reading from a ByteArrayInputStream cannot raise an IOException
      // under normal circumstances. If this fires, it's a library or JVM
      // bug rather than bad DER input.
      throw new IllegalStateException("Unexpected IO error reading DER from in-memory buffer", e);
    }
  }

  private byte[] copyBytes(int l) {
    byte[] seq = new byte[l];
    for (int i = 0; i < l; i++) {
      seq[i] = (byte) data.read();
    }

    return seq;
  }

  private DerValue[] getValuesFromBytes(byte[] bytes) throws DerDecodingException {
    List<DerValue> result = new ArrayList<>();

    int index = 0;
    while (index < bytes.length) {
      ByteArrayInputStream stream = new ByteArrayInputStream(bytes, index, bytes.length);
      int avail = stream.available();

      Tag tag = new Tag(stream.read());
      int length = readLength(stream);

      // Account for the length of the tag and length in bytes
      // - Tag is always one byte, the length is variable
      int adjustment = Math.abs(stream.available() - avail);

      byte[] buf = new byte[length];
      for (int i = 0; i < length; i++) {
        buf[i] = (byte) stream.read();
      }

      result.add(new DerValue(tag, buf));
      index = index + length + adjustment;
    }

    return result.toArray(new DerValue[]{});
  }

  private int readLength(InputStream inputStream) throws DerDecodingException {
    try {
      int b = inputStream.read();
      if (b == -1) {
        throw new IOException("Invalid DER encoding, unable to read length byte");
      }

      int length = b;
      int remaining = length & 0x80; // 0b1000000 or 128
      if (remaining == 0) {
        // Length is less than 128, the length is full represented in the first byte
        return length;
      }

      remaining = length & 0x7F; // 0b1000001 or 127
      if (remaining == 0) {
        // 0x80 alone signals BER indefinite-length form. DER (X.690 §10.1)
        // forbids it -- a definite length is required for every TLV.
        throw new IOException("Indefinite-length encoding is not allowed in DER (X.690 §10.1)");
      }

      //noinspection ConstantConditions
      if (remaining < 0) {
        throw new IOException("Invalid DER encoding");
      } else if (remaining > 4) {
        throw new IOException("Invalid DER encoding, length value too large");
      }

      length = inputStream.read() & 0xFF; // 0b11111111 or 255
      remaining = remaining - 1;
      if (length == 0) {
        throw new IOException("Redundant length bytes found");
      }

      while (remaining > 0) {
        remaining = remaining - 1;
        length <<= 8;
        length += inputStream.read() & 0xFF;  // 0b11111111 or255
      }

      if (length < 0) {
        throw new IOException("Invalid length bytes");
      } else if (length <= 127) {
        throw new IOException("Length encoding should use short form");
      }

      return length;
    } catch (IOException e) {
      throw new DerDecodingException(e);
    }
  }

  private int readLength() throws DerDecodingException {
    return readLength(data);
  }
}
