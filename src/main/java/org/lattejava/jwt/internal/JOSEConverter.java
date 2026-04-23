/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.lattejava.jwt.internal;

import org.lattejava.jwt.InvalidJWTSignatureException;

/**
 * Conversion between ECDSA signatures in JOSE concatenation form
 * ({@code R || S}, fixed-length curve-order-length big-endian unsigned
 * integers) and ASN.1 DER {@code SEQUENCE { INTEGER r, INTEGER s }} as
 * produced and consumed by {@code java.security.Signature}.
 *
 * <p>This conversion is a known CVE surface in JWT libraries (Auth0 Node 2015,
 * historical nimbus). The implementation here exists in one place so it can be
 * audited against a single contract and tested directly.</p>
 *
 * @author The Latte Project
 */
public final class JOSEConverter {
  private JOSEConverter() {
  }

  /**
   * Convert a DER-encoded {@code SEQUENCE { INTEGER r, INTEGER s }} (as
   * produced by {@code java.security.Signature.sign()} for an ECDSA
   * signer) into JOSE concatenation form: {@code R || S}, each integer
   * left-zero-padded to {@code curveIntLength} bytes.
   *
   * @param der            the DER-encoded ECDSA signature
   * @param curveIntLength the curve-order length in bytes (32 / 48 / 66 / 32
   *                       for P-256 / P-384 / P-521 / secp256k1)
   * @return the {@code 2 * curveIntLength}-byte JOSE-format signature
   * @throws IllegalStateException if {@code der} is not a well-formed DER
   *                               ECDSA signature, or if either integer
   *                               exceeds {@code curveIntLength} bytes.
   *                               This indicates a library or provider
   *                               bug — callers should not catch this.
   */
  public static byte[] derToJose(byte[] der, int curveIntLength) {
    if (der == null) {
      throw new IllegalStateException("DER signature is null");
    }
    if (curveIntLength <= 0) {
      throw new IllegalStateException("Invalid curve integer length [" + curveIntLength + "]");
    }
    int idx = 0;
    if (der.length < 8 || (der[idx++] & 0xFF) != 0x30) {
      throw new IllegalStateException("Malformed ECDSA DER signature: missing SEQUENCE tag");
    }
    int seqLen;
    int b = der[idx++] & 0xFF;
    if ((b & 0x80) == 0) {
      seqLen = b;
    } else {
      int n = b & 0x7F;
      if (n != 1 || idx >= der.length) {
        throw new IllegalStateException("Malformed ECDSA DER signature: invalid SEQUENCE length");
      }
      seqLen = der[idx++] & 0xFF;
    }
    if (idx + seqLen != der.length) {
      throw new IllegalStateException("Malformed ECDSA DER signature: SEQUENCE length mismatch");
    }

    int[] cursor = {idx};
    byte[] rContent = readDerInteger(der, cursor);
    byte[] sContent = readDerInteger(der, cursor);
    if (cursor[0] != der.length) {
      throw new IllegalStateException("Malformed ECDSA DER signature: trailing bytes after S");
    }

    byte[] r = stripLeadingZerosForUnsigned(rContent);
    byte[] s = stripLeadingZerosForUnsigned(sContent);
    if (r.length > curveIntLength || s.length > curveIntLength) {
      throw new IllegalStateException("ECDSA integer exceeds curve length [" + curveIntLength + "]");
    }

    byte[] out = new byte[2 * curveIntLength];
    System.arraycopy(r, 0, out, curveIntLength - r.length, r.length);
    System.arraycopy(s, 0, out, 2 * curveIntLength - s.length, s.length);
    return out;
  }

  /**
   * Convert a JOSE-format ECDSA signature ({@code R || S}, each
   * {@code curveIntLength} bytes) into DER {@code SEQUENCE { INTEGER r,
   * INTEGER s }} as consumed by {@code java.security.Signature.verify()}.
   *
   * @param jose           the JOSE-format signature, exactly
   *                       {@code 2 * curveIntLength} bytes
   * @param curveIntLength the curve-order length in bytes
   * @return the DER-encoded signature
   * @throws InvalidJWTSignatureException if {@code jose.length != 2 * curveIntLength}
   */
  public static byte[] joseToDer(byte[] jose, int curveIntLength) {
    if (jose == null || jose.length != 2 * curveIntLength) {
      throw new InvalidJWTSignatureException();
    }
    byte[] r = new byte[curveIntLength];
    byte[] s = new byte[curveIntLength];
    System.arraycopy(jose, 0, r, 0, curveIntLength);
    System.arraycopy(jose, curveIntLength, s, 0, curveIntLength);
    byte[] rEnc = encodeUnsignedInteger(r);
    byte[] sEnc = encodeUnsignedInteger(s);
    int seqLen = rEnc.length + sEnc.length;
    int seqHeaderLen = (seqLen < 128) ? 2 : 3;
    byte[] out = new byte[seqHeaderLen + seqLen];
    int p = 0;
    out[p++] = 0x30;
    if (seqLen < 128) {
      out[p++] = (byte) seqLen;
    } else {
      out[p++] = (byte) 0x81;
      out[p++] = (byte) seqLen;
    }
    System.arraycopy(rEnc, 0, out, p, rEnc.length);
    p += rEnc.length;
    System.arraycopy(sEnc, 0, out, p, sEnc.length);
    return out;
  }

  /**
   * Read a DER {@code INTEGER} from {@code der} starting at
   * {@code cursor[0]}, advance the cursor past the value, return the raw
   * content bytes (which may include a DER leading-zero pad byte for the
   * sign bit).
   */
  private static byte[] readDerInteger(byte[] der, int[] cursor) {
    int idx = cursor[0];
    if (idx + 2 > der.length || (der[idx] & 0xFF) != 0x02) {
      throw new IllegalStateException("Malformed ECDSA DER signature: missing INTEGER tag");
    }
    int len = der[idx + 1] & 0xFF;
    if ((len & 0x80) != 0 || idx + 2 + len > der.length || len == 0) {
      throw new IllegalStateException("Malformed ECDSA DER signature: invalid INTEGER length");
    }
    byte[] value = new byte[len];
    System.arraycopy(der, idx + 2, value, 0, len);
    cursor[0] = idx + 2 + len;
    return value;
  }

  /**
   * Strip any leading zero bytes used in DER to keep the INTEGER
   * non-negative. Returns the raw unsigned magnitude. Returns a
   * 1-byte {@code 0x00} array if the original value was all zeros.
   */
  private static byte[] stripLeadingZerosForUnsigned(byte[] value) {
    int start = 0;
    while (start < value.length - 1 && value[start] == 0x00) {
      start++;
    }
    if (start == 0) {
      return value;
    }
    byte[] out = new byte[value.length - start];
    System.arraycopy(value, start, out, 0, out.length);
    return out;
  }

  /**
   * Encode {@code value} (interpreted as a big-endian unsigned integer)
   * as a DER {@code INTEGER}. Strips redundant leading zero bytes and
   * prepends a single 0x00 byte if the high bit of the first content
   * byte is set (DER requires non-negative INTEGER encoding).
   */
  private static byte[] encodeUnsignedInteger(byte[] value) {
    int start = 0;
    while (start < value.length - 1 && value[start] == 0x00) {
      start++;
    }
    byte[] content = new byte[value.length - start];
    System.arraycopy(value, start, content, 0, content.length);
    boolean prependZero = (content[0] & 0x80) != 0;
    int contentLen = content.length + (prependZero ? 1 : 0);
    byte[] out = new byte[2 + contentLen];
    out[0] = 0x02;
    out[1] = (byte) contentLen;
    int off = 2;
    if (prependZero) {
      out[off++] = 0x00;
    }
    System.arraycopy(content, 0, out, off, content.length);
    return out;
  }
}
