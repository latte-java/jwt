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

import java.math.*;
import java.security.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Tests for {@link JOSEConverter} covering DER↔JOSE round-trip over all four curve lengths, the high-bit-set DER
 * padding edge case, leading-zero JOSE values, and rejection of malformed DER / wrong-length JOSE input.
 *
 * @author Daniel DeGroff
 */
public class JOSEConverterTest {
  private static final SecureRandom RNG = new SecureRandom();

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  private static byte[] randomBytes(int len) {
    byte[] out = new byte[len];
    RNG.nextBytes(out);
    // Ensure the value is non-zero so DER stripping never returns 0-length.
    if (out[len - 1] == 0) {
      out[len - 1] = 1;
    }
    return out;
  }

  @DataProvider(name = "curveIntLengths")
  public Object[][] curveIntLengths() {
    return new Object[][]{
        {32},   // ES256, ES256K
        {48},   // ES384
        {66},   // ES512 (P-521)
    };
  }

  @Test
  public void derToJose_integerExceedsCurveLength_throws() {
    // r is 33 bytes (0x00 pad + 32 bytes with high bit set) -> content after
    // leading-zero strip is 32 bytes = OK. Build an r of actual 33 unsigned
    // bytes to trigger the guard.
    BigInteger big = BigInteger.ONE.shiftLeft(33 * 8).subtract(BigInteger.ONE); // 33 bytes of 0xFF
    byte[] r = big.toByteArray(); // 34 bytes (leading 0x00 for sign)
    byte[] rContent = Arrays.copyOfRange(r, 0, r.length);
    int innerLen = rContent.length + 2 + 1 + 2; // roughly: r-TLV + s-TLV
    // Simpler: encode r as DER INTEGER with 34 bytes content; s as INTEGER 0x01.
    byte[] rTlv = new byte[2 + rContent.length];
    rTlv[0] = 0x02;
    rTlv[1] = (byte) rContent.length;
    System.arraycopy(rContent, 0, rTlv, 2, rContent.length);
    byte[] sTlv = new byte[]{0x02, 0x01, 0x01};
    int seqLen = rTlv.length + sTlv.length;
    byte[] der = new byte[2 + (seqLen >= 128 ? 1 : 0) + seqLen];
    int p = 0;
    der[p++] = 0x30;
    if (seqLen >= 128) {
      der[p++] = (byte) 0x81;
    }
    der[p++] = (byte) seqLen;
    System.arraycopy(rTlv, 0, der, p, rTlv.length);
    p += rTlv.length;
    System.arraycopy(sTlv, 0, der, p, sTlv.length);
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("exceeds"));
    }
  }

  @Test
  public void derToJose_missingIntegerTag_throws() {
    // SEQUENCE { <not-an-integer> }
    byte[] der = new byte[]{0x30, 0x06, 0x05, 0x01, 0x01, 0x02, 0x01, 0x02};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException expected) {
    }
  }

  @Test
  public void derToJose_missingSequenceTag_throws() {
    byte[] der = new byte[]{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException expected) {
    }
  }

  @Test
  public void derToJose_negativeInteger_throws() {
    // Use case: DER malleability -- INTEGER r with high bit set and no 0x00
    // pad (content byte 0x80 interpreted in two's complement is negative).
    // ECDSA r and s are unsigned by definition; the parser rejects.
    byte[] der = new byte[]{0x30, 0x06, 0x02, 0x01, (byte) 0x80, 0x02, 0x01, 0x01};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException for negative INTEGER");
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("negative"));
    }
  }

  @Test
  public void derToJose_nonCanonicalLongFormSequenceLength_throws() {
    // Use case: DER malleability -- SEQUENCE length 6 encoded with the long
    // form byte (0x30 0x81 0x06 ...) when short form (0x30 0x06 ...) is
    // canonical. The parser rejects non-canonical long-form.
    byte[] der = new byte[]{0x30, (byte) 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException for non-canonical long-form SEQUENCE length");
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("non-canonical") || expected.getMessage().contains("SEQUENCE length"));
    }
  }

  @Test
  public void derToJose_null_throws() {
    try {
      JOSEConverter.derToJose(null, 32);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException expected) {
    }
  }

  @Test
  public void derToJose_redundantLeadingZero_throws() {
    // Use case: DER malleability -- INTEGER r encoded as 0x00 0x01 (two
    // bytes) instead of the canonical 0x01 (one byte). The leading 0x00 is
    // only legal when the next byte has its high bit set; here it does not,
    // so the encoding is non-minimal and rejected.
    byte[] der = new byte[]{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException for non-minimal INTEGER encoding");
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("non-minimal"));
    }
  }

  @Test
  public void derToJose_sequenceLengthMismatch_throws() {
    // Claimed length != actual
    byte[] der = new byte[]{0x30, 0x10, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException expected) {
    }
  }

  @Test
  public void derToJose_trailingBytesAfterSignature_throws() {
    // Use case: DER malleability -- SEQUENCE body ends before the declared
    // length, with extra bytes tacked on. Parser computes seqLen vs buffer
    // length and rejects.
    byte[] der = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException for trailing bytes");
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("SEQUENCE length"));
    }
  }

  @Test
  public void derToJose_truncated_throws() {
    // A valid-looking SEQUENCE header but truncated content
    byte[] der = new byte[]{0x30, 0x06, 0x02, 0x02, 0x01, 0x02};
    try {
      JOSEConverter.derToJose(der, 32);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException expected) {
    }
  }

  @Test
  public void joseToDer_null_throws() {
    try {
      JOSEConverter.joseToDer(null, 32);
      fail("Expected InvalidJWTSignatureException");
    } catch (InvalidJWTSignatureException expected) {
    }
  }

  @Test(dataProvider = "curveIntLengths")
  public void joseToDer_wrongLength_throws(int len) {
    try {
      JOSEConverter.joseToDer(new byte[2 * len - 1], len);
      fail("Expected InvalidJWTSignatureException for JOSE length " + (2 * len - 1));
    } catch (InvalidJWTSignatureException expected) {
    }
    try {
      JOSEConverter.joseToDer(new byte[2 * len + 1], len);
      fail("Expected InvalidJWTSignatureException for JOSE length " + (2 * len + 1));
    } catch (InvalidJWTSignatureException expected) {
    }
  }

  @Test(dataProvider = "curveIntLengths")
  public void roundTrip_highBitSet(int len) {
    // Force both r and s to have their high bit set so joseToDer must prepend
    // a DER padding byte and derToJose must strip it.
    byte[] r = randomBytes(len);
    r[0] = (byte) 0xFF;
    byte[] s = randomBytes(len);
    s[0] = (byte) 0x80;
    byte[] jose = concat(r, s);
    byte[] der = JOSEConverter.joseToDer(jose, len);
    byte[] roundTrip = JOSEConverter.derToJose(der, len);
    assertEquals(roundTrip, jose);
  }

  @Test(dataProvider = "curveIntLengths")
  public void roundTrip_leadingZeroInJose(int len) {
    // JOSE value where r's most-significant byte is 0x00 (r < 2^((len-1)*8))
    // -- the DER encoding will strip that byte. Round-trip must still yield
    // the original padded form.
    byte[] jose = new byte[2 * len];
    // r = 0x01 in its lowest byte, all higher bytes zero.
    jose[len - 1] = 0x01;
    // s = 0x7F in its lowest byte, all higher bytes zero.
    jose[2 * len - 1] = 0x7F;
    byte[] der = JOSEConverter.joseToDer(jose, len);
    byte[] roundTrip = JOSEConverter.derToJose(der, len);
    assertEquals(roundTrip, jose);
  }

  @Test(dataProvider = "curveIntLengths")
  public void roundTrip_random(int len) {
    for (int i = 0; i < 256; i++) {
      byte[] r = randomBytes(len);
      byte[] s = randomBytes(len);
      byte[] jose = concat(r, s);
      byte[] der = JOSEConverter.joseToDer(jose, len);
      byte[] roundTrip = JOSEConverter.derToJose(der, len);
      assertEquals(roundTrip, jose, "JOSE round-trip mismatch (len=" + len + ")");
    }
  }

  @Test(dataProvider = "curveIntLengths")
  public void roundTrip_smallValues(int len) {
    // r and s are small positive integers (e.g. r=1, s=2); derToJose must
    // left-zero-pad to the curve length.
    byte[] jose = new byte[2 * len];
    jose[len - 1] = 0x01;
    jose[2 * len - 1] = 0x02;
    byte[] der = JOSEConverter.joseToDer(jose, len);
    byte[] roundTrip = JOSEConverter.derToJose(der, len);
    assertEquals(roundTrip, jose);
  }
}
