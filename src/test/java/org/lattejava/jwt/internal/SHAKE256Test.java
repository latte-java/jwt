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

import java.nio.charset.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.*;

import org.bouncycastle.jcajce.provider.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Tests for {@link SHAKE256}.
 *
 * <p>NIST CAVP SHAKE256 KAT vectors plus cross-validation against
 * BouncyCastle's {@code SHAKEDigest(256)} (test-scope only) and provider-preference fall-back semantics.</p>
 *
 * @author Daniel DeGroff
 */
public class SHAKE256Test {

  // NIST SHAKE-256 KAT: input "abc", first 64 output bytes
  private static final String ABC_KAT_64 =
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
          + "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
  private static final Provider BC_FIPS = new BouncyCastleFipsProvider();
  // NIST SHAKE-256 KAT (well-known): empty input, first 64 output bytes
  private static final String EMPTY_KAT_64 =
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
          + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
  private static final HexFormat HEX = HexFormat.of();

  /**
   * BouncyCastle FIPS exposes SHAKE256 via JCE as a fixed 64-byte digest; the variable-length API is not surfaced. For
   * cross-validation we read the full 64 bytes and slice as needed.
   */
  private static byte[] bcShake64(byte[] input) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHAKE256", BC_FIPS);
      md.update(input);
      return md.digest();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void brokenProviderFallsBackToBundled() throws Exception {
    // Use case: A registered "SHAKE256" provider that returns wrong bytes is
    // detected by the probe self-test and the library falls back to bundled.
    BrokenShakeProvider broken = new BrokenShakeProvider();
    Security.insertProviderAt(broken, 1);
    try {
      // Reset any cached provider state from prior tests so the probe re-runs.
      SHAKE256.resetProviderCacheForTesting();

      // Expect the bundled SHAKE256 result (i.e., correct), not all zeros.
      byte[] actual = SHAKE256.digest("abc".getBytes(StandardCharsets.US_ASCII), 64);
      assertEquals(HEX.formatHex(actual), ABC_KAT_64,
          "must NOT echo the broken provider's all-zero output");

      // Confirm cached provider is null (bundled path took over)
      assertFalse(SHAKE256.hasCachedProviderForTesting(),
          "cached provider must be null after KAT failure");

      // Verify the broken provider WAS actually queried. Without this the test
      // can silently pass when JCA falls through to another SHAKE256 provider
      // (e.g. BC-FIPS) because BrokenShake's class could not be loaded —
      // toString() alone does not prove the service was consulted.
      assertTrue(BrokenShakeMessageDigest.INSTANTIATIONS.get() > 0,
          "broken provider's SHAKE256 service must have been instantiated");
    } finally {
      Security.removeProvider(broken.getName());
      SHAKE256.resetProviderCacheForTesting();
    }
  }

  @Test
  public void crossValidationAgainstBouncyCastle() {
    // Use case: bundled implementation matches BouncyCastle's JCE-registered
    // SHAKE256 (which produces a fixed 64-byte output) for both empty and
    // randomized inputs (cross-validation).
    Random r = new Random(0xCAFEBABEL);
    for (int trial = 0; trial < 64; trial++) {
      int inLen = r.nextInt(300);
      byte[] input = new byte[inLen];
      r.nextBytes(input);
      byte[] expected = bcShake64(input);
      byte[] actual = SHAKE256.digest(input, 64);
      assertEquals(actual, expected, "trial=" + trial + " inLen=" + inLen);
    }
  }

  @Test(dataProvider = "katVectors")
  public void katVector(String name, byte[] input, int outputBytes, String expectedHex) {
    // Use case: NIST CAVP KAT vectors match for empty / abc / variable lengths.
    byte[] actual = SHAKE256.digest(input, outputBytes);
    assertEquals(actual.length, outputBytes, name + " length");
    assertEquals(HEX.formatHex(actual), expectedHex, name);
  }

  @DataProvider(name = "katVectors")
  public Object[][] katVectors() {
    return new Object[][]{
        {"empty 64", new byte[0], 64, EMPTY_KAT_64},
        {"abc 64", "abc".getBytes(StandardCharsets.US_ASCII), 64, ABC_KAT_64},
        // 32 / 57 / 64 / 128 byte slices for the same input — all derived from
        // the empty-input squeeze stream above (variable output length is the
        // same byte stream truncated/extended).
        {"empty 32", new byte[0], 32, EMPTY_KAT_64.substring(0, 64)},
        {"empty 57", new byte[0], 57, EMPTY_KAT_64.substring(0, 114)}
    };
  }

  @Test
  public void noProviderUsesBundled() {
    // Use case: When no SHAKE256 provider is registered (stock JDK), the
    // bundled implementation is used and produces correct output.
    SHAKE256.resetProviderCacheForTesting();
    try {
      byte[] expected = bcShake64("hello".getBytes(StandardCharsets.UTF_8));
      byte[] actual = SHAKE256.digest("hello".getBytes(StandardCharsets.UTF_8), 64);
      assertEquals(actual, expected);
    } finally {
      SHAKE256.resetProviderCacheForTesting();
    }
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void rejectsNonPositiveOutputBytes() {
    // Use case: outputBytes <= 0 is rejected.
    SHAKE256.digest(new byte[0], 0);
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void rejectsNullInput() {
    // Use case: null input is rejected.
    SHAKE256.digest(null, 32);
  }

  @Test
  public void shake256_57Bytes() {
    // Use case: 57-byte output (used by Ed448 at_hash/c_hash) — verified against
    // the 64-byte BC reference (truncated to 57).
    byte[] input = "openid-connect-at-hash-input".getBytes(StandardCharsets.UTF_8);
    byte[] expected64 = bcShake64(input);
    byte[] actual = SHAKE256.digest(input, 57);
    assertEquals(actual.length, 57);
    byte[] expected57 = new byte[57];
    System.arraycopy(expected64, 0, expected57, 0, 57);
    assertEquals(actual, expected57);
  }

  @Test
  public void variableLength_128() {
    // Use case: 128-byte squeeze (extends past first sponge block) is internally
    // consistent: re-running the bundled implementation produces identical bytes
    // and the prefix matches the 64-byte output (SHAKE is a stream cipher of
    // sorts; the first N bytes of any longer squeeze equal the squeeze of N).
    byte[] long128 = SHAKE256.digest(new byte[0], 128);
    byte[] short64 = SHAKE256.digest(new byte[0], 64);
    byte[] prefix = new byte[64];
    System.arraycopy(long128, 0, prefix, 0, 64);
    assertEquals(prefix, short64, "first 64 bytes of 128-byte squeeze must equal 64-byte squeeze");
    // Confirm against the documented NIST vector for empty input.
    assertEquals(HEX.formatHex(short64), EMPTY_KAT_64);
  }

  /**
   * Always returns all-zeros; will fail the KAT self-test.
   */
  public static final class BrokenShakeMessageDigest extends MessageDigest {
    /**
     * Counts instantiations so tests can assert the service was actually consulted.
     */
    static final AtomicInteger INSTANTIATIONS = new AtomicInteger();

    private int outLen = 32;

    public BrokenShakeMessageDigest() {
      super("SHAKE256");
      INSTANTIATIONS.incrementAndGet();
    }

    @Override
    protected byte[] engineDigest() {
      return new byte[outLen];
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws java.security.DigestException {
      if (len < 0) {
        throw new ProviderException("negative len");
      }
      for (int i = 0; i < len; i++) {
        buf[offset + i] = 0;
      }
      outLen = len;
      return len;
    }

    @Override
    protected int engineGetDigestLength() {
      return 0; // SHAKE is variable-length
    }

    @Override
    protected void engineReset() {
    }

    @Override
    protected void engineUpdate(byte input) {
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
    }
  }

  /**
   * Broken Provider used to validate the probe self-test path.
   *
   * <p>Registers via {@code putService(...)} with an overridden
   * {@link Service#newInstance(Object)} rather than the legacy class-name form. The legacy form requires JCA
   * ({@code java.base}) to reflectively instantiate the impl class — which fails with {@code IllegalAccessException}
   * because {@code org.lattejava.jwt.internal} is not opened to {@code java.base} in this module. When that happens,
   * JCA silently falls through to the next provider offering SHAKE256 (e.g. BC-FIPS under {@code test.fips=true}),
   * which defeats the purpose of this test.
   */
  private static final class BrokenShakeProvider extends Provider {
    BrokenShakeProvider() {
      super("BrokenShake", "1.0", "Test-only broken SHAKE256 provider");
      putService(new Service(this, "MessageDigest", "SHAKE256",
          BrokenShakeMessageDigest.class.getName(), null, null) {
        @Override
        public Object newInstance(Object constructorParameter) {
          return new BrokenShakeMessageDigest();
        }
      });
    }
  }
}
