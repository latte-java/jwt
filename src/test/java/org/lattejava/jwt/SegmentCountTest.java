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

package org.lattejava.jwt;

import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Spec §14 "Segment count" matrix: confirms how the decoder treats every
 * structural segment-count permutation. Built from the table in
 * specs/7.0-architecture.md §5 step 3.
 *
 * @author The Latte Project
 */
public class SegmentCountTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static String b64(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  /** Build a header b64 segment for the given alg, and a payload b64 segment with subject. */
  private static String[] validHeaderAndPayload() {
    String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    return new String[] {header, payload};
  }

  @DataProvider(name = "segmentCases")
  public Object[][] segmentCases() {
    String[] hp = validHeaderAndPayload();
    String header = hp[0];
    String payload = hp[1];
    return new Object[][] {
        // input, expected exception class for authenticated decode, description
        {header + "." + payload,
            MissingSignatureException.class,
            "two segments (no trailing dot)"},
        {header + "." + payload + ".",
            InvalidJWTSignatureException.class,
            "three segments with empty signature -> verifier rejects"},
        {header + "." + payload + ".badbutvalidb64",
            InvalidJWTSignatureException.class,
            "three segments with bogus signature -> verifier rejects"},
        {header + "." + payload + ".sig.extra",
            InvalidJWTException.class,
            "four segments"},
        {header + "." + payload + ".sig.extra.more",
            InvalidJWTException.class,
            "five segments (JWE-looking)"},
        {"." + payload + ".sig",
            InvalidJWTException.class,
            "empty first segment"},
        {header + ".." + "sig",
            InvalidJWTException.class,
            "empty middle segment"},
    };
  }

  // Use case: spec §14 segment-count matrix -- authenticated decode path.
  @Test(dataProvider = "segmentCases")
  public void segmentCounts(String input, Class<? extends Exception> expected, String description) {
    JWTDecoder decoder = new JWTDecoder();
    Verifier verifier = HMACVerifier.newVerifier(SECRET);
    try {
      decoder.decode(input, VerifierResolver.of(verifier));
      fail("Expected [" + expected.getSimpleName() + "] for [" + description + "], no exception thrown");
    } catch (Exception e) {
      if (!expected.isAssignableFrom(e.getClass())) {
        throw new AssertionError("Expected [" + expected.getSimpleName() + "] for [" + description
            + "], got [" + e.getClass().getSimpleName() + "]", e);
      }
    }
  }

  // Use case: "a.b.c" proceeds through the full sig flow on a real signed token.
  @Test
  public void threeSegments_realToken_succeeds() {
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(SECRET));
    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(HMACVerifier.newVerifier(SECRET)));
    assertNotNull(decoded);
  }

  // Use case: "a.b." (empty signature) is structurally valid for decodeUnsecured.
  @Test
  public void threeSegmentsEmptySig_decodeUnsecured_succeeds() {
    String[] hp = validHeaderAndPayload();
    String token = hp[0] + "." + hp[1] + ".";
    JWT decoded = new JWTDecoder().decodeUnsecured(token);
    assertNotNull(decoded);
  }
}
