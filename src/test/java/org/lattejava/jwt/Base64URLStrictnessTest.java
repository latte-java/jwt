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

import static org.testng.Assert.fail;

/**
 * Base64URL strictness: every segment must use only the URL-safe alphabet
 * {@code A-Z a-z 0-9 - _}; padding, whitespace, and non-URL-safe characters
 * ({@code +}, {@code /}, {@code =}) must be rejected with
 * {@link InvalidJWTException} before any parsing.
 *
 * @author Daniel DeGroff
 */
public class Base64URLStrictnessTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  /** Build a valid 3-segment token, then corrupt one segment by inserting a bad char. */
  private static String buildValidToken() {
    JWT jwt = JWT.builder().subject("abc").build();
    return new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(SECRET));
  }

  /** Inject a character into segment N (0=header,1=payload,2=signature). */
  private static String corrupt(String token, int segmentIndex, char badChar) {
    String[] parts = token.split("\\.", -1);
    parts[segmentIndex] = parts[segmentIndex] + badChar;
    return parts[0] + "." + parts[1] + "." + parts[2];
  }

  @DataProvider(name = "strictnessViolations")
  public Object[][] strictnessViolations() {
    return new Object[][] {
        // segmentIndex, badChar, description
        {0, '=', "padding '=' in header"},
        {1, '=', "padding '=' in payload"},
        {2, '=', "padding '=' in signature"},
        {0, ' ', "space in header"},
        {1, ' ', "space in payload"},
        {2, ' ', "space in signature"},
        {0, '\t', "tab in header"},
        {0, '\n', "newline in header"},
        {0, '+', "standard-alphabet '+' in header (not URL-safe)"},
        {1, '+', "standard-alphabet '+' in payload"},
        {2, '+', "standard-alphabet '+' in signature"},
        {0, '/', "standard-alphabet '/' in header"},
        {1, '/', "standard-alphabet '/' in payload"},
        {2, '/', "standard-alphabet '/' in signature"},
    };
  }

  @Test(dataProvider = "strictnessViolations")
  public void strictBase64url_rejects(int segmentIndex, char badChar, String description) {
    // Use case: any non-URL-safe character, padding, or whitespace in any segment rejects with InvalidJWTException.
    String token = corrupt(buildValidToken(), segmentIndex, badChar);
    JWTDecoder decoder = new JWTDecoder();
    Verifier verifier = HMACVerifier.newVerifier(SECRET);
    try {
      decoder.decode(token, VerifierResolver.of(verifier));
      fail("Expected InvalidJWTException for [" + description + "]");
    } catch (InvalidJWTException expected) {
      // good
    } catch (Exception e) {
      throw new AssertionError("Expected InvalidJWTException for [" + description
          + "], got [" + e.getClass().getSimpleName() + "]", e);
    }
  }
}
