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

import org.lattejava.jwt.algorithm.hmac.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Base64URL strictness: any non-URL-safe-alphabet character ({@code +}, {@code /}, whitespace) injected into any
 * segment causes the token to be rejected. Header- and signature-side corruption surfaces as
 * {@link InvalidJWTException} via {@link Base64URL#decode}; payload-side corruption surfaces as
 * {@link InvalidJWTSignatureException} because payload base64URL decoding runs after signature verification, and a
 * tampered signing-input byte produces an HMAC mismatch first. Either way the token is rejected. Trailing {@code =}
 * padding is accepted by the JDK URL decoder when the resulting segment length is mod 4 = 0; we accept that on
 * decode (RFC 7515 §2's no-padding rule applies to emit, not receive).
 *
 * @author Daniel DeGroff
 */
public class Base64URLStrictnessTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  /**
   * Build a valid 3-segment token, then corrupt one segment by inserting a bad char.
   */
  private static String buildValidToken() {
    JWT jwt = JWT.builder().subject("abc").build();
    return new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(SECRET));
  }

  /**
   * Inject a character into segment N (0=header,1=payload,2=signature).
   */
  private static String corrupt(String token, int segmentIndex, char badChar) {
    String[] parts = token.split("\\.", -1);
    parts[segmentIndex] = parts[segmentIndex] + badChar;
    return parts[0] + "." + parts[1] + "." + parts[2];
  }

  @Test(dataProvider = "strictnessViolations")
  public void strictBase64url_rejects(int segmentIndex, char badChar, String description) {
    // Use case: any non-URL-safe character or whitespace in any segment causes the token to be rejected. Header- and signature-side corruption fires InvalidJWTException via Base64URL.decode; payload-side corruption fires InvalidJWTSignatureException because the tampered signing-input bytes fail the HMAC compare before the payload is base64URL-decoded.
    String token = corrupt(buildValidToken(), segmentIndex, badChar);
    JWTDecoder decoder = new JWTDecoder();
    Verifier verifier = HMACVerifier.newVerifier(Algorithm.HS256, SECRET);
    try {
      decoder.decode(token, VerifierResolver.of(verifier));
      fail("Expected JWTException for [" + description + "]");
    } catch (InvalidJWTException | InvalidJWTSignatureException expected) {
      // good — either path is a rejection
    } catch (Exception e) {
      throw new AssertionError("Expected JWTException for [" + description
          + "], got [" + e.getClass().getSimpleName() + "]", e);
    }
  }

  @DataProvider(name = "strictnessViolations")
  public Object[][] strictnessViolations() {
    // The JDK Base64 URL decoder accepts a single trailing '=' when the resulting length is a multiple of 4 (it
    // treats it as optional padding). The HS256 signature is 43 chars unpadded; appending '=' yields 44 chars and
    // decodes to the same 32-byte signature, so the token still verifies. We accept that on receive (RFC 7515 §2's
    // no-padding rule is on emit; decoders may be liberal). Header (20→21) and payload (18→19) corrupted with '='
    // still reject because the resulting lengths aren't mod 4 = 0.
    return new Object[][]{
        // segmentIndex, badChar, description
        {0, '=', "padding '=' in header"},
        {1, '=', "padding '=' in payload"},
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
}
