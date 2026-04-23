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
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * {@code crit} understood-parameters check. Structural shape validation
 * of the {@code crit} array itself is covered in {@link HeaderTest}; this
 * class tests the decoder's runtime understanding set.
 *
 * @author Daniel DeGroff
 */
public class CritHeaderTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private String encodeWithCrit(Object critValue) {
    JWT jwt = JWT.builder().subject("abc").build();
    return new JWTEncoder().encode(jwt,
        HMACSigner.newSHA256Signer(SECRET),
        b -> b.parameter("crit", critValue).parameter("b64", Boolean.FALSE));
  }

  @Test
  public void crit_listedInCriticalHeaders_accepted() {
    // Use case: crit listing "b64"; decoder configured with "b64" in criticalHeaders -> accepted.
    String token = encodeWithCrit(Collections.singletonList("b64"));
    JWTDecoder decoder = JWTDecoder.builder()
        .criticalHeaders(new HashSet<>(Collections.singletonList("b64")))
        .build();
    JWT jwt = decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(SECRET)));
    assertNotNull(jwt);
  }

  @Test
  public void crit_unrecognized_rejected() {
    // Use case: crit listing an unknown parameter name -> InvalidJWTException.
    String token = encodeWithCrit(Collections.singletonList("unknown-ext"));
    JWTDecoder decoder = JWTDecoder.builder()
        .criticalHeaders(new HashSet<>(Collections.singletonList("b64")))
        .build();
    try {
      decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(SECRET)));
      fail("Expected InvalidJWTException for unrecognized crit");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void crit_emptyArray_accepted() {
    // Use case: crit is an empty array -> accepted (no required critical parameters).
    String token = encodeWithCrit(Collections.emptyList());
    JWT jwt = new JWTDecoder().decode(token, VerifierResolver.of(HMACVerifier.newVerifier(SECRET)));
    assertNotNull(jwt);
  }

  @Test
  public void crit_multipleNames_partialUnknown_rejected() {
    // Use case: crit listing multiple values; one unknown -> InvalidJWTException.
    String token = encodeWithCrit(Arrays.asList("b64", "unknown-ext"));
    JWTDecoder decoder = JWTDecoder.builder()
        .criticalHeaders(new HashSet<>(Collections.singletonList("b64")))
        .build();
    try {
      decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(SECRET)));
      fail("Expected InvalidJWTException when any crit entry is unrecognized");
    } catch (InvalidJWTException expected) {
      // good
    }
  }
}
