/*
 * Copyright (c) 2026, the latte-java project authors
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

package org.lattejava.jwt;

import org.lattejava.jwt.jwks.JSONWebKey;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Tests for the public {@link JWKThumbprint} API surface (byte-returning
 * compute and base64url helper). Canonicalisation behaviour is exhaustively
 * covered by the internal thumbprint test; these tests pin the public
 * contract.
 *
 * @author Daniel DeGroff
 */
public class JWKThumbprintTest {
  // RFC 7638 §3.1 canonical RSA JWK example; documented SHA-256 base64url
  // thumbprint is "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
  private static JSONWebKey rfc7638Rsa() {
    return JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
        .e("AQAB")
        .build();
  }

  @Test
  public void compute_returnsRawDigestBytes() {
    // Use case: compute() returns the raw SHA-256 digest (32 bytes), leaving
    // the caller in control of how the bytes are encoded.
    byte[] digest = JWKThumbprint.compute("SHA-256", rfc7638Rsa());
    assertNotNull(digest);
    assertEquals(digest.length, 32);
  }

  @Test
  public void base64url_matchesRfc7638Vector() {
    // Use case: compute() + base64url() round-trips to the RFC 7638 §3.1 vector.
    byte[] digest = JWKThumbprint.compute("SHA-256", rfc7638Rsa());
    assertEquals(JWKThumbprint.base64url(digest), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
  }

  @Test
  public void base64url_matchesJwtUtilsPath() {
    // Use case: the public compute() + base64url() pair produces the identical
    // kid that JWTUtils.generateJWS_kidSHA256() returns, so users can swap in
    // the low-level API without changing output.
    byte[] digest = JWKThumbprint.compute("SHA-256", rfc7638Rsa());
    String viaPublic = JWKThumbprint.base64url(digest);
    String viaUtils = JWTUtils.generateJWS_kidSHA256(rfc7638Rsa());
    assertEquals(viaPublic, viaUtils);
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void compute_rejectsNullAlgorithm() {
    JWKThumbprint.compute(null, rfc7638Rsa());
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void compute_rejectsNullKey() {
    JWKThumbprint.compute("SHA-256", null);
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void compute_rejectsUnknownAlgorithm() {
    JWKThumbprint.compute("SHA-000", rfc7638Rsa());
  }
}
