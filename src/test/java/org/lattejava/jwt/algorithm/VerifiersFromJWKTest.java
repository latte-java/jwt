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

package org.lattejava.jwt.algorithm;

import org.lattejava.jwt.BaseTest;
import org.lattejava.jwt.jwks.JSONWebKey;
import org.testng.annotations.Test;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.Verifiers;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class VerifiersFromJWKTest extends BaseTest {
  private static Map<String, Object> rsaJWKBase() {
    Map<String, Object> m = new HashMap<>();
    m.put("kty", "RSA");
    m.put("kid", "k1");
    m.put("alg", "RS256");
    m.put("use", "sig");
    m.put("n", "sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw");
    m.put("e", "AQAB");
    return m;
  }

  @Test
  public void toPublicKey_RSA_returns_RSAPublicKey() {
    // Use case: instance shorthand for JSONWebKey.parse(this) returns the same PublicKey.
    JSONWebKey jwk = JSONWebKey.fromMap(rsaJWKBase());
    PublicKey publicKey = jwk.toPublicKey();
    assertNotNull(publicKey);
    assertTrue(publicKey instanceof RSAPublicKey);
  }

  @Test
  public void fromJWK_RSA_happyPath_returnsVerifier() {
    // Use case: well-formed RSA JWK with kid and alg yields a usable Verifier.
    JSONWebKey jwk = JSONWebKey.fromMap(rsaJWKBase());
    Verifier v = Verifiers.fromJWK(jwk);
    assertNotNull(v);
    assertTrue(v.canVerify(Algorithm.RS256));
  }

  @Test
  public void fromJWK_missingKid_returnsNull() {
    // Use case: kid is required for kid-keyed resolution.
    Map<String, Object> m = rsaJWKBase();
    m.remove("kid");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_missingAlg_returnsNull() {
    // Use case: alg is required to construct a 1:1-bound verifier.
    Map<String, Object> m = rsaJWKBase();
    m.remove("alg");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_HMACAlg_returnsNull() {
    // Use case: HMAC algorithms do not belong on a public JWKS.
    Map<String, Object> m = new HashMap<>();
    m.put("kty", "oct");
    m.put("kid", "k1");
    m.put("alg", "HS256");
    m.put("k", "AAAA");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_octKty_returnsNull() {
    // Use case: symmetric secrets do not belong on a public JWKS.
    Map<String, Object> m = new HashMap<>();
    m.put("kty", "oct");
    m.put("kid", "k1");
    m.put("alg", "RS256");
    m.put("k", "AAAA");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_useEnc_returnsNull() {
    // Use case: encryption-use keys are not signature verifiers.
    Map<String, Object> m = rsaJWKBase();
    m.put("use", "enc");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_useNullIsAllowed() {
    // Use case: absent use is permitted (RFC 7517 makes use optional).
    Map<String, Object> m = rsaJWKBase();
    m.remove("use");
    assertNotNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_ECAlgCrvMismatch_returnsNull() {
    // Use case: alg=ES256 with crv=P-384 is structurally inconsistent; reject.
    Map<String, Object> m = new HashMap<>();
    m.put("kty", "EC");
    m.put("kid", "k1");
    m.put("alg", "ES256");
    m.put("crv", "P-384");
    m.put("x", "AAAA");
    m.put("y", "AAAA");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_OKPAlgCrvMismatch_returnsNull() {
    // Use case: alg=Ed25519 with crv=Ed448 is rejected.
    Map<String, Object> m = new HashMap<>();
    m.put("kty", "OKP");
    m.put("kid", "k1");
    m.put("alg", "Ed25519");
    m.put("crv", "Ed448");
    m.put("x", "AAAA");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }

  @Test
  public void fromJWK_parseFailure_returnsNull() {
    // Use case: malformed key material is skipped, not propagated as an exception.
    Map<String, Object> m = rsaJWKBase();
    m.put("n", "***not-base64url***");
    assertNull(Verifiers.fromJWK(JSONWebKey.fromMap(m)));
  }
}
