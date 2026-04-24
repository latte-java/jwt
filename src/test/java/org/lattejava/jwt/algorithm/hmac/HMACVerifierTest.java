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

package org.lattejava.jwt.algorithm.hmac;

import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class HMACVerifierTest extends BaseJWTTest {
  @Test
  public void canVerify() {
    // Use case: each algorithm-bound HMAC verifier accepts ONLY its bound algorithm; all other
    // algorithms (including the other HS* siblings) are rejected. This is the algorithm-confusion
    // defence required by RFC 8725 §3.1 -- one verifier == one algorithm.
    String secret = "super-secret-key-that-is-at-least-64-bytes-long-for-sha512-algorithm-compat-requirement!!";
    Verifier hs256 = HMACVerifier.newVerifier(Algorithm.HS256, secret);
    Verifier hs384 = HMACVerifier.newVerifier(Algorithm.HS384, secret);
    Verifier hs512 = HMACVerifier.newVerifier(Algorithm.HS512, secret);

    assertTrue(hs256.canVerify(Algorithm.HS256));
    assertFalse(hs256.canVerify(Algorithm.HS384));
    assertFalse(hs256.canVerify(Algorithm.HS512));

    assertFalse(hs384.canVerify(Algorithm.HS256));
    assertTrue(hs384.canVerify(Algorithm.HS384));
    assertFalse(hs384.canVerify(Algorithm.HS512));

    assertFalse(hs512.canVerify(Algorithm.HS256));
    assertFalse(hs512.canVerify(Algorithm.HS384));
    assertTrue(hs512.canVerify(Algorithm.HS512));

    // Cross-family algorithms always rejected by every HMAC verifier.
    for (Verifier v : new Verifier[]{hs256, hs384, hs512}) {
      assertFalse(v.canVerify(Algorithm.ES256));
      assertFalse(v.canVerify(Algorithm.ES384));
      assertFalse(v.canVerify(Algorithm.ES512));
      assertFalse(v.canVerify(Algorithm.PS256));
      assertFalse(v.canVerify(Algorithm.PS384));
      assertFalse(v.canVerify(Algorithm.PS512));
      assertFalse(v.canVerify(Algorithm.RS256));
      assertFalse(v.canVerify(Algorithm.RS384));
      assertFalse(v.canVerify(Algorithm.RS512));
    }
  }

  @Test
  public void test_wrongSecret() {
    JWT jwt = JWT.builder().subject("123456789").build();
    Signer signer = HMACSigner.newSHA256Signer("super-secret-key-that-is-at-least-32-bytes-long!!");
    String encodedJWT = new JWTEncoder().encode(jwt, signer);

    expectException(InvalidJWTSignatureException.class, () ->
        new JWTDecoder().decode(encodedJWT, VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, "wrong-secret-key-that-is-at-least-32-bytes-long!!"))));
  }

  @Test
  public void test_tamperedSignature() {
    JWT jwt = JWT.builder().subject("123456789").build();
    Signer signer = HMACSigner.newSHA256Signer("super-secret-key-that-is-at-least-32-bytes-long!!");
    String encodedJWT = new JWTEncoder().encode(jwt, signer);

    // Flip the last character of the signature
    char lastChar = encodedJWT.charAt(encodedJWT.length() - 1);
    char flipped = lastChar == 'A' ? 'B' : 'A';
    String tampered = encodedJWT.substring(0, encodedJWT.length() - 1) + flipped;

    expectException(InvalidJWTSignatureException.class, () ->
        new JWTDecoder().decode(tampered, VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, "super-secret-key-that-is-at-least-32-bytes-long!!"))));
  }

  @Test
  public void test_secretIsDefensivelyCopied() {
    // Use case: mutating the original secret array after constructing a verifier must not
    // affect the verifier's behavior -- a post-construction scribble cannot silently change
    // which signatures the verifier accepts.
    String secretString = "super-secret-key-that-is-at-least-32-bytes-long!!";
    byte[] original = secretString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Verifier verifier = HMACVerifier.newVerifier(Algorithm.HS256, original);

    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(secretString));

    // Scribble over the caller's copy
    for (int i = 0; i < original.length; i++) {
      original[i] = 0;
    }

    // Verifier must still validate against the original secret.
    new JWTDecoder().decode(encoded, VerifierResolver.of(verifier));
  }
}
