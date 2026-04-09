/*
 * Copyright (c) 2025, the latte-java project authors
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
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.JWT;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class HMACVerifierTest extends BaseJWTTest {
  @Test
  public void canVerify() {
    Verifier verifier = HMACVerifier.newVerifier("super-secret-key-that-is-at-least-64-bytes-long-for-sha512-algorithm-compat-requirement!!");

    assertFalse(verifier.canVerify(Algorithm.ES256));
    assertFalse(verifier.canVerify(Algorithm.ES384));
    assertFalse(verifier.canVerify(Algorithm.ES512));

    assertTrue(verifier.canVerify(Algorithm.HS256));
    assertTrue(verifier.canVerify(Algorithm.HS384));
    assertTrue(verifier.canVerify(Algorithm.HS512));

    assertFalse(verifier.canVerify(Algorithm.PS256));
    assertFalse(verifier.canVerify(Algorithm.PS384));
    assertFalse(verifier.canVerify(Algorithm.PS512));

    assertFalse(verifier.canVerify(Algorithm.RS256));
    assertFalse(verifier.canVerify(Algorithm.RS384));
    assertFalse(verifier.canVerify(Algorithm.RS512));
  }

  @Test
  public void test_wrongSecret() {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = HMACSigner.newSHA256Signer("super-secret-key-that-is-at-least-32-bytes-long!!");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);

    expectException(InvalidJWTSignatureException.class, () ->
        JWT.getDecoder().decode(encodedJWT, HMACVerifier.newVerifier("wrong-secret-key-that-is-at-least-32-bytes-long!!")));
  }

  @Test
  public void test_tamperedSignature() {
    JWT jwt = new JWT().setSubject("123456789");
    Signer signer = HMACSigner.newSHA256Signer("super-secret-key-that-is-at-least-32-bytes-long!!");
    String encodedJWT = JWT.getEncoder().encode(jwt, signer);

    // Flip the last character of the signature
    char lastChar = encodedJWT.charAt(encodedJWT.length() - 1);
    char flipped = lastChar == 'A' ? 'B' : 'A';
    String tampered = encodedJWT.substring(0, encodedJWT.length() - 1) + flipped;

    expectException(InvalidJWTSignatureException.class, () ->
        JWT.getDecoder().decode(tampered, HMACVerifier.newVerifier("super-secret-key-that-is-at-least-32-bytes-long!!")));
  }
}
