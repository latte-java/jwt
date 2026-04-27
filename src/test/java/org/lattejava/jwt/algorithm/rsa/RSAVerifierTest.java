/*
 * Copyright (c) 2017-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.algorithm.rsa;

import java.nio.charset.*;
import java.nio.file.*;
import java.security.interfaces.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.internal.pem.*;
import org.testng.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * @author Daniel DeGroff
 */
public class RSAVerifierTest extends BaseJWTTest {
  @Test
  public void test_public_pem_parsing() {
    Arrays.asList(
              "rsa_certificate_2048.pem",
              "rsa_public_key_2047.pem",
              "rsa_public_key_2048.pem",
              "rsa_public_key_2048_with_meta.pem",
              "rsa_public_key_3072.pem",
              "rsa_public_key_4096.pem",
              "rsa_pss_public_key_2048.pem",
              "rsa_pss_public_key_3072.pem",
              "rsa_pss_public_key_4096.pem")
          .forEach(fileName -> {
            for (Algorithm alg : new Algorithm[]{Algorithm.RS256, Algorithm.RS384, Algorithm.RS512}) {
              // Take a Path arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, getPath(fileName)), alg);
              // Take a String arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, readFile(fileName)), alg);
              // Take a byte[] arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, readFile(fileName).getBytes(StandardCharsets.UTF_8)), alg);
              // Take a public key arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, (RSAPublicKey) PEM.decode(readFile(fileName)).getPublicKey()), alg);
            }
          });

    // Public key parsing also works with private keys since the public key is encoded in the private
    Arrays.asList(
              "rsa_private_key_2048.pem",
              "rsa_private_key_2048_with_meta.pem",
              "rsa_private_key_3072.pem",
              "rsa_private_key_4096.pem",
              "rsa_pss_private_key_2048.pem",
              "rsa_pss_private_key_3072.pem",
              "rsa_pss_private_key_4096.pem")
          .forEach((fileName -> {
            for (Algorithm alg : new Algorithm[]{Algorithm.RS256, Algorithm.RS384, Algorithm.RS512}) {
              // Take a Path arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, getPath(fileName)), alg);
              // Take a String arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, readFile(fileName)), alg);
              // Take a byte[] arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, readFile(fileName).getBytes(StandardCharsets.UTF_8)), alg);
              // Take a public key arg
              assertRSAVerifier(RSAVerifier.newVerifier(alg, (RSAPublicKey) PEM.decode(readFile(fileName)).getPublicKey()), alg);
            }
          }));
  }

  @Test
  public void test_rsa_1024_pem() {
    try {
      RSAVerifier.newVerifier(Algorithm.RS256, new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_1024.pem"))));
      Assert.fail("Expected [InvalidKeyLengthException] exception");
    } catch (InvalidKeyLengthException ignore) {
    } catch (Exception e) {
      Assert.fail("Unexpected exception", e);
    }
  }

  private void assertRSAVerifier(Verifier verifier, Algorithm bound) {
    // Use case: verifier accepts ONLY its bound RS* algorithm; every other algorithm rejected.
    assertFalse(verifier.canVerify(Algorithm.ES256));
    assertFalse(verifier.canVerify(Algorithm.ES384));
    assertFalse(verifier.canVerify(Algorithm.ES512));

    assertFalse(verifier.canVerify(Algorithm.HS256));
    assertFalse(verifier.canVerify(Algorithm.HS384));
    assertFalse(verifier.canVerify(Algorithm.HS512));

    assertFalse(verifier.canVerify(Algorithm.PS256));
    assertFalse(verifier.canVerify(Algorithm.PS384));
    assertFalse(verifier.canVerify(Algorithm.PS512));

    assertEquals(verifier.canVerify(Algorithm.RS256), bound == Algorithm.RS256);
    assertEquals(verifier.canVerify(Algorithm.RS384), bound == Algorithm.RS384);
    assertEquals(verifier.canVerify(Algorithm.RS512), bound == Algorithm.RS512);
  }
}
