/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.algorithm.ec;

import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.MissingPublicKeyException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.pem.PEM;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class ECVerifierTest extends BaseJWTTest {
  @Test
  public void test_public_pem_parsing() {
    // Each key can only verify its own curve's algorithm
    assertECVerifierForFile("ec_public_key_p_256.pem", Algorithm.ES256);
    assertECVerifierForFile("ec_public_key_p_384.pem", Algorithm.ES384);
    assertECVerifierForFile("ec_public_key_p_521.pem", Algorithm.ES512);

    // Public key parsing fails with private keys w/out an encoded public key
    Arrays.asList(
            "ec_private_key_p_256.pem",
            "ec_private_key_p_384.pem",
            "ec_private_key_p_521.pem")
        .forEach(this::assertFailed);

    // Public key parsing works with private keys when the private key contains a public key
    assertECVerifierForFile("ec_private_prime256v1_p_256_openssl.pem", Algorithm.ES256);
    assertECVerifierForFile("ec_private_prime256v1_p_256_openssl_pkcs8.pem", Algorithm.ES256);
    assertECVerifierForFile("ec_private_secp384r1_p_384_openssl.pem", Algorithm.ES384);
    assertECVerifierForFile("ec_private_secp384r1_p_384_openssl_pkcs8.pem", Algorithm.ES384);
    assertECVerifierForFile("ec_private_secp521r1_p_512_openssl.pem", Algorithm.ES512);
    assertECVerifierForFile("ec_private_secp521r1_p_512_openssl_pkcs8.pem", Algorithm.ES512);
  }

  private void assertECVerifierForFile(String fileName, Algorithm expectedAlgorithm) {
    assertECVerifier(ECVerifier.newVerifier(getPath(fileName)), expectedAlgorithm);
    assertECVerifier(ECVerifier.newVerifier(readFile(fileName)), expectedAlgorithm);
    assertECVerifier(ECVerifier.newVerifier(readFile(fileName).getBytes(StandardCharsets.UTF_8)), expectedAlgorithm);
    assertECVerifier(ECVerifier.newVerifier((ECPublicKey) PEM.decode(readFile(fileName)).getPublicKey()), expectedAlgorithm);
  }

  private void assertECVerifier(Verifier verifier, Algorithm expectedAlgorithm) {
    // Only the curve-matching algorithm should return true
    for (Algorithm alg : Algorithm.standardValues()) {
      if (alg == expectedAlgorithm) {
        assertTrue(verifier.canVerify(alg), "Expected canVerify(" + alg + ") to be true");
      } else {
        assertFalse(verifier.canVerify(alg), "Expected canVerify(" + alg + ") to be false");
      }
    }
  }

  private void assertFailed(String fileName) {
    try {
      ECVerifier.newVerifier(readFile(fileName));
      Assert.fail("Expected [MissingPublicKeyException] exception");
    } catch (MissingPublicKeyException e) {
      assertEquals(e.getMessage(), "PEM did not contain a public key", "[" + fileName + "]");
    } catch (Exception e) {
      Assert.fail("Unexpected exception when parsing file [" + fileName + "]", e);
    }
  }
}
