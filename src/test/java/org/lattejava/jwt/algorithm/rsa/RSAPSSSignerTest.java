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

import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.pem.PEM;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * @author Daniel DeGroff
 */
public class RSAPSSSignerTest extends BaseJWTTest {
  @Test
  public void test_invalidKey() {
    // EC private key cannot be used for an RSA-PSS signer
    try {
      RSAPSSSigner.newSHA256Signer(readFile("ec_private_key_p_256.pem"));
      fail("Expected exception.");
    } catch (InvalidKeyTypeException e) {
      assertTrue(e.getMessage().startsWith("Expecting a private key of type [RSAPrivateKey], but found ["));
    }

    try {
      RSAPSSSigner.newSHA256Signer(PEM.decode(readFile("ec_private_key_p_256.pem")).privateKey);
      fail("Expected exception.");
    } catch (InvalidKeyTypeException e) {
      assertTrue(e.getMessage().startsWith("Expecting a private key of type [RSAPrivateKey], but found ["));
    }
  }

  @Test
  public void test_private_pem_parsing() {
    // No kid
    assertNotNull(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_2048.pem")));
    assertNotNull(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_2048_with_meta.pem")));
    assertNotNull(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_3072.pem")));
    assertNotNull(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_4096.pem")));

    assertNotNull(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_2048.pem")));
    assertNotNull(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_2048_with_meta.pem")));
    assertNotNull(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_3072.pem")));
    assertNotNull(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_4096.pem")));

    assertNotNull(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_2048.pem")));
    assertNotNull(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_2048_with_meta.pem")));
    assertNotNull(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_3072.pem")));
    assertNotNull(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_4096.pem")));

    // RSA PSS keys
    assertNotNull(RSAPSSSigner.newSHA256Signer(readFile("rsa_pss_private_key_2048.pem")));
    assertNotNull(RSAPSSSigner.newSHA384Signer(readFile("rsa_pss_private_key_3072.pem")));
    assertNotNull(RSAPSSSigner.newSHA512Signer(readFile("rsa_pss_private_key_4096.pem")));

    // With kid
    assertEquals(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_2048.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_2048_with_meta.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_3072.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA256Signer(readFile("rsa_private_key_4096.pem"), "abc").getKid(), "abc");

    assertEquals(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_2048.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_2048_with_meta.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_3072.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA384Signer(readFile("rsa_private_key_4096.pem"), "abc").getKid(), "abc");

    assertEquals(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_2048.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_2048_with_meta.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_3072.pem"), "abc").getKid(), "abc");
    assertEquals(RSAPSSSigner.newSHA512Signer(readFile("rsa_private_key_4096.pem"), "abc").getKid(), "abc");
  }
}
