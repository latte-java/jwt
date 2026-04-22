/*
 * Copyright (c) 2016-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.algorithm;

import org.lattejava.jwt.Signer;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.lattejava.jwt.algorithm.ec.ECSigner;
import org.lattejava.jwt.algorithm.ec.ECVerifier;
import org.lattejava.jwt.algorithm.ed.EdDSASigner;
import org.lattejava.jwt.algorithm.ed.EdDSAVerifier;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAPSSSigner;
import org.lattejava.jwt.algorithm.rsa.RSAPSSVerifier;
import org.lattejava.jwt.algorithm.rsa.RSASigner;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.testng.annotations.Test;
import org.testng.internal.collections.Pair;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * @author Daniel DeGroff
 */
public class VerifierTest {
  static List<Pair<Pair<Signer, Verifier>, String>> algorithms = new ArrayList<>();

  static {
    try {
      String hmacSecret = "super-secret-key-that-is-at-least-32-bytes-long!!";
      JWT jwt = JWT.builder().subject("123456789").build();
      JWTEncoder encoder = new JWTEncoder();

      String hmacToken = encoder.encode(jwt, HMACSigner.newSHA256Signer(hmacSecret));
      algorithms.add(new Pair<>(new Pair<>(HMACSigner.newSHA256Signer(hmacSecret), HMACVerifier.newVerifier(hmacSecret)), hmacToken));

      String rsaPrivateKey = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_4096.pem")));
      String rsaPublicKey = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_4096.pem")));
      String rsaToken = encoder.encode(jwt, RSASigner.newSHA256Signer(rsaPrivateKey));
      algorithms.add(new Pair<>(new Pair<>(RSASigner.newSHA256Signer(rsaPrivateKey), RSAVerifier.newVerifier(rsaPublicKey)), rsaToken));

      // RSA-PSS
      String rsaPssToken = encoder.encode(jwt, RSAPSSSigner.newSHA256Signer(rsaPrivateKey));
      algorithms.add(new Pair<>(new Pair<>(RSAPSSSigner.newSHA256Signer(rsaPrivateKey), RSAPSSVerifier.newVerifier(rsaPublicKey)), rsaPssToken));

      // EC
      String ecPrivateKey = new String(Files.readAllBytes(Paths.get("src/test/resources/ec_private_key_p_256.pem")));
      String ecPublicKey = new String(Files.readAllBytes(Paths.get("src/test/resources/ec_public_key_p_256.pem")));
      String ecToken = encoder.encode(jwt, ECSigner.newSHA256Signer(ecPrivateKey));
      algorithms.add(new Pair<>(new Pair<>(ECSigner.newSHA256Signer(ecPrivateKey), ECVerifier.newVerifier(ecPublicKey)), ecToken));

      // EdDSA Ed25519
      String ed25519PrivateKey = new String(Files.readAllBytes(Paths.get("src/test/resources/ed_dsa_ed25519_private_key.pem")));
      String ed25519Token = encoder.encode(jwt, EdDSASigner.newSigner(ed25519PrivateKey));
      algorithms.add(new Pair<>(new Pair<>(EdDSASigner.newSigner(ed25519PrivateKey), EdDSAVerifier.newVerifier(Paths.get("src/test/resources/ed_dsa_ed25519_public_key.pem"))), ed25519Token));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void verify() {
    // JWT Subject : 123456789
    for (Pair<Pair<Signer, Verifier>, String> algorithm : algorithms) {

      // Implicit call to verifier.verify and get a JWT back
      try {
        JWT jwt = new JWTDecoder().decode(algorithm.second(), algorithm.first().second());
        assertNotNull(jwt);
        assertEquals(jwt.subject(), "123456789");
      } catch (Exception e) {
        fail("Failed to validate signature.", e);
      }
    }
  }
}
