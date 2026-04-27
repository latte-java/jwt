/*
 * Copyright (c) 2016-2026, FusionAuth, All Rights Reserved
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

import java.security.*;

import org.lattejava.jwt.internal.pem.*;

/**
 * Static factories for generating asymmetric {@link KeyPair} values for use with JWT signing schemes.
 *
 * @author Daniel DeGroff
 */
public class KeyPairs {
  /**
   * Generate a new public / private key pair using a 256-bit EC key. A 256-bit EC key is roughly equivalent to a
   * 3072-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateEC_256() {
    return generate("EC", 256);
  }

  /**
   * Generate a new public / private key pair using a 384-bit EC key. A 384-bit EC key is roughly equivalent to a
   * 7680-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateEC_384() {
    return generate("EC", 384);
  }

  /**
   * Generate a new public / private key pair using a 521-bit EC key. A 521-bit EC key is roughly equivalent to a
   * 15,360-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateEC_521() {
    return generate("EC", 521);
  }

  /**
   * Generate a new public / private key pair using the Ed25519 curve.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateEd25519() {
    return generate("ed25519", null);
  }

  /**
   * Generate a new public / private key pair using the Ed448 curve.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateEd448() {
    return generate("ed448", null);
  }

  /**
   * Generate a new public / private key pair using a 2048-bit RSA-PSS key. This is the minimum key length for use with
   * an RSA-PSS signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateRSAPSS_2048() {
    return generate("RSASSA-PSS", 2048);
  }

  /**
   * Generate a new public / private key pair using a 3072-bit RSA-PSS key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateRSAPSS_3072() {
    return generate("RSASSA-PSS", 3072);
  }

  /**
   * Generate a new public / private key pair using a 4096-bit RSA-PSS key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateRSAPSS_4096() {
    return generate("RSASSA-PSS", 4096);
  }

  /**
   * Generate a new public / private key pair using a 2048-bit RSA key. This is the minimum key length for use with an
   * RSA signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateRSA_2048() {
    return generate("RSA", 2048);
  }

  /**
   * Generate a new public / private key pair using a 3072-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateRSA_3072() {
    return generate("RSA", 3072);
  }

  /**
   * Generate a new public / private key pair using a 4096-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generateRSA_4096() {
    return generate("RSA", 4096);
  }

  private static KeyPair generate(String algorithm, Integer keySize) {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
      if (keySize != null) {
        keyPairGenerator.initialize(keySize);
      }
      java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

      String privateKey = PEM.encode(keyPair.getPrivate(), keyPair.getPublic());
      String publicKey = PEM.encode(keyPair.getPublic());
      return new KeyPair(privateKey, publicKey);
    } catch (NoSuchAlgorithmException e) {
      throw new JWTSigningException("Required key pair algorithm [" + algorithm + "] is not registered with this JVM", e);
    }
  }
}
