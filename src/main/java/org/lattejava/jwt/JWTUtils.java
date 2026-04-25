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

package org.lattejava.jwt;

import org.lattejava.jwt.internal.pem.PEM;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helper to generate new HMAC secrets, EC and RSA public / private key pairs and other fun things.
 *
 * @author Daniel DeGroff
 */
public class JWTUtils {
  /**
   * Generate a new public / private key pair using a 2048-bit RSA key. This is the minimum key length for use with an
   * RSA signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate2048_RSAKeyPair() {
    return generateKeyPair("RSA", 2048);
  }

  /**
   * Generate a new public / private key pair using a 2048-bit RSA PSS key. This is the minimum key length for use with an
   * RSA PSS signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate2048_RSAPSSKeyPair() {
    return generateKeyPair("RSASSA-PSS", 2048);
  }

  /**
   * Generate a new public / private key pair using a 3072-bit RSA PSS key. This is the minimum key length for use with an
   * RSA PSS signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate3072_RSAPSSKeyPair() {
    return generateKeyPair("RSASSA-PSS", 3072);
  }

  /**
   * Generate a new public / private key pair using a 4096-bit RSA PSS key. This is the minimum key length for use with an
   * RSA PSS signing scheme for JWT.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate4096_RSAPSSKeyPair() {
    return generateKeyPair("RSASSA-PSS", 4096);
  }

  /**
   * Generate a new public / private key pair using a 256 bit EC key. A 256 bit EC key is roughly equivalent to a 3072 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate256_ECKeyPair() {
    return generateKeyPair("EC", 256);
  }

  /**
   * Generate a new public / private key pair using a 3072-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate3072_RSAKeyPair() {
    return generateKeyPair("RSA", 3072);
  }

  /**
   * Generate a new public / private key pair using a 384-bit EC key. A 384 bit EC key is roughly equivalent to a 7680 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate384_ECKeyPair() {
    return generateKeyPair("EC", 384);
  }

  /**
   * Generate a new public / private key pair using a 4096-bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate4096_RSAKeyPair() {
    return generateKeyPair("RSA", 4096);
  }

  /**
   * Generate a new public / private key pair using a 521 bit EC key. A 521 bit EC key is roughly equivalent to a 15,360 bit RSA key.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate521_ECKeyPair() {
    return generateKeyPair("EC", 521);
  }

  /**
   * Generate a new public / private key pair using the Ed25529 curve.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate_ed25519_EdDSAKeyPair() {
    return generateKeyPair("ed25519", null);
  }

  /**
   * Generate a new public / private key pair using the Ed448 curve.
   *
   * @return a public and private key PEM in their respective X.509 and PKCS#8 key formats.
   */
  public static KeyPair generate_ed448_EdDSAKeyPair() {
    return generateKeyPair("ed448", null);
  }

  /**
   * Generate a 32 byte (256 bit) HMAC secret for use with a SHA-256 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA256_HMACSecret() {
    return generateSecureRandom(32);
  }

  /**
   * Generate a 48 byte (384 bit) HMAC secret for use with a SHA-384 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA384_HMACSecret() {
    return generateSecureRandom(48);
  }

  /**
   * Generate a 64 byte (512 bit) HMAC secret for use with a SHA-512 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA512_HMACSecret() {
    return generateSecureRandom(64);
  }

  /**
   * Return a secure random string
   *
   * @param bytes the number of bytes used to generate the random byte array to be encoded.
   * @return a random string.
   */
  public static String generateSecureRandom(int bytes) {
    byte[] buffer = new byte[bytes];
    new SecureRandom().nextBytes(buffer);
    return Base64.getEncoder().encodeToString(buffer);
  }

  /**
   * Generate a new Public / Private key pair with a key size of the provided length.
   *
   * @param algorithm the algorithm to use to generate the key pair
   * @param keySize   the optional key size when applicable
   * @return a public and private key in PEM format.
   */
  private static KeyPair generateKeyPair(String algorithm, Integer keySize) {
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
