/*
 * Copyright (c) 2016-2020, FusionAuth, All Rights Reserved
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

import org.lattejava.jwt.InvalidKeyLengthException;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.Algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * This class can sign and verify a JWT that was signed using HMAC.
 *
 * @author Daniel DeGroff
 */
public class HMACSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final byte[] secret;

  private HMACSigner(Algorithm algorithm, byte[] secret, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(secret);
    assertMinimumSecretLength(algorithm, secret);

    this.algorithm = algorithm;
    this.kid = kid;
    this.secret = secret;
  }

  private HMACSigner(Algorithm algorithm, String secret, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(secret);

    this.algorithm = algorithm;
    this.kid = kid;
    this.secret = secret.getBytes(StandardCharsets.UTF_8);
    assertMinimumSecretLength(algorithm, this.secret);
  }

  // RFC 7518 Section 3.2: "A key of the same size as the hash output or larger MUST be used with this algorithm."
  private static void assertMinimumSecretLength(Algorithm algorithm, byte[] secret) {
    int minimumLength = switch (algorithm.name()) {
      case "HS256" -> 32;
      case "HS384" -> 48;
      case "HS512" -> 64;
      default -> 0;
    };
    if (secret.length < minimumLength) {
      throw new InvalidKeyLengthException("Secret length of [" + secret.length + "] bytes is less than the required length of [" + minimumLength + "] bytes for algorithm [" + algorithm.name() + "].");
    }
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(byte[] secret) {
    return newSHA256Signer(secret, null);
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(String secret) {
    return newSHA256Signer(secret, null);
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  /**
   * Build a new HMAC signer using a SHA-256 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA256Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(byte[] secret) {
    return newSHA384Signer(secret, null);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(String secret) {
    return newSHA384Signer(secret, null);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  /**
   * Build a new HMAC signer using a SHA-384 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA384Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(byte[] secret) {
    return newSHA512Signer(secret, null);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(String secret) {
    return newSHA512Signer(secret, null);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
  }

  /**
   * Build a new HMAC signer using a SHA-512 hash.
   *
   * @param secret The secret used to generate the HMAC hash.
   * @param kid    The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new HMAC signer.
   */
  public static HMACSigner newSHA512Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
  }

  @Override
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getKid() {
    return kid;
  }

  @Override
  public byte[] sign(byte[] message) {
    Objects.requireNonNull(message);

    try {
      String jcaName = org.lattejava.jwt.internal.JCAAlgorithmMapping.toJCA(algorithm);
      Mac mac = Mac.getInstance(jcaName);
      mac.init(new SecretKeySpec(secret, jcaName));
      return mac.doFinal(message);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
