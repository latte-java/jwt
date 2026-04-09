/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.alg.ec;

import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.MissingPrivateKeyException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.domain.Algorithm;
import org.lattejava.jwt.pem.PEM;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class ECSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final ECPrivateKey privateKey;

  private ECSigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;

    if (!(privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = (ECPrivateKey) privateKey;
    validateCurve(this.privateKey, algorithm);
  }

  private ECSigner(Algorithm algorithm, String privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.kid = kid;
    PEM pem = PEM.decode(privateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }

    if (!(pem.privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = pem.getPrivateKey();
    validateCurve(this.privateKey, algorithm);
  }

  private static void validateCurve(ECPrivateKey key, Algorithm algorithm) {
    int fieldSize = key.getParams().getCurve().getField().getFieldSize();
    Algorithm expected = switch (fieldSize) {
      case 256 -> Algorithm.ES256;
      case 384 -> Algorithm.ES384;
      case 521 -> Algorithm.ES512;
      default -> throw new InvalidKeyTypeException("Unsupported EC curve with field size [" + fieldSize + "]. Expected 256, 384, or 521.");
    };
    if (expected != algorithm) {
      throw new InvalidKeyTypeException("The provided EC key uses curve with field size [" + fieldSize + "] which is not compatible with algorithm [" + algorithm.name() + "].");
    }
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-256 hash.
   *
   * @param privateKey The private key.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-384 hash.
   *
   * @param privateKey The private key.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key PEM expected to be in PKCS#1 or PKCS#8 format.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(String privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  /**
   * Build a new EC signer using a SHA-512 hash.
   *
   * @param privateKey The private key.
   * @param kid        The key identifier. This will be used by the JWTEncoder to write the 'kid' header.
   * @return a new EC signer.
   */
  public static ECSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
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
  public byte[] sign(String message) {
    Objects.requireNonNull(message);

    try {
      Signature signature = Signature.getInstance(algorithm.getName() + "inP1363Format");
      signature.initSign(privateKey);
      signature.update((message).getBytes(StandardCharsets.UTF_8));
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
