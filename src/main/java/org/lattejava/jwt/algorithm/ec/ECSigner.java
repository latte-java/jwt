/*
 * Copyright (c) 2018-2026, FusionAuth, All Rights Reserved
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

import java.security.*;
import java.security.interfaces.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.internal.*;

/**
 * ECDSA {@link Signer} for the {@code ES256} / {@code ES384} / {@code ES512} / {@code ES256K} JWA algorithms (RFC 7518
 * §3.4 and RFC 8812 §3.2).
 *
 * <p>Each call to {@link #sign(byte[]...)} obtains a fresh {@link Signature}
 * instance ({@link Signature} is not thread-safe), produces a DER-encoded ECDSA signature, then converts it to JOSE
 * {@code R || S} fixed-length form via {@link JOSEConverter#derToJose(byte[], int)}.</p>
 *
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
    this.privateKey = KeyCoercion.asPrivate(privateKey, ECPrivateKey.class);
    ECFamily.assertCurveMatchesAlgorithm(this.privateKey.getParams(), algorithm);
  }

  private ECSigner(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(pemPrivateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.privateFromPem(pemPrivateKey, ECPrivateKey.class);
    ECFamily.assertCurveMatchesAlgorithm(this.privateKey.getParams(), algorithm);
  }

  public static ECSigner newSHA256Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES256, pemPrivateKey, null);
  }

  public static ECSigner newSHA256Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES256, pemPrivateKey, kid);
  }

  public static ECSigner newSHA256Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  public static ECSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  public static ECSigner newSHA384Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES384, pemPrivateKey, null);
  }

  public static ECSigner newSHA384Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES384, pemPrivateKey, kid);
  }

  public static ECSigner newSHA384Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  public static ECSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  public static ECSigner newSHA512Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES512, pemPrivateKey, null);
  }

  public static ECSigner newSHA512Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES512, pemPrivateKey, kid);
  }

  public static ECSigner newSHA512Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  public static ECSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
  }

  public static ECSigner newSecp256k1Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES256K, pemPrivateKey, null);
  }

  public static ECSigner newSecp256k1Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES256K, pemPrivateKey, kid);
  }

  public static ECSigner newSecp256k1Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256K, privateKey, null);
  }

  public static ECSigner newSecp256k1Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256K, privateKey, kid);
  }

  @Override
  public Algorithm algorithm() {
    return algorithm;
  }

  @Override
  public String kid() {
    return kid;
  }

  @Override
  public byte[] sign(byte[]... segments) {
    Objects.requireNonNull(segments);
    try {
      Signature signature = Signature.getInstance(ECFamily.toJCA(algorithm));
      signature.initSign(privateKey);
      for (byte[] segment : segments) {
        signature.update(segment);
      }
      byte[] der = signature.sign();
      return JOSEConverter.derToJose(der, ECFamily.curveIntLength(algorithm));
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
