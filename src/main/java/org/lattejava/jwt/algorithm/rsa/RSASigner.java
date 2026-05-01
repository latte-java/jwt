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

package org.lattejava.jwt.algorithm.rsa;

import java.security.*;
import java.security.interfaces.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.internal.*;

/**
 * RSASSA-PKCS1-v1_5 {@link Signer} for the {@code RS256} / {@code RS384} / {@code RS512} JWA algorithms (RFC 7518
 * §3.3).
 *
 * <p>Each call to {@link #sign(byte[]...)} obtains a fresh
 * {@link Signature} instance ({@link Signature} is not thread-safe).</p>
 *
 * @author Daniel DeGroff
 */
public class RSASigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final RSAPrivateKey privateKey;

  private RSASigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.asPrivate(privateKey, RSAPrivateKey.class);
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  private RSASigner(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(pemPrivateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.privateFromPem(pemPrivateKey, RSAPrivateKey.class);
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  public static RSASigner newSHA256Signer(String pemPrivateKey) {
    return new RSASigner(Algorithm.RS256, pemPrivateKey, null);
  }

  public static RSASigner newSHA256Signer(String pemPrivateKey, String kid) {
    return new RSASigner(Algorithm.RS256, pemPrivateKey, kid);
  }

  public static RSASigner newSHA256Signer(PrivateKey privateKey) {
    return new RSASigner(Algorithm.RS256, privateKey, null);
  }

  public static RSASigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new RSASigner(Algorithm.RS256, privateKey, kid);
  }

  public static RSASigner newSHA384Signer(String pemPrivateKey) {
    return new RSASigner(Algorithm.RS384, pemPrivateKey, null);
  }

  public static RSASigner newSHA384Signer(String pemPrivateKey, String kid) {
    return new RSASigner(Algorithm.RS384, pemPrivateKey, kid);
  }

  public static RSASigner newSHA384Signer(PrivateKey privateKey) {
    return new RSASigner(Algorithm.RS384, privateKey, null);
  }

  public static RSASigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new RSASigner(Algorithm.RS384, privateKey, kid);
  }

  public static RSASigner newSHA512Signer(String pemPrivateKey) {
    return new RSASigner(Algorithm.RS512, pemPrivateKey, null);
  }

  public static RSASigner newSHA512Signer(String pemPrivateKey, String kid) {
    return new RSASigner(Algorithm.RS512, pemPrivateKey, kid);
  }

  public static RSASigner newSHA512Signer(PrivateKey privateKey) {
    return new RSASigner(Algorithm.RS512, privateKey, null);
  }

  public static RSASigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new RSASigner(Algorithm.RS512, privateKey, kid);
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
      Signature signature = Signature.getInstance(RSAFamily.toJCA(algorithm));
      signature.initSign(privateKey);
      for (byte[] segment : segments) {
        Objects.requireNonNull(segment, "segment");
        signature.update(segment);
      }
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
