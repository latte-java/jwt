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

package org.lattejava.jwt.algorithm.hmac;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidKeyLengthException;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.Signer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * HMAC-based {@link Signer} for the {@code HS256} / {@code HS384} /
 * {@code HS512} JWA algorithms (RFC 7518 §3.2).
 *
 * <p>Each call to {@link #sign(byte[])} obtains a fresh {@link Mac}
 * instance ({@link Mac} is not thread-safe).</p>
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
    HMACFamily.assertMinimumSecretLength(algorithm, secret);

    this.algorithm = algorithm;
    this.kid = kid;
    // Defensive copy so callers cannot mutate the signer's secret after construction.
    this.secret = secret.clone();
  }

  private HMACSigner(Algorithm algorithm, String secret, String kid) {
    this(algorithm, secret == null ? null : secret.getBytes(StandardCharsets.UTF_8), kid);
  }

  public static HMACSigner newSHA256Signer(byte[] secret) {
    return new HMACSigner(Algorithm.HS256, secret, null);
  }

  public static HMACSigner newSHA256Signer(String secret) {
    return new HMACSigner(Algorithm.HS256, secret, null);
  }

  public static HMACSigner newSHA256Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  public static HMACSigner newSHA256Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  public static HMACSigner newSHA384Signer(byte[] secret) {
    return new HMACSigner(Algorithm.HS384, secret, null);
  }

  public static HMACSigner newSHA384Signer(String secret) {
    return new HMACSigner(Algorithm.HS384, secret, null);
  }

  public static HMACSigner newSHA384Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  public static HMACSigner newSHA384Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  public static HMACSigner newSHA512Signer(byte[] secret) {
    return new HMACSigner(Algorithm.HS512, secret, null);
  }

  public static HMACSigner newSHA512Signer(String secret) {
    return new HMACSigner(Algorithm.HS512, secret, null);
  }

  public static HMACSigner newSHA512Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
  }

  public static HMACSigner newSHA512Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
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
  public byte[] sign(byte[] message) {
    Objects.requireNonNull(message);
    String jcaName = HMACFamily.toJCA(algorithm);
    try {
      Mac mac = Mac.getInstance(jcaName);
      mac.init(new SecretKeySpec(secret, jcaName));
      return mac.doFinal(message);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
