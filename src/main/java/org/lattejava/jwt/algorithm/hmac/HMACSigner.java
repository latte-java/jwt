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

import java.nio.charset.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.Signer;

/**
 * HMAC-based {@link Signer} for the {@code HS256} / {@code HS384} / {@code HS512} JWA algorithms (RFC 7518 §3.2).
 *
 * <p>The JCA algorithm name and {@link SecretKeySpec} are cached at construction so
 * {@link #sign(byte[])} skips the per-call allocation and the redundant defensive copy of
 * the secret. The {@link Mac} instance itself is also initialised once in the constructor
 * and reused across calls; {@link Mac} is not thread-safe so {@link #sign(byte[])}
 * synchronises on it. Lock cost is essentially free at low/medium concurrency under
 * HotSpot biased locking; under extreme concurrency on a single shared signer the lock
 * will become a contention point, in which case callers can construct one signer per
 * thread or per partition.</p>
 *
 * @author Daniel DeGroff
 */
public class HMACSigner implements Signer {
  private final Algorithm algorithm;
  private final String jcaName;
  private final SecretKeySpec keySpec;
  private final String kid;
  private final Mac mac;

  private HMACSigner(Algorithm algorithm, byte[] secret, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(secret);
    HMACFamily.assertMinimumSecretLength(algorithm, secret);

    this.algorithm = algorithm;
    this.jcaName = HMACFamily.toJCA(algorithm);
    // SecretKeySpec clones the secret internally, satisfying the defensive-copy contract.
    this.keySpec = new SecretKeySpec(secret, jcaName);
    this.kid = kid;
    try {
      this.mac = Mac.getInstance(jcaName);
      this.mac.init(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new JWTSigningException("An unexpected exception occurred when initialising HMAC for [" + jcaName + "]", e);
    }
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
    // Mac.doFinal implicitly resets the Mac so the same instance is reusable across calls.
    // Synchronise because Mac is not thread-safe; biased locking makes the uncontended
    // case effectively free.
    synchronized (mac) {
      return mac.doFinal(message);
    }
  }
}
