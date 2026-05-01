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

import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.lattejava.jwt.*;

/**
 * HMAC-based {@link Verifier} for the {@code HS256} / {@code HS384} / {@code HS512} JWA algorithms (RFC 7518 §3.2).
 *
 * <p>Each instance is bound to a single JWA algorithm at construction time;
 * {@link #canVerify(Algorithm)} returns true only for that exact algorithm. Binding at construction prevents
 * algorithm-confusion attacks where a tampered header {@code alg} could coax a family-accepting verifier into using a
 * weaker hash than the caller intended (RFC 8725 §3.1).</p>
 *
 * <p>Signature comparison uses
 * {@link MessageDigest#isEqual(byte[], byte[])} -- documented as constant-time since JDK 7u40 (JDK-8006276) -- to avoid
 * leaking the valid MAC via comparison-timing side channels.</p>
 *
 * <p>The JCA algorithm name and {@link SecretKeySpec} are cached at construction so
 * {@link #verify(byte[], byte[])} skips the per-call allocation and the redundant defensive
 * copy of the secret. The {@link Mac} instance itself is also initialised once in the
 * constructor and reused across calls; {@link Mac} is not thread-safe so
 * {@link #verify(byte[], byte[])} synchronises on it. Lock cost is essentially free at
 * low/medium concurrency under HotSpot biased locking; under extreme concurrency on a
 * single shared verifier the lock will become a contention point, in which case callers
 * can construct one verifier per thread or per partition.</p>
 *
 * @author Daniel DeGroff
 */
public class HMACVerifier implements Verifier {
  private final Algorithm algorithm;
  private final String jcaName;
  private final SecretKeySpec keySpec;
  private final Mac mac;

  private HMACVerifier(Algorithm algorithm, byte[] secret) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(secret, "secret");
    requireHMAC(algorithm);
    HMACFamily.assertMinimumSecretLength(algorithm, secret);
    this.algorithm = algorithm;
    this.jcaName = HMACFamily.toJCA(algorithm);
    // SecretKeySpec clones the secret internally, satisfying the defensive-copy contract.
    this.keySpec = new SecretKeySpec(secret, jcaName);
    try {
      this.mac = Mac.getInstance(jcaName);
      this.mac.init(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new JWTVerifierException("An unexpected exception occurred when initialising HMAC for [" + jcaName + "]", e);
    }
  }

  private HMACVerifier(Algorithm algorithm, String secret) {
    this(algorithm, secret == null ? null : secret.getBytes(StandardCharsets.UTF_8));
  }

  public static HMACVerifier newVerifier(Algorithm algorithm, String secret) {
    return new HMACVerifier(algorithm, secret);
  }

  public static HMACVerifier newVerifier(Algorithm algorithm, byte[] bytes) {
    return new HMACVerifier(algorithm, bytes);
  }

  public static HMACVerifier newVerifier(Algorithm algorithm, Path path) {
    Objects.requireNonNull(path, "path");
    try {
      return new HMACVerifier(algorithm, Files.readAllBytes(path));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
  }

  private static void requireHMAC(Algorithm algorithm) {
    switch (algorithm.name()) {
      case "HS256", "HS384", "HS512" -> {
      }
      default -> throw new IllegalArgumentException(
          "Expected HMAC algorithm but found [" + algorithm.name() + "]");
    }
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return algorithm != null && this.algorithm.name().equals(algorithm.name());
  }

  @Override
  public void verify(byte[] message, byte[] signature) {
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);
    // Mac.doFinal implicitly resets the Mac so the same instance is reusable across calls.
    // Synchronise because Mac is not thread-safe; biased locking makes the uncontended
    // case effectively free.
    byte[] expected;
    synchronized (mac) {
      expected = mac.doFinal(message);
    }
    if (!MessageDigest.isEqual(signature, expected)) {
      throw new InvalidJWTSignatureException();
    }
  }
}
