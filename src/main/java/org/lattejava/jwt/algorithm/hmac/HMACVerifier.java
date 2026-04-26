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
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.Verifier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * HMAC-based {@link Verifier} for the {@code HS256} / {@code HS384} /
 * {@code HS512} JWA algorithms (RFC 7518 §3.2).
 *
 * <p>Each instance is bound to a single JWA algorithm at construction time;
 * {@link #canVerify(Algorithm)} returns true only for that exact algorithm.
 * Binding at construction prevents algorithm-confusion attacks where a
 * tampered header {@code alg} could coax a family-accepting verifier into
 * using a weaker hash than the caller intended (RFC 8725 §3.1).</p>
 *
 * <p>Signature comparison uses
 * {@link MessageDigest#isEqual(byte[], byte[])} -- documented as
 * constant-time since JDK 7u40 (JDK-8006276) -- to avoid leaking the
 * valid MAC via comparison-timing side channels.</p>
 *
 * <p>The JCA algorithm name and {@link SecretKeySpec} are cached at
 * construction so {@link #verify(byte[], byte[])} skips the per-call
 * allocation and the redundant defensive copy of the secret. Each call
 * still obtains a fresh {@link Mac} instance ({@link Mac} is not
 * thread-safe).</p>
 *
 * @author Daniel DeGroff
 */
public class HMACVerifier implements Verifier {
  private final Algorithm algorithm;
  private final String jcaName;
  private final SecretKeySpec keySpec;

  private HMACVerifier(Algorithm algorithm, byte[] secret) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(secret, "secret");
    requireHMAC(algorithm);
    HMACFamily.assertMinimumSecretLength(algorithm, secret);
    this.algorithm = algorithm;
    this.jcaName = HMACFamily.toJCA(algorithm);
    // SecretKeySpec clones the secret internally, satisfying the defensive-copy contract.
    this.keySpec = new SecretKeySpec(secret, jcaName);
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

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return algorithm != null && this.algorithm.name().equals(algorithm.name());
  }

  @Override
  public void verify(byte[] message, byte[] signature) {
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Mac mac = Mac.getInstance(jcaName);
      mac.init(keySpec);
      byte[] expected = mac.doFinal(message);
      if (!MessageDigest.isEqual(signature, expected)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
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
}
