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
 * <p>Signature comparison uses
 * {@link MessageDigest#isEqual(byte[], byte[])} -- documented as
 * constant-time since JDK 7u40 (JDK-8006276) -- to avoid leaking the
 * valid MAC via comparison-timing side channels.</p>
 *
 * <p>Each call to {@link #verify(Algorithm, byte[], byte[])} obtains a
 * fresh {@link Mac} instance ({@link Mac} is not thread-safe).</p>
 *
 * @author Daniel DeGroff
 */
public class HMACVerifier implements Verifier {
  private final byte[] secret;

  private HMACVerifier(byte[] secret) {
    Objects.requireNonNull(secret);
    this.secret = secret;
  }

  private HMACVerifier(String secret) {
    this(secret == null ? null : secret.getBytes(StandardCharsets.UTF_8));
  }

  public static HMACVerifier newVerifier(String secret) {
    return new HMACVerifier(secret);
  }

  public static HMACVerifier newVerifier(byte[] bytes) {
    return new HMACVerifier(bytes);
  }

  public static HMACVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);
    try {
      return new HMACVerifier(Files.readAllBytes(path));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "HS256", "HS384", "HS512" -> true;
      default -> false;
    };
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);
    HMACFamily.assertMinimumSecretLength(algorithm, secret);

    String jcaName = HMACFamily.toJCA(algorithm);
    try {
      Mac mac = Mac.getInstance(jcaName);
      mac.init(new SecretKeySpec(secret, jcaName));
      byte[] expected = mac.doFinal(message);
      if (!MessageDigest.isEqual(signature, expected)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
