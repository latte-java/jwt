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

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.internal.KeyCoercion;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * RSASSA-PKCS1-v1_5 {@link Verifier} for the {@code RS256} / {@code RS384}
 * / {@code RS512} JWA algorithms (RFC 7518 §3.3).
 *
 * <p>Each instance is bound to a single JWA algorithm at construction time;
 * {@link #canVerify(Algorithm)} returns true only for that exact algorithm.
 * Binding at construction prevents algorithm-confusion attacks where a
 * tampered header {@code alg} could coax a family-accepting verifier into
 * using a weaker hash than the caller intended (RFC 8725 §3.1).</p>
 *
 * <p>Each call to {@link #verify(byte[], byte[])} obtains a fresh
 * {@link Signature} instance ({@link Signature} is not thread-safe).</p>
 *
 * @author Daniel DeGroff
 */
public class RSAVerifier implements Verifier {
  private final Algorithm algorithm;

  private final RSAPublicKey publicKey;

  private RSAVerifier(Algorithm algorithm, PublicKey publicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(publicKey, "publicKey");
    requireRSA(algorithm);
    this.algorithm = algorithm;
    this.publicKey = KeyCoercion.asPublic(publicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
    RSAFamily.assertAcceptablePublicExponent(this.publicKey.getPublicExponent());
  }

  private RSAVerifier(Algorithm algorithm, String pemPublicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(pemPublicKey, "pemPublicKey");
    requireRSA(algorithm);
    this.algorithm = algorithm;
    this.publicKey = KeyCoercion.publicFromPem(pemPublicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
    RSAFamily.assertAcceptablePublicExponent(this.publicKey.getPublicExponent());
  }

  public static RSAVerifier newVerifier(Algorithm algorithm, PublicKey publicKey) {
    return new RSAVerifier(algorithm, publicKey);
  }

  public static RSAVerifier newVerifier(Algorithm algorithm, String pemPublicKey) {
    return new RSAVerifier(algorithm, pemPublicKey);
  }

  public static RSAVerifier newVerifier(Algorithm algorithm, byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    return new RSAVerifier(algorithm, new String(bytes, StandardCharsets.UTF_8));
  }

  public static RSAVerifier newVerifier(Algorithm algorithm, Path path) {
    Objects.requireNonNull(path, "path");
    try {
      return new RSAVerifier(algorithm, new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
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
      Signature verifier = Signature.getInstance(RSAFamily.toJCA(this.algorithm));
      verifier.initVerify(publicKey);
      verifier.update(message);
      try {
        if (!verifier.verify(signature)) {
          throw new InvalidJWTSignatureException();
        }
      } catch (SignatureException e) {
        // JCA signals malformed/truncated signature bytes via SignatureException. The cause
        // is intentionally dropped: the bare exception type is the signal.
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }

  private static void requireRSA(Algorithm algorithm) {
    switch (algorithm.name()) {
      case "RS256", "RS384", "RS512" -> {
      }

      default -> throw new IllegalArgumentException(
          "Expected RSASSA-PKCS1-v1_5 algorithm but found [" + algorithm.name() + "]");
    }
  }
}
