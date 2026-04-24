/*
 * Copyright (c) 2020-2026, FusionAuth, All Rights Reserved
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
import org.lattejava.jwt.algorithm.KeyCoercion;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * RSASSA-PSS {@link Verifier} for the {@code PS256} / {@code PS384}
 * / {@code PS512} JWA algorithms (RFC 7518 §3.5).
 *
 * <p>Each instance is bound to a single JWA algorithm at construction time;
 * {@link #canVerify(Algorithm)} returns true only for that exact algorithm.
 * Binding at construction prevents algorithm-confusion attacks where a
 * tampered header {@code alg} could coax a family-accepting verifier into
 * using a weaker hash than the caller intended (RFC 8725 §3.1).</p>
 *
 * <p>Each call to {@link #verify(byte[], byte[])} obtains a fresh
 * {@link Signature} instance and configures it with an explicit
 * {@code PSSParameterSpec} so the parameters are not inherited from the
 * JCA provider's defaults.</p>
 *
 * @author Daniel DeGroff
 */
public class RSAPSSVerifier implements Verifier {
  private final Algorithm algorithm;

  private final RSAPublicKey publicKey;

  private RSAPSSVerifier(Algorithm algorithm, PublicKey publicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(publicKey, "publicKey");
    requirePSS(algorithm);
    this.algorithm = algorithm;
    this.publicKey = KeyCoercion.asPublic(publicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
    RSAFamily.assertAcceptablePublicExponent(this.publicKey.getPublicExponent());
  }

  private RSAPSSVerifier(Algorithm algorithm, String pemPublicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(pemPublicKey, "pemPublicKey");
    requirePSS(algorithm);
    this.algorithm = algorithm;
    this.publicKey = KeyCoercion.publicFromPem(pemPublicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
    RSAFamily.assertAcceptablePublicExponent(this.publicKey.getPublicExponent());
  }

  public static RSAPSSVerifier newVerifier(Algorithm algorithm, PublicKey publicKey) {
    return new RSAPSSVerifier(algorithm, publicKey);
  }

  public static RSAPSSVerifier newVerifier(Algorithm algorithm, String pemPublicKey) {
    return new RSAPSSVerifier(algorithm, pemPublicKey);
  }

  public static RSAPSSVerifier newVerifier(Algorithm algorithm, byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    return new RSAPSSVerifier(algorithm, new String(bytes, StandardCharsets.UTF_8));
  }

  public static RSAPSSVerifier newVerifier(Algorithm algorithm, Path path) {
    Objects.requireNonNull(path, "path");
    try {
      return new RSAPSSVerifier(algorithm, new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
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
      Signature verifier = Signature.getInstance("RSASSA-PSS");
      verifier.setParameter(RSAFamily.pssParameterSpec(this.algorithm));
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
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException
             | InvalidAlgorithmParameterException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }

  private static void requirePSS(Algorithm algorithm) {
    switch (algorithm.name()) {
      case "PS256", "PS384", "PS512" -> {
      }
      default -> throw new IllegalArgumentException(
          "Expected RSASSA-PSS algorithm but found [" + algorithm.name() + "]");
    }
  }
}
