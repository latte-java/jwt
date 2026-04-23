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
import org.lattejava.jwt.algorithm.KeyCoercion;

import java.io.IOException;
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
 * <p>Each call to {@link #verify(Algorithm, byte[], byte[])} obtains a
 * fresh {@link Signature} instance ({@link Signature} is not thread-safe).</p>
 *
 * @author Daniel DeGroff
 */
public class RSAVerifier implements Verifier {
  private final RSAPublicKey publicKey;

  private RSAVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    this.publicKey = KeyCoercion.asPublic(publicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
  }

  private RSAVerifier(String pemPublicKey) {
    Objects.requireNonNull(pemPublicKey);
    this.publicKey = KeyCoercion.publicFromPem(pemPublicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
  }

  public static RSAVerifier newVerifier(PublicKey publicKey) {
    return new RSAVerifier(publicKey);
  }

  public static RSAVerifier newVerifier(String pemPublicKey) {
    return new RSAVerifier(pemPublicKey);
  }

  public static RSAVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new RSAVerifier(new String(bytes));
  }

  public static RSAVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);
    try {
      return new RSAVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "RS256", "RS384", "RS512" -> true;
      default -> false;
    };
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);
    try {
      Signature verifier = Signature.getInstance(RSAFamily.toJCA(algorithm));
      verifier.initVerify(publicKey);
      verifier.update(message);
      try {
        if (!verifier.verify(signature)) {
          throw new InvalidJWTSignatureException();
        }
      } catch (SignatureException e) {
        throw new InvalidJWTSignatureException(e);
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
