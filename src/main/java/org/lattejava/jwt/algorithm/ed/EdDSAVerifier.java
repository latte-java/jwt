/*
 * Copyright (c) 2026, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.algorithm.ed;

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
import java.security.interfaces.EdECPublicKey;
import java.util.Objects;

/**
 * EdDSA {@link Verifier} for the {@code Ed25519} / {@code Ed448} JWA
 * algorithms (RFC 8037 §3.1, JOSE registry).
 *
 * <p>The bound JWA algorithm is derived from the key's curve at
 * construction. {@link #verify(Algorithm, byte[], byte[])} re-checks the
 * caller-supplied algorithm against the bound algorithm so a key cannot
 * be cross-used (Ed25519 key handed an Ed448-tagged signature).</p>
 *
 * <p>Each call to {@link #verify(Algorithm, byte[], byte[])} obtains a
 * fresh {@link Signature} instance ({@link Signature} is not thread-safe).</p>
 *
 * @author Daniel DeGroff
 */
public class EdDSAVerifier implements Verifier {
  private final Algorithm algorithm;

  private final EdECPublicKey publicKey;

  private EdDSAVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    this.publicKey = KeyCoercion.asPublic(publicKey, EdECPublicKey.class);
    this.algorithm = EdDSAFamily.algorithmForCurveName(this.publicKey.getParams().getName());
  }

  private EdDSAVerifier(String pemPublicKey) {
    Objects.requireNonNull(pemPublicKey);
    this.publicKey = KeyCoercion.publicFromPem(pemPublicKey, EdECPublicKey.class);
    this.algorithm = EdDSAFamily.algorithmForCurveName(this.publicKey.getParams().getName());
  }

  public static EdDSAVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);
    try {
      return new EdDSAVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
  }

  public static EdDSAVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new EdDSAVerifier(new String(bytes));
  }

  public static EdDSAVerifier newVerifier(PublicKey publicKey) {
    return new EdDSAVerifier(publicKey);
  }

  public static EdDSAVerifier newVerifier(String pemPublicKey) {
    return new EdDSAVerifier(pemPublicKey);
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return this.algorithm == algorithm;
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    int expectedLength;
    try {
      expectedLength = EdDSAFamily.signatureLength(algorithm);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTSignatureException(e);
    }
    if (signature.length != expectedLength) {
      throw new InvalidJWTSignatureException();
    }
    if (this.algorithm != algorithm) {
      throw new InvalidJWTSignatureException();
    }

    try {
      Signature verifier = Signature.getInstance(EdDSAFamily.toJCA(algorithm));
      verifier.initVerify(publicKey);
      verifier.update(message);
      try {
        if (!verifier.verify(signature)) {
          throw new InvalidJWTSignatureException();
        }
      } catch (SignatureException e) {
        throw new InvalidJWTSignatureException(e);
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
