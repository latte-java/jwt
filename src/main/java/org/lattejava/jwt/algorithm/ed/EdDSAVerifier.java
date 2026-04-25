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
import java.security.interfaces.EdECPublicKey;
import java.util.Objects;

/**
 * EdDSA {@link Verifier} for the {@code Ed25519} / {@code Ed448} JWA
 * algorithms (RFC 8037 §3.1, JOSE registry).
 *
 * <p>The bound JWA algorithm is derived from the key's curve at
 * construction. {@link #canVerify(Algorithm)} returns true only for that
 * exact algorithm, so a key cannot be cross-used (Ed25519 key handed an
 * Ed448-tagged signature) once the decoder gates the verify call on
 * {@code canVerify}.</p>
 *
 * <p>Each call to {@link #verify(byte[], byte[])} obtains a fresh
 * {@link Signature} instance ({@link Signature} is not thread-safe).</p>
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
      return new EdDSAVerifier(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
  }

  public static EdDSAVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new EdDSAVerifier(new String(bytes, StandardCharsets.UTF_8));
  }

  public static EdDSAVerifier newVerifier(PublicKey publicKey) {
    return new EdDSAVerifier(publicKey);
  }

  public static EdDSAVerifier newVerifier(String pemPublicKey) {
    return new EdDSAVerifier(pemPublicKey);
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return algorithm != null && this.algorithm.name().equals(algorithm.name());
  }

  @Override
  public void verify(byte[] message, byte[] signature) {
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    int expectedLength;
    try {
      expectedLength = EdDSAFamily.signatureLength(this.algorithm);
    } catch (IllegalArgumentException e) {
      // EdDSAFamily does not recognize the bound algorithm -- an internal precondition violation.
      // This should never happen because the constructor derives the algorithm from a supported curve.
      throw new IllegalStateException("EdDSAVerifier bound to unsupported algorithm ["
          + this.algorithm.name() + "]", e);
    }
    if (signature.length != expectedLength) {
      throw new InvalidJWTSignatureException();
    }

    try {
      Signature verifier = Signature.getInstance(EdDSAFamily.toJCA(this.algorithm));
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
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
