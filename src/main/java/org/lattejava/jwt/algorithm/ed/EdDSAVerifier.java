/*
 * Copyright (c) 2025, FusionAuth, All Rights Reserved
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

import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.MissingPublicKeyException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.pem.PEM;

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
 * @author Daniel DeGroff
 */
public class EdDSAVerifier implements Verifier {
  private final Algorithm algorithm;

  private final EdECPublicKey publicKey;

  private EdDSAVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);

    if (!(publicKey instanceof EdECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [EdECPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = (EdECPublicKey) publicKey;
    this.algorithm = Algorithm.fromName(this.publicKey.getParams().getName());
    if (this.algorithm == null) {
      throw new InvalidKeyTypeException("Unsupported algorithm reported by the public key. [" + this.publicKey.getParams().getName() + "].");
    }
  }

  private EdDSAVerifier(String publicKey) {
    Objects.requireNonNull(publicKey);

    PEM pem = PEM.decode(publicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }

    if (!(pem.publicKey instanceof EdECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [EdECPublicKey], but found [" + pem.publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = pem.getPublicKey();
    this.algorithm = Algorithm.fromName(this.publicKey.getParams().getName());
    if (this.algorithm == null) {
      throw new InvalidKeyTypeException("Unsupported algorithm reported by the public key. [" + this.publicKey.getParams().getName() + "].");
    }
  }

  /**
   * Return a new instance of the EdDSA Verifier with the provided public key.
   *
   * @param path The path to the public key PEM.
   * @return a new instance of the EdDSA verifier.
   */
  public static EdDSAVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new EdDSAVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * Return a new instance of the EdDSA Verifier with the provided public key.
   *
   * @param bytes The bytes of the public key in PEM format.
   * @return a new instance of the EdDSA verifier.
   */
  public static EdDSAVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new EdDSAVerifier(new String(bytes));
  }

  /**
   * Return a new instance of the EdDSA Verifier with the provided public key.
   *
   * @param publicKey The public key object.
   * @return a new instance of the EdDSA verifier.
   */
  public static EdDSAVerifier newVerifier(PublicKey publicKey) {
    return new EdDSAVerifier(publicKey);
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

    int expectedLength = switch (algorithm) {
      case Ed25519 -> 64;
      case Ed448 -> 114;
      default -> throw new InvalidJWTSignatureException();
    };
    if (signature.length != expectedLength) {
      throw new InvalidJWTSignatureException();
    }

    try {
      Signature verifier = Signature.getInstance(algorithm.getName());
      verifier.initVerify(publicKey);
      verifier.update(message);

      // Depending upon the JCE provider, an invalid signature may cause verify() to return false
      // or throw a SignatureException. For example, the signature length may not match the key size.
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
