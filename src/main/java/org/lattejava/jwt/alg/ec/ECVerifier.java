/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.alg.ec;

import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.MissingPublicKeyException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.domain.Algorithm;
import org.lattejava.jwt.pem.PEM;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class ECVerifier implements Verifier {
  private final Algorithm algorithm;

  private final ECPublicKey publicKey;

  private ECVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);

    if (!(publicKey instanceof ECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [ECPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = (ECPublicKey) publicKey;
    this.algorithm = algorithmForKey(this.publicKey);
  }

  private ECVerifier(String publicKey) {
    Objects.requireNonNull(publicKey);

    PEM pem = PEM.decode(publicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }

    if (!(pem.publicKey instanceof ECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [ECPublicKey], but found [" + pem.publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = pem.getPublicKey();
    this.algorithm = algorithmForKey(this.publicKey);
  }

  private static Algorithm algorithmForKey(ECPublicKey key) {
    int fieldSize = key.getParams().getCurve().getField().getFieldSize();
    return switch (fieldSize) {
      case 256 -> Algorithm.ES256;
      case 384 -> Algorithm.ES384;
      case 521 -> Algorithm.ES512;
      default -> throw new InvalidKeyTypeException("Unsupported EC curve with field size [" + fieldSize + "]. Expected 256, 384, or 521.");
    };
  }

  /**
   * Return a new instance of the EC Verifier with the provided public key.
   *
   * @param publicKey The EC public key PEM.
   * @return a new instance of the EC verifier.
   */
  public static ECVerifier newVerifier(String publicKey) {
    return new ECVerifier(publicKey);
  }

  /**
   * Return a new instance of the EC Verifier with the provided public key.
   *
   * @param publicKey The EC public key object.
   * @return a new instance of the EC verifier.
   */
  public static ECVerifier newVerifier(PublicKey publicKey) {
    return new ECVerifier(publicKey);
  }

  /**
   * Return a new instance of the EC Verifier with the provided public key.
   *
   * @param path The path to the EC public key PEM.
   * @return a new instance of the EC verifier.
   */
  public static ECVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new ECVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * Return a new instance of the EC Verifier with the provided public key.
   *
   * @param bytes The bytes of the EC public key PEM.
   * @return a new instance of the EC verifier.
   */
  public static ECVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new ECVerifier(new String(bytes));
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
      case ES256 -> 64;
      case ES384 -> 96;
      case ES512 -> 132;
      default -> throw new InvalidJWTSignatureException();
    };
    if (signature.length != expectedLength) {
      throw new InvalidJWTSignatureException();
    }
    try {
      Signature verifier = Signature.getInstance(algorithm.getName() + "inP1363Format");
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
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
