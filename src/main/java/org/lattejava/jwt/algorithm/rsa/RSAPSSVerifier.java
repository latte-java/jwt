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
 * <p>Each call to {@link #verify(Algorithm, byte[], byte[])} obtains a
 * fresh {@link Signature} instance and configures it with an explicit
 * {@code PSSParameterSpec} so the parameters are not inherited from the
 * JCA provider's defaults.</p>
 *
 * @author Daniel DeGroff
 */
public class RSAPSSVerifier implements Verifier {
  private final RSAPublicKey publicKey;

  private RSAPSSVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    this.publicKey = KeyCoercion.asPublic(publicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
  }

  private RSAPSSVerifier(String pemPublicKey) {
    Objects.requireNonNull(pemPublicKey);
    this.publicKey = KeyCoercion.publicFromPem(pemPublicKey, RSAPublicKey.class);
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
  }

  public static RSAPSSVerifier newVerifier(PublicKey publicKey) {
    return new RSAPSSVerifier(publicKey);
  }

  public static RSAPSSVerifier newVerifier(String pemPublicKey) {
    return new RSAPSSVerifier(pemPublicKey);
  }

  public static RSAPSSVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new RSAPSSVerifier(new String(bytes));
  }

  public static RSAPSSVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);
    try {
      return new RSAPSSVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "PS256", "PS384", "PS512" -> true;
      default -> false;
    };
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);
    try {
      Signature verifier = Signature.getInstance("RSASSA-PSS");
      verifier.setParameter(RSAFamily.pssParameterSpec(algorithm));
      verifier.initVerify(publicKey);
      verifier.update(message);
      try {
        if (!verifier.verify(signature)) {
          throw new InvalidJWTSignatureException();
        }
      } catch (SignatureException e) {
        throw new InvalidJWTSignatureException(e);
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException
             | InvalidAlgorithmParameterException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
