/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.lattejava.jwt.algorithm.rsa;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.MissingPublicKeyException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.pem.PEM;

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
 * fresh {@link Signature} instance per the spec §6 thread-safety contract.</p>
 *
 * @author The Latte Project
 */
public class RSAVerifier implements Verifier {
  private final RSAPublicKey publicKey;

  private RSAVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    if (!(publicKey instanceof RSAPublicKey rsa)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = rsa;
    RSAFamily.assertMinimumModulus(this.publicKey.getModulus().bitLength());
  }

  private RSAVerifier(String pemPublicKey) {
    Objects.requireNonNull(pemPublicKey);
    PEM pem = PEM.decode(pemPublicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }
    if (!(pem.publicKey instanceof RSAPublicKey rsa)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + pem.publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = rsa;
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
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
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
