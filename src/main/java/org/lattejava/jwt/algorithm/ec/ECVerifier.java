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

package org.lattejava.jwt.algorithm.ec;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.algorithm.KeyCoercion;
import org.lattejava.jwt.internal.JOSEConverter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * ECDSA {@link Verifier} for the {@code ES256} / {@code ES384} / {@code ES512}
 * / {@code ES256K} JWA algorithms (RFC 7518 §3.4 and RFC 8812 §3.2).
 *
 * <p>When constructed with a caller-supplied {@link ECPublicKey}, the key
 * is round-tripped through {@code KeyFactory.generatePublic(new
 * X509EncodedKeySpec(key.getEncoded()))} so the JCE provider rejects
 * off-curve points before verification (CVE-2022-21449 defense). PEM-loaded
 * keys are already produced by the PEM decoder via the same provider path,
 * so they are accepted as-is.</p>
 *
 * <p>Each call to {@link #verify(Algorithm, byte[], byte[])} obtains a
 * fresh {@link Signature} instance ({@link Signature} is not thread-safe),
 * validates that the JOSE signature length matches the curve, converts
 * JOSE {@code R || S} to DER via {@link JOSEConverter#joseToDer(byte[], int)},
 * and verifies.</p>
 *
 * @author The Latte Project
 */
public class ECVerifier implements Verifier {
  private final Algorithm algorithm;

  private final ECPublicKey publicKey;

  private ECVerifier(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    this.publicKey = revalidate(KeyCoercion.asPublic(publicKey, ECPublicKey.class));
    this.algorithm = ECFamily.algorithmForCurve(this.publicKey.getParams());
  }

  private ECVerifier(String pemPublicKey) {
    Objects.requireNonNull(pemPublicKey);
    this.publicKey = KeyCoercion.publicFromPem(pemPublicKey, ECPublicKey.class);
    this.algorithm = ECFamily.algorithmForCurve(this.publicKey.getParams());
  }

  /**
   * Re-derive the EC public key via {@code KeyFactory.generatePublic} so
   * the JCE provider runs its on-curve / point-validation checks. Defends
   * against caller-supplied {@code ECPublicKey} instances that bypass the
   * provider's validation (the CVE-2022-21449 surface).
   */
  private static ECPublicKey revalidate(ECPublicKey key) {
    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyTypeException("EC public key did not provide an X.509 encoding for revalidation.");
    }
    try {
      PublicKey derived = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
      if (!(derived instanceof ECPublicKey ec)) {
        throw new InvalidKeyTypeException("Re-derived key is not an ECPublicKey [" + derived.getClass().getSimpleName() + "].");
      }
      return ec;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new InvalidKeyTypeException("Provided EC public key failed re-validation: " + e.getMessage());
    }
  }

  public static ECVerifier newVerifier(String pemPublicKey) {
    return new ECVerifier(pemPublicKey);
  }

  public static ECVerifier newVerifier(PublicKey publicKey) {
    return new ECVerifier(publicKey);
  }

  public static ECVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new ECVerifier(new String(bytes));
  }

  public static ECVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);
    try {
      return new ECVerifier(new String(Files.readAllBytes(path)));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read file from path [" + path + "]", e);
    }
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
    int curveIntLength;
    try {
      expectedLength = ECFamily.joseSignatureLength(algorithm);
      curveIntLength = ECFamily.curveIntLength(algorithm);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTSignatureException();
    }
    if (signature.length != expectedLength) {
      throw new InvalidJWTSignatureException();
    }

    byte[] der = JOSEConverter.joseToDer(signature, curveIntLength);
    try {
      Signature verifier = Signature.getInstance(ECFamily.toJCA(algorithm));
      verifier.initVerify(publicKey);
      verifier.update(message);
      try {
        if (!verifier.verify(der)) {
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
