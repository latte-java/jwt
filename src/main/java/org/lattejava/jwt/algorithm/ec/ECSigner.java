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
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.MissingPrivateKeyException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.internal.JOSEConverter;
import org.lattejava.jwt.pem.PEM;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

/**
 * ECDSA {@link Signer} for the {@code ES256} / {@code ES384} / {@code ES512}
 * / {@code ES256K} JWA algorithms (RFC 7518 §3.4 and RFC 8812 §3.2).
 *
 * <p>Each call to {@link #sign(byte[])} obtains a fresh {@link Signature}
 * instance (spec §6 thread-safety contract), produces a DER-encoded ECDSA
 * signature, then converts it to JOSE {@code R || S} fixed-length form
 * via {@link JOSEConverter#derToJose(byte[], int)}.</p>
 *
 * @author The Latte Project
 */
public class ECSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final ECPrivateKey privateKey;

  private ECSigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);
    if (!(privateKey instanceof ECPrivateKey ec)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = ec;
    ECFamily.assertCurveMatchesAlgorithm(this.privateKey.getParams(), algorithm);
  }

  private ECSigner(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(pemPrivateKey);
    PEM pem = PEM.decode(pemPrivateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }
    if (!(pem.privateKey instanceof ECPrivateKey ec)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [ECPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = ec;
    ECFamily.assertCurveMatchesAlgorithm(this.privateKey.getParams(), algorithm);
  }

  public static ECSigner newSHA256Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES256, pemPrivateKey, null);
  }

  public static ECSigner newSHA256Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES256, pemPrivateKey, kid);
  }

  public static ECSigner newSHA256Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256, privateKey, null);
  }

  public static ECSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256, privateKey, kid);
  }

  public static ECSigner newSHA384Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES384, pemPrivateKey, null);
  }

  public static ECSigner newSHA384Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES384, pemPrivateKey, kid);
  }

  public static ECSigner newSHA384Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES384, privateKey, null);
  }

  public static ECSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES384, privateKey, kid);
  }

  public static ECSigner newSHA512Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES512, pemPrivateKey, null);
  }

  public static ECSigner newSHA512Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES512, pemPrivateKey, kid);
  }

  public static ECSigner newSHA512Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES512, privateKey, null);
  }

  public static ECSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES512, privateKey, kid);
  }

  public static ECSigner newSecp256k1Signer(String pemPrivateKey) {
    return new ECSigner(Algorithm.ES256K, pemPrivateKey, null);
  }

  public static ECSigner newSecp256k1Signer(String pemPrivateKey, String kid) {
    return new ECSigner(Algorithm.ES256K, pemPrivateKey, kid);
  }

  public static ECSigner newSecp256k1Signer(PrivateKey privateKey) {
    return new ECSigner(Algorithm.ES256K, privateKey, null);
  }

  public static ECSigner newSecp256k1Signer(PrivateKey privateKey, String kid) {
    return new ECSigner(Algorithm.ES256K, privateKey, kid);
  }

  @Override
  public Algorithm algorithm() {
    return algorithm;
  }

  @Override
  public String kid() {
    return kid;
  }

  @Override
  public byte[] sign(byte[] message) {
    Objects.requireNonNull(message);
    try {
      Signature signature = Signature.getInstance(ECFamily.toJCA(algorithm));
      signature.initSign(privateKey);
      signature.update(message);
      byte[] der = signature.sign();
      return JOSEConverter.derToJose(der, ECFamily.curveIntLength(algorithm));
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
