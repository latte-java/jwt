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
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.algorithm.KeyCoercion;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

/**
 * RSASSA-PKCS1-v1_5 {@link Signer} for the {@code RS256} / {@code RS384}
 * / {@code RS512} JWA algorithms (RFC 7518 §3.3).
 *
 * <p>Each call to {@link #sign(byte[])} obtains a fresh
 * {@link Signature} instance ({@link Signature} is not thread-safe).</p>
 *
 * @author The Latte Project
 */
public class RSASigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final RSAPrivateKey privateKey;

  private RSASigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.asPrivate(privateKey, RSAPrivateKey.class);
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  private RSASigner(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(pemPrivateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.privateFromPem(pemPrivateKey, RSAPrivateKey.class);
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  public static RSASigner newSHA256Signer(String pemPrivateKey) {
    return new RSASigner(Algorithm.RS256, pemPrivateKey, null);
  }

  public static RSASigner newSHA256Signer(String pemPrivateKey, String kid) {
    return new RSASigner(Algorithm.RS256, pemPrivateKey, kid);
  }

  public static RSASigner newSHA256Signer(PrivateKey privateKey) {
    return new RSASigner(Algorithm.RS256, privateKey, null);
  }

  public static RSASigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new RSASigner(Algorithm.RS256, privateKey, kid);
  }

  public static RSASigner newSHA384Signer(String pemPrivateKey) {
    return new RSASigner(Algorithm.RS384, pemPrivateKey, null);
  }

  public static RSASigner newSHA384Signer(String pemPrivateKey, String kid) {
    return new RSASigner(Algorithm.RS384, pemPrivateKey, kid);
  }

  public static RSASigner newSHA384Signer(PrivateKey privateKey) {
    return new RSASigner(Algorithm.RS384, privateKey, null);
  }

  public static RSASigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new RSASigner(Algorithm.RS384, privateKey, kid);
  }

  public static RSASigner newSHA512Signer(String pemPrivateKey) {
    return new RSASigner(Algorithm.RS512, pemPrivateKey, null);
  }

  public static RSASigner newSHA512Signer(String pemPrivateKey, String kid) {
    return new RSASigner(Algorithm.RS512, pemPrivateKey, kid);
  }

  public static RSASigner newSHA512Signer(PrivateKey privateKey) {
    return new RSASigner(Algorithm.RS512, privateKey, null);
  }

  public static RSASigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new RSASigner(Algorithm.RS512, privateKey, kid);
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
      Signature signature = Signature.getInstance(RSAFamily.toJCA(algorithm));
      signature.initSign(privateKey);
      signature.update(message);
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
