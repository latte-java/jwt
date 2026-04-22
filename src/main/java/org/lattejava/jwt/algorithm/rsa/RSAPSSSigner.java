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
import org.lattejava.jwt.InvalidKeyTypeException;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.MissingPrivateKeyException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.pem.PEM;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

/**
 * RSASSA-PSS {@link Signer} for the {@code PS256} / {@code PS384}
 * / {@code PS512} JWA algorithms (RFC 7518 §3.5).
 *
 * <p>Each call to {@link #sign(byte[])} obtains a fresh
 * {@link Signature} instance and configures it with the explicit
 * {@code PSSParameterSpec} mandated by spec §6.</p>
 *
 * @author The Latte Project
 */
public class RSAPSSSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final RSAPrivateKey privateKey;

  private RSAPSSSigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);
    if (!(privateKey instanceof RSAPrivateKey rsa)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [RSAPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = rsa;
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  private RSAPSSSigner(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(pemPrivateKey);
    PEM pem = PEM.decode(pemPrivateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }
    if (!(pem.privateKey instanceof RSAPrivateKey rsa)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [RSAPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = rsa;
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  public static RSAPSSSigner newSHA256Signer(String pemPrivateKey) {
    return new RSAPSSSigner(Algorithm.PS256, pemPrivateKey, null);
  }

  public static RSAPSSSigner newSHA256Signer(String pemPrivateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS256, pemPrivateKey, kid);
  }

  public static RSAPSSSigner newSHA256Signer(PrivateKey privateKey) {
    return new RSAPSSSigner(Algorithm.PS256, privateKey, null);
  }

  public static RSAPSSSigner newSHA256Signer(PrivateKey privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS256, privateKey, kid);
  }

  public static RSAPSSSigner newSHA384Signer(String pemPrivateKey) {
    return new RSAPSSSigner(Algorithm.PS384, pemPrivateKey, null);
  }

  public static RSAPSSSigner newSHA384Signer(String pemPrivateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS384, pemPrivateKey, kid);
  }

  public static RSAPSSSigner newSHA384Signer(PrivateKey privateKey) {
    return new RSAPSSSigner(Algorithm.PS384, privateKey, null);
  }

  public static RSAPSSSigner newSHA384Signer(PrivateKey privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS384, privateKey, kid);
  }

  public static RSAPSSSigner newSHA512Signer(String pemPrivateKey) {
    return new RSAPSSSigner(Algorithm.PS512, pemPrivateKey, null);
  }

  public static RSAPSSSigner newSHA512Signer(String pemPrivateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS512, pemPrivateKey, kid);
  }

  public static RSAPSSSigner newSHA512Signer(PrivateKey privateKey) {
    return new RSAPSSSigner(Algorithm.PS512, privateKey, null);
  }

  public static RSAPSSSigner newSHA512Signer(PrivateKey privateKey, String kid) {
    return new RSAPSSSigner(Algorithm.PS512, privateKey, kid);
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
      Signature signature = Signature.getInstance("RSASSA-PSS");
      signature.setParameter(RSAFamily.pssParameterSpec(algorithm));
      signature.initSign(privateKey);
      signature.update(message);
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException
             | InvalidAlgorithmParameterException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
