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

package org.lattejava.jwt.algorithm.ed;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.algorithm.KeyCoercion;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.util.Objects;

/**
 * EdDSA {@link Signer} for the {@code Ed25519} / {@code Ed448} JWA
 * algorithms (RFC 8037 §3.1, JOSE registry).
 *
 * <p>The JWA algorithm is derived from the key's curve at construction.
 * Each call to {@link #sign(byte[])} obtains a fresh {@link Signature}
 * instance ({@link Signature} is not thread-safe).</p>
 *
 * @author The Latte Project
 */
public class EdDSASigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final EdECPrivateKey privateKey;

  private EdDSASigner(PrivateKey privateKey, String kid) {
    Objects.requireNonNull(privateKey);
    this.privateKey = KeyCoercion.asPrivate(privateKey, EdECPrivateKey.class);
    this.kid = kid;
    this.algorithm = EdDSAFamily.algorithmForCurveName(this.privateKey.getParams().getName());
  }

  private EdDSASigner(String pemPrivateKey, String kid) {
    Objects.requireNonNull(pemPrivateKey);
    this.privateKey = KeyCoercion.privateFromPem(pemPrivateKey, EdECPrivateKey.class);
    this.kid = kid;
    this.algorithm = EdDSAFamily.algorithmForCurveName(this.privateKey.getParams().getName());
  }

  public static EdDSASigner newSigner(PrivateKey privateKey, String kid) {
    return new EdDSASigner(privateKey, kid);
  }

  public static EdDSASigner newSigner(PrivateKey privateKey) {
    return new EdDSASigner(privateKey, null);
  }

  public static EdDSASigner newSigner(String pemPrivateKey, String kid) {
    return new EdDSASigner(pemPrivateKey, kid);
  }

  public static EdDSASigner newSigner(String pemPrivateKey) {
    return new EdDSASigner(pemPrivateKey, null);
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
      Signature signature = Signature.getInstance(EdDSAFamily.toJCA(algorithm));
      signature.initSign(privateKey);
      signature.update(message);
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
