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
 * @author Daniel DeGroff
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
