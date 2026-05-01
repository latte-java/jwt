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

import java.security.*;
import java.security.interfaces.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.internal.*;

/**
 * RSASSA-PSS {@link Signer} for the {@code PS256} / {@code PS384} / {@code PS512} JWA algorithms (RFC 7518 §3.5).
 *
 * <p>Each call to {@link #sign(byte[]...)} obtains a fresh
 * {@link Signature} instance and configures it with an explicit {@code PSSParameterSpec} so the parameters are not
 * inherited from the JCA provider's defaults.</p>
 *
 * @author Daniel DeGroff
 */
public class RSAPSSSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final RSAPrivateKey privateKey;

  private RSAPSSSigner(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(privateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.asPrivate(privateKey, RSAPrivateKey.class);
    RSAFamily.assertMinimumModulus(this.privateKey.getModulus().bitLength());
  }

  private RSAPSSSigner(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(pemPrivateKey);
    this.algorithm = algorithm;
    this.kid = kid;
    this.privateKey = KeyCoercion.privateFromPem(pemPrivateKey, RSAPrivateKey.class);
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
  public byte[] sign(byte[]... segments) {
    Objects.requireNonNull(segments);
    try {
      Signature signature = Signature.getInstance("RSASSA-PSS");
      signature.setParameter(RSAFamily.pssParameterSpec(algorithm));
      signature.initSign(privateKey);
      for (byte[] segment : segments) {
        Objects.requireNonNull(segment, "segment");
        signature.update(segment);
      }
      return signature.sign();
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException
             | InvalidAlgorithmParameterException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
