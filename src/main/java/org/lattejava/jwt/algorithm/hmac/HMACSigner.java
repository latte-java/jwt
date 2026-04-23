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

package org.lattejava.jwt.algorithm.hmac;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidKeyLengthException;
import org.lattejava.jwt.JWTSigningException;
import org.lattejava.jwt.Signer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * HMAC-based {@link Signer} for the {@code HS256} / {@code HS384} /
 * {@code HS512} JWA algorithms (RFC 7518 §3.2).
 *
 * <p>Each call to {@link #sign(byte[])} obtains a fresh {@link Mac}
 * instance ({@link Mac} is not thread-safe).</p>
 *
 * @author The Latte Project
 */
public class HMACSigner implements Signer {
  private final Algorithm algorithm;

  private final String kid;

  private final byte[] secret;

  private HMACSigner(Algorithm algorithm, byte[] secret, String kid) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(secret);
    HMACFamily.assertMinimumSecretLength(algorithm, secret);

    this.algorithm = algorithm;
    this.kid = kid;
    this.secret = secret;
  }

  private HMACSigner(Algorithm algorithm, String secret, String kid) {
    this(algorithm, secret == null ? null : secret.getBytes(StandardCharsets.UTF_8), kid);
  }

  public static HMACSigner newSHA256Signer(byte[] secret) {
    return new HMACSigner(Algorithm.HS256, secret, null);
  }

  public static HMACSigner newSHA256Signer(String secret) {
    return new HMACSigner(Algorithm.HS256, secret, null);
  }

  public static HMACSigner newSHA256Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  public static HMACSigner newSHA256Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS256, secret, kid);
  }

  public static HMACSigner newSHA384Signer(byte[] secret) {
    return new HMACSigner(Algorithm.HS384, secret, null);
  }

  public static HMACSigner newSHA384Signer(String secret) {
    return new HMACSigner(Algorithm.HS384, secret, null);
  }

  public static HMACSigner newSHA384Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  public static HMACSigner newSHA384Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS384, secret, kid);
  }

  public static HMACSigner newSHA512Signer(byte[] secret) {
    return new HMACSigner(Algorithm.HS512, secret, null);
  }

  public static HMACSigner newSHA512Signer(String secret) {
    return new HMACSigner(Algorithm.HS512, secret, null);
  }

  public static HMACSigner newSHA512Signer(byte[] secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
  }

  public static HMACSigner newSHA512Signer(String secret, String kid) {
    return new HMACSigner(Algorithm.HS512, secret, kid);
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
    String jcaName = HMACFamily.toJCA(algorithm);
    try {
      Mac mac = Mac.getInstance(jcaName);
      mac.init(new SecretKeySpec(secret, jcaName));
      return mac.doFinal(message);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
