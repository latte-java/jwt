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

package org.lattejava.jwt;

import org.lattejava.jwt.algorithm.ec.ECSigner;
import org.lattejava.jwt.algorithm.ed.EdDSASigner;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.rsa.RSAPSSSigner;
import org.lattejava.jwt.algorithm.rsa.RSASigner;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * Static factories for {@link Signer} instances. The split between
 * {@link #forHMAC(Algorithm, byte[])} and {@link #forAsymmetric(Algorithm, PrivateKey)}
 * is deliberate: passing a private key to {@code forHMAC} (or a shared secret to
 * {@code forAsymmetric}) is rejected with {@link IllegalArgumentException} so a
 * misplaced key cannot be silently coerced into the wrong algorithm family.
 *
 * @author The Latte Project
 */
public final class Signers {
  private Signers() {
  }

  // ---------------------------------------------------------------------
  // forHMAC -- shared-secret algorithms only (HS256, HS384, HS512)
  // ---------------------------------------------------------------------

  /**
   * Build an HMAC {@link Signer} for the given algorithm using the supplied
   * shared secret bytes.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret the shared secret bytes (must meet the per-algorithm minimum length)
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Signer forHMAC(Algorithm algorithm, byte[] secret) {
    return forHMAC(algorithm, secret, null);
  }

  /**
   * Build an HMAC {@link Signer} from a UTF-8 secret string.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret the shared secret as a UTF-8 string
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Signer forHMAC(Algorithm algorithm, String secret) {
    return forHMAC(algorithm, secret, null);
  }

  /**
   * Build an HMAC {@link Signer} with an explicit {@code kid}.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret the shared secret bytes
   * @param kid optional Key ID to attach to produced signatures (may be null)
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Signer forHMAC(Algorithm algorithm, byte[] secret, String kid) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "HS256" -> HMACSigner.newSHA256Signer(secret, kid);
      case "HS384" -> HMACSigner.newSHA384Signer(secret, kid);
      case "HS512" -> HMACSigner.newSHA512Signer(secret, kid);
      default -> throw new IllegalArgumentException(
          "forHMAC requires an HMAC algorithm (HS256/HS384/HS512); got " + algorithm.name());
    };
  }

  /**
   * Build an HMAC {@link Signer} from a UTF-8 secret string with an explicit {@code kid}.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret the shared secret as a UTF-8 string
   * @param kid optional Key ID to attach to produced signatures (may be null)
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Signer forHMAC(Algorithm algorithm, String secret, String kid) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "HS256" -> HMACSigner.newSHA256Signer(secret, kid);
      case "HS384" -> HMACSigner.newSHA384Signer(secret, kid);
      case "HS512" -> HMACSigner.newSHA512Signer(secret, kid);
      default -> throw new IllegalArgumentException(
          "forHMAC requires an HMAC algorithm (HS256/HS384/HS512); got " + algorithm.name());
    };
  }

  // ---------------------------------------------------------------------
  // forAsymmetric -- RSA, RSA-PSS, ECDSA, EdDSA
  // ---------------------------------------------------------------------

  /**
   * Build an asymmetric {@link Signer} from a PEM-encoded private key.
   *
   * @param algorithm any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param pemPrivateKey the PEM-encoded private key
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Signer forAsymmetric(Algorithm algorithm, String pemPrivateKey) {
    return forAsymmetric(algorithm, pemPrivateKey, null);
  }

  /**
   * Build an asymmetric {@link Signer} from a PEM-encoded private key with an explicit {@code kid}.
   *
   * @param algorithm any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param pemPrivateKey the PEM-encoded private key
   * @param kid optional Key ID (may be null)
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Signer forAsymmetric(Algorithm algorithm, String pemPrivateKey, String kid) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "RS256" -> RSASigner.newSHA256Signer(pemPrivateKey, kid);
      case "RS384" -> RSASigner.newSHA384Signer(pemPrivateKey, kid);
      case "RS512" -> RSASigner.newSHA512Signer(pemPrivateKey, kid);
      case "PS256" -> RSAPSSSigner.newSHA256Signer(pemPrivateKey, kid);
      case "PS384" -> RSAPSSSigner.newSHA384Signer(pemPrivateKey, kid);
      case "PS512" -> RSAPSSSigner.newSHA512Signer(pemPrivateKey, kid);
      case "ES256" -> ECSigner.newSHA256Signer(pemPrivateKey, kid);
      case "ES384" -> ECSigner.newSHA384Signer(pemPrivateKey, kid);
      case "ES512" -> ECSigner.newSHA512Signer(pemPrivateKey, kid);
      case "ES256K" -> ECSigner.newSecp256k1Signer(pemPrivateKey, kid);
      case "Ed25519", "Ed448" -> EdDSASigner.newSigner(pemPrivateKey, kid);
      default -> throw new IllegalArgumentException(
          "forAsymmetric requires an asymmetric algorithm (RS*/PS*/ES*/Ed*); got " + algorithm.name());
    };
  }

  /**
   * Build an asymmetric {@link Signer} from a pre-built {@link PrivateKey}.
   *
   * @param algorithm any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param privateKey the private key
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Signer forAsymmetric(Algorithm algorithm, PrivateKey privateKey) {
    return forAsymmetric(algorithm, privateKey, null);
  }

  /**
   * Build an asymmetric {@link Signer} from a pre-built {@link PrivateKey} with an explicit {@code kid}.
   *
   * @param algorithm any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param privateKey the private key
   * @param kid optional Key ID (may be null)
   * @return a fresh {@code Signer}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Signer forAsymmetric(Algorithm algorithm, PrivateKey privateKey, String kid) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "RS256" -> RSASigner.newSHA256Signer(privateKey, kid);
      case "RS384" -> RSASigner.newSHA384Signer(privateKey, kid);
      case "RS512" -> RSASigner.newSHA512Signer(privateKey, kid);
      case "PS256" -> RSAPSSSigner.newSHA256Signer(privateKey, kid);
      case "PS384" -> RSAPSSSigner.newSHA384Signer(privateKey, kid);
      case "PS512" -> RSAPSSSigner.newSHA512Signer(privateKey, kid);
      case "ES256" -> ECSigner.newSHA256Signer(privateKey, kid);
      case "ES384" -> ECSigner.newSHA384Signer(privateKey, kid);
      case "ES512" -> ECSigner.newSHA512Signer(privateKey, kid);
      case "ES256K" -> ECSigner.newSecp256k1Signer(privateKey, kid);
      case "Ed25519", "Ed448" -> EdDSASigner.newSigner(privateKey, kid);
      default -> throw new IllegalArgumentException(
          "forAsymmetric requires an asymmetric algorithm (RS*/PS*/ES*/Ed*); got " + algorithm.name());
    };
  }
}
