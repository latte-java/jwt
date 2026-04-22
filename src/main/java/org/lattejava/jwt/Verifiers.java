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

import org.lattejava.jwt.algorithm.ec.ECVerifier;
import org.lattejava.jwt.algorithm.ed.EdDSAVerifier;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAPSSVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;

/**
 * Static factories for {@link Verifier} instances. The split between
 * {@link #forHMAC(Algorithm, byte[])} and {@link #forAsymmetric(Algorithm, PublicKey)}
 * is deliberate: passing a public key to {@code forHMAC} (or a shared secret to
 * {@code forAsymmetric}) is rejected with {@link IllegalArgumentException} so a
 * misplaced key cannot be silently coerced into the wrong algorithm family.
 *
 * <p>{@link #anyOf(Verifier...)} composes multiple verifiers; the first delegate
 * whose {@link Verifier#canVerify(Algorithm)} returns true handles the verify
 * call, and any exception it throws propagates immediately (fail-fast — no
 * fall-through to subsequent verifiers).</p>
 *
 * <p>See spec §6 ("Signers / Verifiers Factories") for the full contract.</p>
 *
 * @author The Latte Project
 */
public final class Verifiers {
  private Verifiers() {
  }

  // ---------------------------------------------------------------------
  // forHMAC -- shared-secret algorithms only
  // ---------------------------------------------------------------------

  /**
   * Build an HMAC {@link Verifier} for the given algorithm using the supplied
   * shared secret bytes.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret the shared secret bytes
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Verifier forHMAC(Algorithm algorithm, byte[] secret) {
    requireHMAC(algorithm);
    return HMACVerifier.newVerifier(secret);
  }

  /**
   * Build an HMAC {@link Verifier} from a UTF-8 secret string.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret the shared secret as a UTF-8 string
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Verifier forHMAC(Algorithm algorithm, String secret) {
    requireHMAC(algorithm);
    return HMACVerifier.newVerifier(secret);
  }

  // ---------------------------------------------------------------------
  // forAsymmetric -- RSA, RSA-PSS, ECDSA, EdDSA
  // ---------------------------------------------------------------------

  /**
   * Build an asymmetric {@link Verifier} from a PEM-encoded public key.
   *
   * @param algorithm any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param pemPublicKey the PEM-encoded public key
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Verifier forAsymmetric(Algorithm algorithm, String pemPublicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "RS256", "RS384", "RS512" -> RSAVerifier.newVerifier(pemPublicKey);
      case "PS256", "PS384", "PS512" -> RSAPSSVerifier.newVerifier(pemPublicKey);
      case "ES256", "ES256K", "ES384", "ES512" -> ECVerifier.newVerifier(pemPublicKey);
      case "Ed25519", "Ed448" -> EdDSAVerifier.newVerifier(pemPublicKey);
      default -> throw new IllegalArgumentException(
          "forAsymmetric requires an asymmetric algorithm (RS*/PS*/ES*/Ed*); got " + algorithm.name());
    };
  }

  /**
   * Build an asymmetric {@link Verifier} from a pre-built {@link PublicKey}.
   *
   * @param algorithm any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param publicKey the public key
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Verifier forAsymmetric(Algorithm algorithm, PublicKey publicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "RS256", "RS384", "RS512" -> RSAVerifier.newVerifier(publicKey);
      case "PS256", "PS384", "PS512" -> RSAPSSVerifier.newVerifier(publicKey);
      case "ES256", "ES256K", "ES384", "ES512" -> ECVerifier.newVerifier(publicKey);
      case "Ed25519", "Ed448" -> EdDSAVerifier.newVerifier(publicKey);
      default -> throw new IllegalArgumentException(
          "forAsymmetric requires an asymmetric algorithm (RS*/PS*/ES*/Ed*); got " + algorithm.name());
    };
  }

  // ---------------------------------------------------------------------
  // anyOf -- composite verifier
  // ---------------------------------------------------------------------

  /**
   * Compose multiple verifiers into a single fail-fast composite. The composite's
   * {@link Verifier#canVerify(Algorithm)} returns {@code true} if any delegate
   * accepts the algorithm. The composite's {@link Verifier#verify(Algorithm, byte[], byte[])}
   * invokes the FIRST matching delegate; any exception that delegate throws
   * propagates immediately.
   *
   * <p>If no delegate matches, {@link Verifier#verify(Algorithm, byte[], byte[])}
   * throws {@link MissingVerifierException}.</p>
   *
   * @param verifiers one or more delegates (must be non-null and non-empty)
   * @return a composite {@code Verifier}
   * @throws NullPointerException if {@code verifiers} or any element is null
   * @throws IllegalArgumentException if {@code verifiers} is empty
   */
  public static Verifier anyOf(Verifier... verifiers) {
    Objects.requireNonNull(verifiers, "verifiers");
    if (verifiers.length == 0) {
      throw new IllegalArgumentException("anyOf requires at least one Verifier");
    }
    Verifier[] copy = verifiers.clone();
    for (int i = 0; i < copy.length; i++) {
      Objects.requireNonNull(copy[i], "verifiers[" + i + "]");
    }
    List<Verifier> delegates = List.of(copy);
    return new Verifier() {
      @Override
      public boolean canVerify(Algorithm algorithm) {
        for (Verifier v : delegates) {
          if (v.canVerify(algorithm)) {
            return true;
          }
        }
        return false;
      }

      @Override
      public void verify(Algorithm algorithm, byte[] signingInput, byte[] signature) {
        for (Verifier v : delegates) {
          if (v.canVerify(algorithm)) {
            v.verify(algorithm, signingInput, signature);
            return;
          }
        }
        throw new MissingVerifierException(
            "No Verifier in this anyOf composite accepts algorithm " + algorithm.name());
      }
    };
  }

  // ---------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------

  private static void requireHMAC(Algorithm algorithm) {
    Objects.requireNonNull(algorithm, "algorithm");
    switch (algorithm.name()) {
      case "HS256", "HS384", "HS512" -> {
      }
      default -> throw new IllegalArgumentException(
          "forHMAC requires an HMAC algorithm (HS256/HS384/HS512); got " + algorithm.name());
    }
  }
}
