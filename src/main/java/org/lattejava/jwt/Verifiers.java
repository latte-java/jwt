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

import java.security.*;
import java.util.*;

import org.lattejava.jwt.algorithm.ec.*;
import org.lattejava.jwt.algorithm.ed.*;
import org.lattejava.jwt.algorithm.hmac.*;
import org.lattejava.jwt.algorithm.rsa.*;
import org.lattejava.jwt.jwks.*;

/**
 * Static factories for {@link Verifier} instances. The split between {@link #forHMAC(Algorithm, byte[])} and
 * {@link #forAsymmetric(Algorithm, PublicKey)} is deliberate: passing a public key to {@code forHMAC} (or a shared
 * secret to {@code forAsymmetric}) is rejected with {@link IllegalArgumentException} so a misplaced key cannot be
 * silently coerced into the wrong algorithm family.
 *
 * <p>Multi-verifier dispatch is not provided here. Callers that need to pick a
 * {@link Verifier} per token should use {@link VerifierResolver#byKid} (kid-keyed map) or {@link VerifierResolver#from}
 * (arbitrary function over the header), which make the resolution strategy explicit at the resolver layer.</p>
 *
 * @author Daniel DeGroff
 */
public final class Verifiers {
  private Verifiers() {
  }

  // ---------------------------------------------------------------------
  // forHMAC -- shared-secret algorithms only
  // ---------------------------------------------------------------------

  /**
   * Build an asymmetric {@link Verifier} from a PEM-encoded public key.
   *
   * @param algorithm    any RS*, PS*, ES*, Ed*, or ES256K algorithm
   * @param pemPublicKey the PEM-encoded public key
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is an HMAC algorithm
   */
  public static Verifier forAsymmetric(Algorithm algorithm, String pemPublicKey) {
    Objects.requireNonNull(algorithm, "algorithm");
    return switch (algorithm.name()) {
      case "RS256", "RS384", "RS512" -> RSAVerifier.newVerifier(algorithm, pemPublicKey);
      case "PS256", "PS384", "PS512" -> RSAPSSVerifier.newVerifier(algorithm, pemPublicKey);
      case "ES256", "ES256K", "ES384", "ES512" -> ECVerifier.newVerifier(pemPublicKey);
      case "Ed25519", "Ed448" -> EdDSAVerifier.newVerifier(pemPublicKey);
      default -> throw new IllegalArgumentException(
          "Expected asymmetric algorithm but found [" + algorithm.name() + "]");
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
      case "RS256", "RS384", "RS512" -> RSAVerifier.newVerifier(algorithm, publicKey);
      case "PS256", "PS384", "PS512" -> RSAPSSVerifier.newVerifier(algorithm, publicKey);
      case "ES256", "ES256K", "ES384", "ES512" -> ECVerifier.newVerifier(publicKey);
      case "Ed25519", "Ed448" -> EdDSAVerifier.newVerifier(publicKey);
      default -> throw new IllegalArgumentException(
          "Expected asymmetric algorithm but found [" + algorithm.name() + "]");
    };
  }

  // ---------------------------------------------------------------------
  // forAsymmetric -- RSA, RSA-PSS, ECDSA, EdDSA
  // ---------------------------------------------------------------------

  /**
   * Build an HMAC {@link Verifier} for the given algorithm using the supplied shared secret bytes.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret    the shared secret bytes
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Verifier forHMAC(Algorithm algorithm, byte[] secret) {
    requireHMAC(algorithm);
    return HMACVerifier.newVerifier(algorithm, secret);
  }

  /**
   * Build an HMAC {@link Verifier} from a UTF-8 secret string.
   *
   * @param algorithm one of {@code HS256}, {@code HS384}, {@code HS512}
   * @param secret    the shared secret as a UTF-8 string
   * @return a fresh {@code Verifier}
   * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm
   */
  public static Verifier forHMAC(Algorithm algorithm, String secret) {
    requireHMAC(algorithm);
    return HMACVerifier.newVerifier(algorithm, secret);
  }

  // ---------------------------------------------------------------------
  // fromJWK -- JWKS-driven
  // ---------------------------------------------------------------------

  /**
   * Build a {@link Verifier} from a JSON Web Key. Throws {@link InvalidJWKException} if the JWK is not usable for
   * signature verification; the exception's {@link InvalidJWKException#reason()} carries the categorical reason so
   * callers can route to log levels or skip lists.
   *
   * <p>Rejected when: {@code kid} is missing; {@code alg} is missing or HMAC;
   * {@code kty} is missing or {@code oct}; {@code use} is present and not {@code sig};
   * {@code alg}/{@code kty}/{@code crv} are mutually inconsistent; key material fails to parse; or verifier
   * construction would fail.</p>
   *
   * @param jwk the JSON Web Key; must be non-null
   * @return a fresh verifier bound to {@code jwk.alg()}
   * @throws InvalidJWKException if the JWK is not usable for signature verification
   */
  public static Verifier fromJWK(JSONWebKey jwk) {
    Objects.requireNonNull(jwk, "jwk");

    if (jwk.kid() == null) {
      throw new InvalidJWKException(InvalidJWKException.Reason.MISSING_KID, "JWK is missing required member [kid]");
    }

    Algorithm alg = jwk.alg();
    if (alg == null) {
      throw new InvalidJWKException(InvalidJWKException.Reason.MISSING_ALG,
          "JWK [" + jwk.kid() + "] is missing required member [alg]");
    }

    String algName = alg.name();
    if (algName.equals("HS256") || algName.equals("HS384") || algName.equals("HS512")) {
      throw new InvalidJWKException(InvalidJWKException.Reason.HMAC_ALG,
          "JWK [" + jwk.kid() + "] uses HMAC alg [" + algName + "]; not usable for signature verification on a public JWKS");
    }

    KeyType kty = jwk.kty();
    if (kty == null) {
      throw new InvalidJWKException(InvalidJWKException.Reason.PARSE_FAILURE,
          "JWK [" + jwk.kid() + "] is missing required member [kty]");
    }
    if (kty == KeyType.OCT) {
      throw new InvalidJWKException(InvalidJWKException.Reason.KTY_OCT,
          "JWK [" + jwk.kid() + "] has [kty=oct]; symmetric secrets do not belong on a public JWKS");
    }

    String use = jwk.use();
    if (use != null && !"sig".equals(use)) {
      throw new InvalidJWKException(InvalidJWKException.Reason.USE_ENC,
          "JWK [" + jwk.kid() + "] has [use=" + use + "]; only [sig] is usable for signature verification");
    }

    if (!algKtyCrvConsistent(algName, kty, jwk.crv())) {
      throw new InvalidJWKException(InvalidJWKException.Reason.ALG_CRV_MISMATCH,
          "JWK [" + jwk.kid() + "] has inconsistent [alg=" + algName + "], [kty=" + kty + "], [crv=" + jwk.crv() + "]");
    }

    PublicKey publicKey;
    try {
      publicKey = jwk.toPublicKey();
    } catch (RuntimeException e) {
      throw new InvalidJWKException(InvalidJWKException.Reason.PARSE_FAILURE,
          "JWK [" + jwk.kid() + "] key material failed to parse", e);
    }

    try {
      return forAsymmetric(alg, publicKey);
    } catch (RuntimeException e) {
      throw new InvalidJWKException(InvalidJWKException.Reason.PARSE_FAILURE,
          "JWK [" + jwk.kid() + "] verifier construction failed", e);
    }
  }

  // ---------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------

  private static boolean algKtyCrvConsistent(String algName, KeyType kty, String crv) {
    if (kty == KeyType.EC) {
      String expected = switch (algName) {
        case "ES256" -> "P-256";
        case "ES384" -> "P-384";
        case "ES512" -> "P-521";
        case "ES256K" -> "secp256k1";
        default -> null;
      };
      return expected != null && expected.equals(crv);
    }
    if (kty == KeyType.OKP) {
      if (!"Ed25519".equals(crv) && !"Ed448".equals(crv)) return false;
      return algName.equals(crv);
    }
    if (kty == KeyType.RSA) {
      return switch (algName) {
        case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> true;
        default -> false;
      };
    }
    return false;
  }

  private static void requireHMAC(Algorithm algorithm) {
    Objects.requireNonNull(algorithm, "algorithm");
    switch (algorithm.name()) {
      case "HS256", "HS384", "HS512" -> {
      }
      default -> throw new IllegalArgumentException(
          "Expected HMAC algorithm but found [" + algorithm.name() + "]");
    }
  }
}
