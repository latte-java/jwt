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

import java.util.Objects;

/**
 * A JSON Web Algorithm (JWA) identifier as registered in the IANA
 * "JSON Web Signature and Encryption Algorithms" registry. This is the
 * value used in the JWT header {@code "alg"} parameter.
 *
 * <p>This interface intentionally exposes only the JWA name. The mapping
 * to a JCA algorithm string (e.g., {@code "SHA256withRSA"}) is an internal
 * concern of each {@link Signer}/{@link Verifier} implementation.</p>
 *
 * <p>Standard constants (e.g., {@link #RS256}, {@link #ES256}) are interned:
 * {@code Algorithm.of("RS256") == Algorithm.RS256}. For custom algorithms,
 * use {@link #of(String)} or implement this interface directly.</p>
 *
 * @author The Latte Project
 */
public interface Algorithm {
  /**
   * The JWA algorithm name, e.g. {@code "RS256"}, {@code "ES384"}, {@code "Ed25519"}.
   * This is the value placed in the JWT header {@code "alg"} parameter.
   *
   * @return the JWA algorithm name (never null for any built-in instance)
   */
  String name();

  // --- Standard constants (15 total, ordered by family) ---

  Algorithm HS256 = new StandardAlgorithm("HS256");

  Algorithm HS384 = new StandardAlgorithm("HS384");

  Algorithm HS512 = new StandardAlgorithm("HS512");

  Algorithm RS256 = new StandardAlgorithm("RS256");

  Algorithm RS384 = new StandardAlgorithm("RS384");

  Algorithm RS512 = new StandardAlgorithm("RS512");

  Algorithm PS256 = new StandardAlgorithm("PS256");

  Algorithm PS384 = new StandardAlgorithm("PS384");

  Algorithm PS512 = new StandardAlgorithm("PS512");

  Algorithm ES256 = new StandardAlgorithm("ES256");

  Algorithm ES384 = new StandardAlgorithm("ES384");

  Algorithm ES512 = new StandardAlgorithm("ES512");

  Algorithm Ed25519 = new StandardAlgorithm("Ed25519");

  Algorithm Ed448 = new StandardAlgorithm("Ed448");

  Algorithm ES256K = new StandardAlgorithm("ES256K");

  /**
   * Look up an Algorithm by JWA name. Returns the pre-built standard constant
   * if the name matches one of the 15 standard algorithms (enabling reference
   * equality via {@code ==}). Returns a new {@link StandardAlgorithm} instance
   * for unrecognized names.
   *
   * <p>Lookup is exact-case per RFC 7515 §4.1.1. {@code Algorithm.of("rs256")}
   * is <em>not</em> the same as {@code Algorithm.RS256}.</p>
   *
   * @param name the JWA name; must not be null
   * @return the interned constant or a new instance
   * @throws NullPointerException if {@code name} is null
   */
  static Algorithm of(String name) {
    Objects.requireNonNull(name, "name");
    return switch (name) {
      case "HS256" -> HS256;
      case "HS384" -> HS384;
      case "HS512" -> HS512;
      case "RS256" -> RS256;
      case "RS384" -> RS384;
      case "RS512" -> RS512;
      case "PS256" -> PS256;
      case "PS384" -> PS384;
      case "PS512" -> PS512;
      case "ES256" -> ES256;
      case "ES384" -> ES384;
      case "ES512" -> ES512;
      case "Ed25519" -> Ed25519;
      case "Ed448" -> Ed448;
      case "ES256K" -> ES256K;
      default -> new StandardAlgorithm(name);
    };
  }

  /**
   * Returns an array of all 15 standard {@code Algorithm} constants in the
   * order: HMAC family, RSA-PKCS1 family, RSASSA-PSS family, ECDSA family,
   * Edwards-curve family, ES256K.
   *
   * @return a fresh array of standard algorithm constants
   */
  static Algorithm[] standardValues() {
    return new Algorithm[]{
        HS256, HS384, HS512,
        RS256, RS384, RS512,
        PS256, PS384, PS512,
        ES256, ES384, ES512,
        Ed25519, Ed448, ES256K
    };
  }

  // --- Legacy 6.x compatibility shims (temporary; removed in later checkpoints) ---

  /**
   * Look up by name returning {@code null} for unrecognized names. Provided as
   * a temporary back-compat shim for 6.x callers (notably
   * {@code JSONWebKey.from(...)} and the EdDSA signer/verifier constructors).
   * Accepts both JWA names ({@code "RS256"}) and the JCA signature/curve names
   * ({@code "SHA256withRSA"}, {@code "Ed25519"}) the legacy enum recognised.
   * New code should use {@link #of(String)} or compare {@link #name()} directly.
   *
   * @param name the JWA name or legacy JCA signature/curve name
   * @return the standard constant or {@code null} if not a standard algorithm
   */
  static Algorithm fromName(String name) {
    if (name == null) {
      return null;
    }
    // Match JWA names exactly first.
    Algorithm direct = switch (name) {
      case "HS256" -> HS256;
      case "HS384" -> HS384;
      case "HS512" -> HS512;
      case "RS256" -> RS256;
      case "RS384" -> RS384;
      case "RS512" -> RS512;
      case "PS256" -> PS256;
      case "PS384" -> PS384;
      case "PS512" -> PS512;
      case "ES256" -> ES256;
      case "ES384" -> ES384;
      case "ES512" -> ES512;
      case "Ed25519" -> Ed25519;
      case "Ed448" -> Ed448;
      case "ES256K" -> ES256K;
      default -> null;
    };
    if (direct != null) {
      return direct;
    }
    // Legacy 6.x semantics: map JCA signature/curve strings (case-insensitive)
    // back to a standard JWA constant. Required by the JWK converter which
    // passes X509Certificate#getSigAlgName() through this method.
    return switch (name.toUpperCase(java.util.Locale.ROOT)) {
      case "HMACSHA256" -> HS256;
      case "HMACSHA384" -> HS384;
      case "HMACSHA512" -> HS512;
      case "SHA256WITHRSA" -> RS256;
      case "SHA384WITHRSA" -> RS384;
      case "SHA512WITHRSA" -> RS512;
      case "SHA256WITHRSAANDMGF1" -> PS256;
      case "SHA384WITHRSAANDMGF1" -> PS384;
      case "SHA512WITHRSAANDMGF1" -> PS512;
      case "SHA256WITHECDSA" -> ES256;
      case "SHA384WITHECDSA" -> ES384;
      case "SHA512WITHECDSA" -> ES512;
      case "SHA256WITHECDSAINP1363FORMAT" -> ES256;
      case "SHA384WITHECDSAINP1363FORMAT" -> ES384;
      case "SHA512WITHECDSAINP1363FORMAT" -> ES512;
      case "ED25519" -> Ed25519;
      case "ED448" -> Ed448;
      default -> null;
    };
  }
}
