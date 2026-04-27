/*
 * Copyright (c) 2016-2026, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt;

import java.util.*;

/**
 * A JSON Web Algorithm (JWA) identifier as registered in the IANA "JSON Web Signature and Encryption Algorithms"
 * registry. This is the value used in the JWT header {@code "alg"} parameter.
 *
 * <p>This interface intentionally exposes only the JWA name. The mapping
 * to a JCA algorithm string (e.g., {@code "SHA256withRSA"}) is an internal concern of each
 * {@link Signer}/{@link Verifier} implementation.</p>
 *
 * <p>Standard constants (e.g., {@link #RS256}, {@link #ES256}) are interned:
 * {@code Algorithm.of("RS256") == Algorithm.RS256}. For custom algorithms, use {@link #of(String)} or implement this
 * interface directly.</p>
 *
 * @author Daniel DeGroff
 */
public interface Algorithm {
  Algorithm ES256 = new StandardAlgorithm("ES256");

  // --- Standard constants (15 total, ordered by family) ---
  Algorithm ES256K = new StandardAlgorithm("ES256K");
  Algorithm ES384 = new StandardAlgorithm("ES384");
  Algorithm ES512 = new StandardAlgorithm("ES512");
  Algorithm Ed25519 = new StandardAlgorithm("Ed25519");
  Algorithm Ed448 = new StandardAlgorithm("Ed448");
  Algorithm HS256 = new StandardAlgorithm("HS256");
  Algorithm HS384 = new StandardAlgorithm("HS384");
  Algorithm HS512 = new StandardAlgorithm("HS512");
  Algorithm PS256 = new StandardAlgorithm("PS256");
  Algorithm PS384 = new StandardAlgorithm("PS384");
  Algorithm PS512 = new StandardAlgorithm("PS512");
  Algorithm RS256 = new StandardAlgorithm("RS256");
  Algorithm RS384 = new StandardAlgorithm("RS384");
  Algorithm RS512 = new StandardAlgorithm("RS512");

  /**
   * Look up a standard {@link Algorithm} by either its JWA name ({@code "RS256"}, {@code "Ed25519"}, …) or one of the
   * JCA signature / curve name forms produced by the JDK — notably
   * {@link java.security.cert.X509Certificate#getSigAlgName()} returns values like {@code "SHA256withRSA"} and
   * {@code "SHA256withRSAandMGF1"}. Returns {@code null} for unrecognized input and silently accepts {@code null}.
   *
   * <p>This method exists specifically to bridge the JCA-shaped strings the JDK
   * emits into the JWA-shaped {@code Algorithm} constants this library uses. Application code should prefer
   * {@link #of(String)} when the input is a JWA name coming from a {@code "alg"} header.</p>
   *
   * <p>JWA names match exactly (per RFC 7515 §4.1.1); JCA names match
   * case-insensitively because the JDK uses mixed case in its sig-alg strings.</p>
   *
   * @param name the JWA name or JCA signature/curve name; {@code null} is tolerated
   * @return the standard constant or {@code null} if the name is not recognized
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
    // JCA signature/curve strings (case-insensitive) → standard JWA constant.
    // The JWK converter passes X509Certificate#getSigAlgName() through here.
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

  /**
   * Look up an Algorithm by JWA name. Returns the pre-built standard constant if the name matches one of the 15
   * standard algorithms (enabling reference equality via {@code ==}). Returns a new {@link StandardAlgorithm} instance
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
   * Returns an array of all 15 standard {@code Algorithm} constants in the order: HMAC family, RSA-PKCS1 family,
   * RSASSA-PSS family, ECDSA family, Edwards-curve family, ES256K.
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

  /**
   * The JWA algorithm name, e.g. {@code "RS256"}, {@code "ES384"}, {@code "Ed25519"}. This is the value placed in the
   * JWT header {@code "alg"} parameter.
   *
   * @return the JWA algorithm name (never null for any built-in instance)
   */
  String name();
}
