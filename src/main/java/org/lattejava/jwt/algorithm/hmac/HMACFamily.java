/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.algorithm.hmac;

import org.lattejava.jwt.*;

/**
 * Package-private helpers shared between {@link HMACSigner} and {@link org.lattejava.jwt.algorithm.hmac.HMACVerifier}:
 * JWA-to-JCA algorithm name mapping and the RFC 7518 §3.2 minimum-secret-length check.
 */
final class HMACFamily {
  private HMACFamily() {
  }

  /**
   * RFC 7518 §3.2: "A key of the same size as the hash output or larger MUST be used with this algorithm."
   */
  static void assertMinimumSecretLength(Algorithm algorithm, byte[] secret) {
    int minimumLength = switch (algorithm.name()) {
      case "HS256" -> 32;
      case "HS384" -> 48;
      case "HS512" -> 64;
      default -> 0;
    };
    if (secret.length < minimumLength) {
      throw new InvalidKeyLengthException("Secret length [" + secret.length
          + "] bytes is less than required [" + minimumLength
          + "] bytes for algorithm [" + algorithm.name() + "]");
    }
  }

  /**
   * Map a JWA HMAC algorithm name to the corresponding JCA {@code Mac.getInstance(...)} string.
   */
  static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "HS256" -> "HmacSHA256";
      case "HS384" -> "HmacSHA384";
      case "HS512" -> "HmacSHA512";
      default -> throw new IllegalArgumentException("Not an HMAC algorithm [" + algorithm.name() + "]");
    };
  }
}
