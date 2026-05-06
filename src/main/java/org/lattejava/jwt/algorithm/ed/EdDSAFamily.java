/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.algorithm.ed;

import org.lattejava.jwt.*;

/**
 * Package-private helpers shared by {@link EdDSASigner} and {@link EdDSAVerifier}: curve-name-to-JWA mapping, expected
 * signature length, and curve / algorithm compatibility checks.
 */
final class EdDSAFamily {
  private EdDSAFamily() {
  }

  /**
   * Map a curve name as reported by {@code NamedParameterSpec.getName()} (i.e. {@code "Ed25519"} / {@code "Ed448"}) to
   * the matching JWA {@link Algorithm}.
   */
  static Algorithm algorithmForCurveName(String curveName) {
    if (curveName == null) {
      throw new InvalidKeyTypeException("EdDSA key did not report a curve name");
    }
    return switch (curveName) {
      case "Ed25519" -> Algorithm.Ed25519;
      case "Ed448" -> Algorithm.Ed448;
      default ->
          throw new InvalidKeyTypeException("Unsupported EdDSA curve [" + curveName + "], expected Ed25519 or Ed448");
    };
  }

  /**
   * Validate that a key's curve name matches the requested JWA algorithm. Used by the verifier when a caller supplies
   * an explicit algorithm (the signer derives its algorithm from the key, so this is mainly a safety check on the
   * verify path).
   */
  static void assertCurveMatchesAlgorithm(String curveName, Algorithm algorithm) {
    Algorithm actual = algorithmForCurveName(curveName);
    if (actual != algorithm) {
      throw new InvalidKeyTypeException("EdDSA key uses curve [" + curveName
          + "] but requested algorithm [" + algorithm.name() + "]");
    }
  }

  /**
   * Expected signature length per RFC 8037 for the given EdDSA algorithm (Ed25519 = 64 bytes, Ed448 = 114 bytes).
   */
  static int signatureLength(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "Ed25519" -> 64;
      case "Ed448" -> 114;
      default -> throw new IllegalArgumentException("Not an EdDSA algorithm [" + algorithm.name() + "]");
    };
  }

  /**
   * The JCA signature-algorithm string for the given EdDSA algorithm. The string equals the curve name on JDK 17+
   * ({@code "Ed25519"} / {@code "Ed448"}).
   */
  static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "Ed25519" -> "Ed25519";
      case "Ed448" -> "Ed448";
      default -> throw new IllegalArgumentException("Not an EdDSA algorithm [" + algorithm.name() + "]");
    };
  }
}
