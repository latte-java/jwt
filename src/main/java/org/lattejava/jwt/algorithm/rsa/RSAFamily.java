/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.algorithm.rsa;

import java.math.*;
import java.security.spec.*;

import org.lattejava.jwt.*;

/**
 * Package-private helpers shared by {@link RSASigner}, {@link RSAVerifier}, {@link RSAPSSSigner},
 * {@link RSAPSSVerifier}: JWA-to-JCA signature algorithm names, the RFC 8725 §3.5 minimum-modulus check, and the RFC
 * 7518 §3.5 PSSParameterSpec construction.
 */
final class RSAFamily {
  private RSAFamily() {
  }

  /**
   * RFC 8017 §3: the RSA public exponent {@code e} must satisfy {@code 2 < e < n} and, per PKCS#1 practice, be odd.
   * The upper bound is the FIPS 186-5 §A.1.1 ceiling of {@code 2^256}, since an oversized {@code e} makes each
   * verification a proportionally expensive modular exponentiation.
   */
  static void assertAcceptablePublicExponent(BigInteger e) {
    if (e == null) {
      throw new InvalidKeyTypeException("RSA public exponent is null");
    }
    if (e.compareTo(BigInteger.valueOf(3)) < 0) {
      throw new InvalidKeyTypeException("RSA public exponent [" + e + "] is less than the minimum acceptable value [3]");
    }
    if (!e.testBit(0)) {
      throw new InvalidKeyTypeException("RSA public exponent [" + e + "] is even; must be odd per PKCS#1");
    }
    if (e.bitLength() > 256) {
      throw new InvalidKeyTypeException("RSA public exponent bit length [" + e.bitLength()
          + "] exceeds the maximum of [256] bits");
    }
  }

  /**
   * RFC 8725 §3.5: RSA modulus must be at least 2048 bits. We accept 2047 because real-world generators occasionally
   * emit a key one bit shy.
   */
  static void assertMinimumModulus(int bitLength) {
    if (bitLength < 2047) {
      throw new InvalidKeyLengthException("Key length [" + bitLength
          + "] bits is less than required 2048 bits");
    }
  }

  /**
   * Build the explicit {@link PSSParameterSpec} required for the given JWA RSASSA-PSS algorithm per RFC 7518 §3.5:
   * hash, MGF1 over the matching hash, salt length equal to the hash length, trailer 1.
   */
  static PSSParameterSpec pssParameterSpec(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "PS256" -> new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
      case "PS384" -> new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
      case "PS512" -> new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
      default -> throw new IllegalArgumentException("Not an RSASSA-PSS algorithm [" + algorithm.name() + "]");
    };
  }

  /**
   * Map a JWA RSASSA-PKCS1 algorithm to the JCA signature algorithm string. Only RS256 / RS384 / RS512 are accepted.
   */
  static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "RS256" -> "SHA256withRSA";
      case "RS384" -> "SHA384withRSA";
      case "RS512" -> "SHA512withRSA";
      default -> throw new IllegalArgumentException("Not an RSA-PKCS1 algorithm [" + algorithm.name() + "]");
    };
  }
}
