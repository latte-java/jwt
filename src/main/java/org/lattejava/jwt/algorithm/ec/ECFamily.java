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

package org.lattejava.jwt.algorithm.ec;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidKeyTypeException;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;

/**
 * Package-private helpers shared by {@link ECSigner} and {@link ECVerifier}:
 * JWA-to-JCA signature algorithm names, JWA-to-curve-integer-length, and
 * curve / algorithm compatibility validation.
 *
 * <p>Note: ECDSA signatures are produced by {@code java.security.Signature}
 * in DER form ({@code SEQUENCE { INTEGER r, INTEGER s }}) and must be
 * converted to/from JOSE {@code R || S} fixed-length form via
 * {@link org.lattejava.jwt.internal.JOSEConverter}. We deliberately do
 * <em>not</em> rely on JDK 17+ {@code "...inP1363Format"} algorithm names
 * because the conversion is a known CVE surface and we want one auditable
 * implementation in {@link org.lattejava.jwt.internal.JOSEConverter}.</p>
 */
final class ECFamily {
  // secp256k1 curve parameters per SEC 2 / RFC 5639. Used to detect a
  // secp256k1 (ES256K) key vs. a P-256 (ES256) key, since both have a
  // 256-bit field size but the curves are distinct.
  private static final BigInteger SECP256K1_P = new BigInteger(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

  private static final BigInteger SECP256K1_A = BigInteger.ZERO;

  private static final BigInteger SECP256K1_B = BigInteger.valueOf(7);

  private ECFamily() {
  }

  /**
   * Map a JWA ECDSA algorithm to the underlying JCA signature algorithm
   * string (DER-output form). Both {@code ES256} (P-256) and
   * {@code ES256K} (secp256k1) use {@code "SHA256withECDSA"} -- the JCA
   * provider uses the supplied key's curve to pick the correct group;
   * the JWA distinction is an algorithm-header concern only.
   */
  static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "ES256", "ES256K" -> "SHA256withECDSA";
      case "ES384" -> "SHA384withECDSA";
      case "ES512" -> "SHA512withECDSA";
      default ->
          throw new IllegalArgumentException("Not an ECDSA algorithm: [" + algorithm.name() + "]");
    };
  }

  /**
   * Curve-order length in bytes for the given JWA ECDSA algorithm.
   * Drives JOSE {@code R || S} encoding length and DER↔JOSE conversion.
   * Note P-521's order is 521 bits, which is 66 bytes (not 64).
   */
  static int curveIntLength(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "ES256", "ES256K" -> 32;
      case "ES384" -> 48;
      case "ES512" -> 66;
      default ->
          throw new IllegalArgumentException("Not an ECDSA algorithm: [" + algorithm.name() + "]");
    };
  }

  /**
   * Expected JOSE signature length (== {@code 2 * curveIntLength}).
   */
  static int joseSignatureLength(Algorithm algorithm) {
    return 2 * curveIntLength(algorithm);
  }

  /**
   * Determine which JWA algorithm an EC key's curve belongs to. Uses the
   * field size to pick the family, then disambiguates the 256-bit case
   * between P-256 (ES256) and secp256k1 (ES256K) by inspecting the
   * curve's {@code (p, a, b)} parameters.
   */
  static Algorithm algorithmForCurve(ECParameterSpec params) {
    int fieldSize = params.getCurve().getField().getFieldSize();
    return switch (fieldSize) {
      case 256 -> isSecp256k1(params) ? Algorithm.ES256K : Algorithm.ES256;
      case 384 -> Algorithm.ES384;
      case 521 -> Algorithm.ES512;
      default ->
          throw new InvalidKeyTypeException("Unsupported EC curve with field size [" + fieldSize + "]. Expected 256, 384, or 521.");
    };
  }

  /**
   * Validate that the given key's curve is the curve required by the
   * given JWA algorithm. Throws {@link InvalidKeyTypeException} for any
   * cross-curve mismatch (e.g. an ES256K key handed to an ES256 signer).
   */
  static void assertCurveMatchesAlgorithm(ECParameterSpec params, Algorithm algorithm) {
    Algorithm actual = algorithmForCurve(params);
    if (actual != algorithm) {
      throw new InvalidKeyTypeException("The provided EC key uses curve for algorithm [" + actual.name()
          + "] which is not compatible with algorithm [" + algorithm.name() + "].");
    }
  }

  private static boolean isSecp256k1(ECParameterSpec params) {
    java.security.spec.EllipticCurve curve = params.getCurve();
    java.security.spec.ECField field = curve.getField();
    if (!(field instanceof java.security.spec.ECFieldFp fp)) {
      return false;
    }
    return SECP256K1_P.equals(fp.getP())
        && SECP256K1_A.equals(curve.getA())
        && SECP256K1_B.equals(curve.getB());
  }
}
