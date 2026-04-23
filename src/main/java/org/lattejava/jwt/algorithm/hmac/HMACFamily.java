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

/**
 * Package-private helpers shared between {@link HMACSigner} and
 * {@link org.lattejava.jwt.algorithm.hmac.HMACVerifier}: JWA-to-JCA
 * algorithm name mapping and the RFC 7518 §3.2 minimum-secret-length
 * check.
 */
final class HMACFamily {
  private HMACFamily() {
  }

  /**
   * Map a JWA HMAC algorithm name to the corresponding JCA
   * {@code Mac.getInstance(...)} string.
   */
  static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "HS256" -> "HmacSHA256";
      case "HS384" -> "HmacSHA384";
      case "HS512" -> "HmacSHA512";
      default ->
          throw new IllegalArgumentException("Not an HMAC algorithm [" + algorithm.name() + "]");
    };
  }

  /**
   * RFC 7518 §3.2: "A key of the same size as the hash output or larger
   * MUST be used with this algorithm."
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
}
