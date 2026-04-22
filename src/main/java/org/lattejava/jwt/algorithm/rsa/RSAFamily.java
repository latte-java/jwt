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

package org.lattejava.jwt.algorithm.rsa;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidKeyLengthException;

import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Package-private helpers shared by {@link RSASigner}, {@link RSAVerifier},
 * {@link RSAPSSSigner}, {@link RSAPSSVerifier}: JWA-to-JCA signature
 * algorithm names, the RFC 8725 §3.5 minimum-modulus check, and the
 * RFC 7518 §3.5 PSSParameterSpec construction.
 */
final class RSAFamily {
  private RSAFamily() {
  }

  /**
   * Map a JWA RSASSA-PKCS1 algorithm to the JCA signature algorithm
   * string. Only RS256 / RS384 / RS512 are accepted.
   */
  static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "RS256" -> "SHA256withRSA";
      case "RS384" -> "SHA384withRSA";
      case "RS512" -> "SHA512withRSA";
      default ->
          throw new IllegalArgumentException("Not an RSA-PKCS1 algorithm: [" + algorithm.name() + "]");
    };
  }

  /**
   * Build the explicit {@link PSSParameterSpec} required for the given
   * JWA RSASSA-PSS algorithm per RFC 7518 §3.5: hash, MGF1 over the
   * matching hash, salt length equal to the hash length, trailer 1.
   */
  static PSSParameterSpec pssParameterSpec(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "PS256" -> new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
      case "PS384" -> new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
      case "PS512" -> new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
      default ->
          throw new IllegalArgumentException("Not an RSASSA-PSS algorithm: [" + algorithm.name() + "]");
    };
  }

  /**
   * RFC 8725 §3.5: RSA modulus must be at least 2048 bits. We accept
   * 2047 because real-world generators occasionally emit a key one bit
   * shy.
   */
  static void assertMinimumModulus(int bitLength) {
    if (bitLength < 2047) {
      throw new InvalidKeyLengthException("Key length of [" + bitLength
          + "] is less than the required key length of 2048 bits.");
    }
  }
}
