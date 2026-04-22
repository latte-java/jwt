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

package org.lattejava.jwt.internal;

import org.lattejava.jwt.Algorithm;

/**
 * Internal helper that maps a JWA {@link Algorithm} name (e.g. {@code "RS256"})
 * to the JCA algorithm string consumed by {@code Mac.getInstance(...)},
 * {@code Signature.getInstance(...)}, {@code MessageDigest.getInstance(...)}, etc.
 *
 * <p><strong>Temporary scaffold.</strong> The 6.x {@code Algorithm} enum carried
 * the JCA string as a field; the 7.0 {@code Algorithm} interface deliberately
 * does not. Per spec §1, the JCA mapping belongs inside each Signer/Verifier
 * implementation and will be inlined there in Checkpoint 4. This class exists
 * only so the legacy crypto classes keep compiling and running between
 * Checkpoint 1 and Checkpoint 4 -- it must be deleted as part of Checkpoint 4.</p>
 *
 * @author The Latte Project
 */
public final class JCAAlgorithmMapping {
  private JCAAlgorithmMapping() {
  }

  /**
   * Map a JWA algorithm to the matching JCA algorithm string.
   *
   * @param algorithm the JWA algorithm (must not be null)
   * @return the JCA algorithm string consumed by JCE
   * @throws IllegalArgumentException if no JCA mapping is known for the JWA name
   */
  public static String toJCA(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "HS256" -> "HmacSHA256";
      case "HS384" -> "HmacSHA384";
      case "HS512" -> "HmacSHA512";
      case "RS256" -> "SHA256withRSA";
      case "RS384" -> "SHA384withRSA";
      case "RS512" -> "SHA512withRSA";
      case "PS256" -> "SHA256withRSAandMGF1";
      case "PS384" -> "SHA384withRSAandMGF1";
      case "PS512" -> "SHA512withRSAandMGF1";
      case "ES256", "ES256K" -> "SHA256withECDSA";
      case "ES384" -> "SHA384withECDSA";
      case "ES512" -> "SHA512withECDSA";
      case "Ed25519" -> "Ed25519";
      case "Ed448" -> "Ed448";
      default ->
          throw new IllegalArgumentException("No JCA mapping for JWA algorithm [" + algorithm.name() + "]");
    };
  }

  /**
   * Map a JWA RSASSA-PSS algorithm to the message-digest name used in
   * {@link java.security.spec.PSSParameterSpec} (the same name passed to
   * {@code MessageDigest.getInstance}).
   *
   * @param algorithm a PSS algorithm (PS256/PS384/PS512)
   * @return the digest name (e.g. {@code "SHA-256"})
   * @throws IllegalArgumentException if {@code algorithm} is not an RSASSA-PSS algorithm
   */
  public static String pssDigestName(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "PS256" -> "SHA-256";
      case "PS384" -> "SHA-384";
      case "PS512" -> "SHA-512";
      default ->
          throw new IllegalArgumentException("PSS digest is only defined for PS256/PS384/PS512, not [" + algorithm.name() + "]");
    };
  }

  /**
   * Map a JWA RSASSA-PSS algorithm to its salt length in bytes (per RFC 7518
   * §3.5: salt length equals hash length).
   *
   * @param algorithm a PSS algorithm (PS256/PS384/PS512)
   * @return the salt length in bytes
   * @throws IllegalArgumentException if {@code algorithm} is not an RSASSA-PSS algorithm
   */
  public static int pssSaltLength(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "PS256" -> 32;
      case "PS384" -> 48;
      case "PS512" -> 64;
      default ->
          throw new IllegalArgumentException("PSS salt length is only defined for PS256/PS384/PS512, not [" + algorithm.name() + "]");
    };
  }
}
