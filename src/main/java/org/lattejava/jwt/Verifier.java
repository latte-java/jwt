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

/**
 * A {@code Verifier} validates a signature against the JWT signing-input
 * bytes.
 *
 * <p>Implementations MUST be safe to share across threads. Each call to
 * {@link #verify(Algorithm, byte[], byte[])} MUST obtain a fresh JCA
 * primitive ({@code Mac}/{@code Signature}) and MUST NOT cache and reuse
 * it across threads -- the JDK explicitly documents these as not
 * thread-safe.</p>
 *
 * <p>Any {@code Verifier} performing HMAC (or any secret-dependent)
 * signature comparison MUST use a constant-time comparison
 * (e.g. {@link java.security.MessageDigest#isEqual(byte[], byte[])}).</p>
 *
 * @author The Latte Project
 */
public interface Verifier {
  /**
   * Does this verifier handle the given algorithm? Answers the algorithm
   * question only -- it does NOT validate a specific signature.
   *
   * @param algorithm the algorithm to test
   * @return true if this Verifier is able to verify a signature for the algorithm
   */
  boolean canVerify(Algorithm algorithm);

  /**
   * Verify the signature. Returns normally on success.
   *
   * <p>The {@code algorithm} argument MUST be one for which
   * {@link #canVerify(Algorithm)} returned true; callers (including
   * {@code JWTDecoder}) guarantee this.</p>
   *
   * @param algorithm the algorithm used to sign the JWT
   * @param message   the JWT signing-input bytes (header.payload encoded as UTF-8)
   * @param signature the signature bytes
   * @throws InvalidJWTSignatureException if the signature does not match the message
   * @throws InvalidKeyLengthException if the verifier's key is too short for the algorithm
   * @throws InvalidKeyTypeException if the key type is not compatible with the algorithm
   * @throws JWTVerifierException if an underlying JCE operation fails
   */
  void verify(Algorithm algorithm, byte[] message, byte[] signature);
}
