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
 * A {@code Signer} produces a signature for the JWT signing-input bytes
 * (header.payload encoded as UTF-8). See spec §6 for the full contract.
 *
 * <p>Implementations MUST be safe to share across threads. Each call to
 * {@link #sign(byte[])} MUST obtain a fresh JCA primitive
 * ({@code Mac}/{@code Signature}) and MUST NOT cache and reuse it across
 * threads -- the JDK explicitly documents these as not thread-safe.</p>
 *
 * @author The Latte Project
 */
public interface Signer {

  /**
   * Returns the JWA algorithm for this signer.
   *
   * @return the algorithm
   */
  Algorithm algorithm();

  /**
   * Sign the provided message and return the signature.
   *
   * @param message The message bytes to sign (header.payload encoded as UTF-8).
   * @return The signature bytes.
   * @throws InvalidKeyLengthException if the signer's key is too short for its algorithm
   * @throws InvalidKeyTypeException if the signer's key is not compatible with its algorithm
   * @throws JWTSigningException if an underlying JCE operation fails (e.g.,
   *         {@code NoSuchAlgorithmException} from a missing JCE provider for
   *         Ed25519 / Ed448 / ES256K on an unsupported JDK)
   */
  byte[] sign(byte[] message);

  /**
   * Returns the key ID for this signer, or {@code null} if no key ID is set.
   * The encoder uses this to populate the {@code "kid"} header parameter.
   *
   * @return the kid, or {@code null}
   */
  default String kid() {
    return null;
  }
}
