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

/**
 * A {@code Signer} produces a signature over an ordered sequence of byte segments. Segments are treated as a single
 * contiguous stream with no separator inserted between them; callers own any framing or layout (for example, JWT
 * compact serialization's {@code header.payload} dot, which the encoder supplies as its own segment).
 *
 * <p>Implementations MUST be safe to share across threads. The strategy used to achieve that thread safety -- per-call
 * JCA primitive allocation, internal locking around a cached primitive, thread-local pooling, or any equivalent -- is
 * an implementation detail. Callers should treat each {@link Signer} as a thread-safe black box.</p>
 *
 * @author Daniel DeGroff
 */
public interface Signer {

  /**
   * Returns the JWA algorithm for this signer.
   *
   * @return the algorithm
   */
  Algorithm algorithm();

  /**
   * Returns the key ID for this signer, or {@code null} if no key ID is set. The encoder uses this to populate the
   * {@code "kid"} header parameter.
   *
   * @return the kid, or {@code null}
   */
  default String kid() {
    return null;
  }

  /**
   * Sign the provided segments as a single byte stream, in order, with no separator inserted between them. The signer
   * treats the input as the concatenation of the segments — the caller is responsible for any segment separators.
   *
   * <p>Implementations stream the segments through the underlying {@link java.security.Signature} or
   * {@link javax.crypto.Mac} via repeated {@code update(...)} calls rather than allocating an intermediate combined
   * buffer. For Ed25519 / Ed448 the JCA {@code Signature} buffers internally regardless, so the streaming approach is a
   * smaller win there than for HMAC / RSA / EC / RSA-PSS — but still a net save - one fewer allocation.
   * </p>
   *
   * <p>Callers with a single contiguous buffer can invoke this method with a single argument
   * ({@code signer.sign(message)}); Java's varargs handling wraps it as a one-element array.</p>
   *
   * @param segments the byte segments to sign, in order; must be non-null and contain non-null elements
   * @return The signature bytes
   * @throws InvalidKeyLengthException if the signer's key is too short for its algorithm
   * @throws InvalidKeyTypeException   if the signer's key is not compatible with its algorithm
   * @throws JWTSigningException       if an underlying JCE operation fails (e.g., {@code NoSuchAlgorithmException} from
   *                                   a missing JCE provider for Ed25519 / Ed448 / ES256K on an unsupported JDK)
   */
  byte[] sign(byte[]... segments);
}
