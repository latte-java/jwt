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
 * A {@code Signer} produces a signature for the JWT signing-input bytes
 * (header.payload encoded as UTF-8).
 *
 * <p>Implementations MUST be safe to share across threads. Each call to
 * {@link #sign(byte[])} MUST obtain a fresh JCA primitive
 * ({@code Mac}/{@code Signature}) and MUST NOT cache and reuse it across
 * threads -- the JDK explicitly documents these as not thread-safe.</p>
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
