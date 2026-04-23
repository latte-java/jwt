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
 * @author Daniel DeGroff
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
