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
 * A {@code Verifier} validates a signature against the JWT signing-input bytes. Each instance is bound 1:1 to a single
 * JWA algorithm at construction time; {@link #canVerify(Algorithm)} returns true only for that exact algorithm, which
 * structurally prevents algorithm-confusion attacks where a tampered header {@code alg} could coax a family-accepting
 * verifier into using a weaker primitive (RFC 8725 §3.1).
 *
 * <p>Implementations MUST be safe to share across threads. Each call to
 * {@link #verify(byte[], byte[])} MUST obtain a fresh JCA primitive ({@code Mac}/{@code Signature}) and MUST NOT cache
 * and reuse it across threads -- the JDK explicitly documents these as not thread-safe.</p>
 *
 * <p>Any {@code Verifier} performing HMAC (or any secret-dependent)
 * signature comparison MUST use a constant-time comparison (e.g.
 * {@link java.security.MessageDigest#isEqual(byte[], byte[])}).</p>
 *
 * @author Daniel DeGroff
 */
public interface Verifier {
  /**
   * Does this verifier handle the given algorithm? Answers the algorithm question only -- it does NOT validate a
   * specific signature.
   *
   * @param algorithm the algorithm to test
   * @return true if this Verifier is able to verify a signature for the algorithm
   */
  boolean canVerify(Algorithm algorithm);

  /**
   * Verify the signature against the message using this verifier's bound algorithm and key. Returns normally on
   * success.
   *
   * <p>Callers (including {@code JWTDecoder}) MUST first gate this call
   * with {@link #canVerify(Algorithm)} using the token's declared {@code alg}; verification is performed with the
   * algorithm bound at construction time regardless of any caller-supplied value.</p>
   *
   * @param message   the JWT signing-input bytes (header.payload encoded as UTF-8)
   * @param signature the signature bytes
   * @throws InvalidJWTSignatureException if the signature does not match the message
   * @throws JWTVerifierException         if an underlying JCE operation fails
   */
  void verify(byte[] message, byte[] signature);
}
