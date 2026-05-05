/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

/**
 * Per-library contract for the benchmark harness. Implementations are stateless after
 * construction; all keys, signers, verifiers, and pre-encoded tokens are stashed during
 * {@link #prepare(Fixtures)} which the harness calls once per JMH trial.
 *
 * The two no-verify decode methods exist so we can compare libraries on their natural
 * "peek" API shape — some libraries expose only payload-claims access, others build a
 * full header+claims object. Adapters that cannot implement either method (no public
 * no-verify API of that shape) throw {@link UnsupportedOperationException}; the
 * orchestrator's parity check tolerates this and the result merger records N/A.
 */
public interface JwtBenchmarkAdapter {

  /** One-time setup. Called from JMH @Setup(Level.Trial). */
  void prepare(Fixtures fixtures) throws Exception;

  /** Encode the canonical claims payload using {@code alg}. */
  String encode(BenchmarkAlgorithm alg) throws Exception;

  /** Parse, verify signature, validate claims (`exp`/`nbf`/`iss`/`aud`). */
  Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception;

  /**
   * Decode only the payload claims (base64 + JSON parse), with no signature verification
   * and no header parsing. Mirrors APIs like {@code JWTUtils.decodePayload} in
   * fusionauth-jwt and {@code decodeClaimsUnsecured} in latte-jwt.
   *
   * @throws UnsupportedOperationException if the library exposes no such API
   */
  Object unsafeDecodeClaims(String token) throws Exception;

  /**
   * Decode the full JWT (header + claims), with no signature verification. Mirrors APIs
   * like auth0's {@code JWT.decode}, jose4j's no-verify {@code JwtConsumer.process}, and
   * latte-jwt's {@code decodeUnsecured}.
   *
   * @throws UnsupportedOperationException if the library exposes no such API
   */
  Object unsafeDecodeFull(String token) throws Exception;
}
