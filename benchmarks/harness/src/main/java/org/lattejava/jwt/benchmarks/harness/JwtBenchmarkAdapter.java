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
 * Adapters that cannot implement {@link #unsafeDecode(String)} (no public no-verify API)
 * throw {@link UnsupportedOperationException} from that method. The orchestrator's parity
 * check tolerates this; the result merger records N/A.
 */
public interface JwtBenchmarkAdapter {

  /** One-time setup. Called from JMH @Setup(Level.Trial). */
  void prepare(Fixtures fixtures) throws Exception;

  /** Encode the canonical claims payload using {@code alg}. */
  String encode(BenchmarkAlgorithm alg) throws Exception;

  /** Parse, verify signature, validate claims (`exp`/`nbf`/`iss`/`aud`). */
  Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception;

  /**
   * Decode a signed token using the library's public unsafe-decode API — base64 + JSON
   * parse, no signature verification, no claim validation.
   *
   * @throws UnsupportedOperationException if the library exposes no such API
   */
  Object unsafeDecode(String token) throws Exception;
}
