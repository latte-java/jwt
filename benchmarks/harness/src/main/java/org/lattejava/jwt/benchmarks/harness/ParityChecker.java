/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

/**
 * Pre-flight smoke test invoked by each per-library Main when launched with --parity-check.
 *
 * For each algorithm, the adapter encodes the canonical claims, decodes its own output, and
 * the round-tripped result is asserted non-null (libraries return wildly different decoded
 * shapes — DecodedJWT, Jws, JwtClaims, etc. — so we verify the call succeeds rather than
 * structurally inspect). For unsafe_decode, the same call is made; UnsupportedOperationException
 * is treated as N/A and not a failure.
 *
 * Exit code 0 = all checks pass (or N/A where applicable).
 * Exit code 1 = any non-N/A check failed.
 */
public final class ParityChecker {

  public static int run(JwtBenchmarkAdapter adapter, Fixtures fixtures, String libraryName) {
    int failures = 0;
    try {
      adapter.prepare(fixtures);
    } catch (Exception e) {
      System.err.println("[" + libraryName + "] prepare() failed: " + e);
      e.printStackTrace(System.err);
      return 1;
    }

    for (BenchmarkAlgorithm alg : BenchmarkAlgorithm.values()) {
      try {
        String token = adapter.encode(alg);
        if (token == null || token.isEmpty()) {
          System.err.println("[" + libraryName + "] " + alg + " encode produced null/empty");
          failures++;
          continue;
        }
        Object decoded = adapter.decodeVerifyValidate(alg, token);
        if (decoded == null) {
          System.err.println("[" + libraryName + "] " + alg + " decode returned null");
          failures++;
        } else {
          System.out.println("[" + libraryName + "] " + alg + " parity OK");
        }
      } catch (Exception e) {
        System.err.println("[" + libraryName + "] " + alg + " parity FAILED: " + e);
        e.printStackTrace(System.err);
        failures++;
      }
    }

    // unsafe_decode (HS256 token) — UnsupportedOperationException is N/A, not a failure
    try {
      String token = adapter.encode(BenchmarkAlgorithm.HS256);
      Object decoded = adapter.unsafeDecode(token);
      if (decoded == null) {
        System.err.println("[" + libraryName + "] unsafe_decode returned null");
        failures++;
      } else {
        System.out.println("[" + libraryName + "] unsafe_decode parity OK");
      }
    } catch (UnsupportedOperationException e) {
      System.out.println("[" + libraryName + "] unsafe_decode N/A (no public unsafe-decode API)");
    } catch (Exception e) {
      System.err.println("[" + libraryName + "] unsafe_decode parity FAILED: " + e);
      e.printStackTrace(System.err);
      failures++;
    }

    return failures == 0 ? 0 : 1;
  }

  private ParityChecker() {}
}
