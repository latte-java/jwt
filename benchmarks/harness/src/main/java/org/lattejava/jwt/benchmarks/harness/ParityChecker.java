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

    // unsafe_decode_claims and unsafe_decode_full (HS256 token).
    // UnsupportedOperationException is N/A (library doesn't expose that API shape), not a failure.
    String hs256Token;
    try {
      hs256Token = adapter.encode(BenchmarkAlgorithm.HS256);
    } catch (Exception e) {
      System.err.println("[" + libraryName + "] HS256 re-encode for unsafe-decode parity FAILED: " + e);
      e.printStackTrace(System.err);
      return 1;
    }
    final String token = hs256Token;
    failures += parityForUnsafe(libraryName, "unsafe_decode_claims", () -> adapter.unsafeDecodeClaims(token));
    failures += parityForUnsafe(libraryName, "unsafe_decode_full",   () -> adapter.unsafeDecodeFull(token));

    return failures == 0 ? 0 : 1;
  }

  private interface UnsafeCall {
    Object call() throws Exception;
  }

  private static int parityForUnsafe(String libraryName, String label, UnsafeCall call) {
    try {
      Object decoded = call.call();
      if (decoded == null) {
        System.err.println("[" + libraryName + "] " + label + " returned null");
        return 1;
      }
      System.out.println("[" + libraryName + "] " + label + " parity OK");
      return 0;
    } catch (UnsupportedOperationException e) {
      System.out.println("[" + libraryName + "] " + label + " N/A (no public no-verify API of this shape)");
      return 0;
    } catch (Exception e) {
      System.err.println("[" + libraryName + "] " + label + " parity FAILED: " + e);
      e.printStackTrace(System.err);
      return 1;
    }
  }

  private ParityChecker() {}
}
