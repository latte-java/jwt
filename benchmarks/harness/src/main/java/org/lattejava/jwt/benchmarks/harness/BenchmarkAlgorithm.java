/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

/**
 * Benchmark-axis algorithm. Named to avoid clashing with `org.lattejava.jwt.Algorithm`
 * inside the latte-jwt adapter — that adapter imports both types.
 */
public enum BenchmarkAlgorithm {
  HS256,
  RS256,
  ES256
}
