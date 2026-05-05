/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.lattejwt;

import org.lattejava.jwt.benchmarks.harness.BenchmarkRunner;

public final class Main {
  public static void main(String[] args) throws Exception {
    BenchmarkRunner.ARGS.set(args);
    BenchmarkRunner.run("latte-jwt", LatteJWTBenchmark.class, new LatteJWTAdapter());
  }
}
