/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */
package org.lattejava.jwt.benchmarks.nimbus;

import org.lattejava.jwt.benchmarks.harness.BenchmarkRunner;

public final class Main {

  public static void main(String[] args) throws Exception {
    BenchmarkRunner.ARGS.set(args);
    BenchmarkRunner.run("nimbus-jose-jwt", NimbusBenchmark.class, new NimbusAdapter());
  }
}
