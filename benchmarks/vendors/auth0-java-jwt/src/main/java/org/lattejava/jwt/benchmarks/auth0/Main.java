/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */
package org.lattejava.jwt.benchmarks.auth0;

import org.lattejava.jwt.benchmarks.harness.BenchmarkRunner;

public final class Main {

  public static void main(String[] args) throws Exception {
    BenchmarkRunner.ARGS.set(args);
    BenchmarkRunner.run("auth0-java-jwt", Auth0Benchmark.class, new Auth0Adapter());
  }
}
