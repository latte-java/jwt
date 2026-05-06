/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */
package org.lattejava.jwt.benchmarks.nimbus;

import org.lattejava.jwt.benchmarks.harness.AbstractJwtBenchmark;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public class NimbusBenchmark extends AbstractJwtBenchmark {

  @Override
  protected JwtBenchmarkAdapter createAdapter() {
    return new NimbusAdapter();
  }
}
