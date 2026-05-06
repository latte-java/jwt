/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */
package org.lattejava.jwt.benchmarks.jose4j;

import org.lattejava.jwt.benchmarks.harness.AbstractJwtBenchmark;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public class Jose4jBenchmark extends AbstractJwtBenchmark {

  @Override
  protected JwtBenchmarkAdapter createAdapter() {
    return new Jose4jAdapter();
  }
}
