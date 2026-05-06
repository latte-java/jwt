/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */
package org.lattejava.jwt.benchmarks.lattejwtjackson;

import org.lattejava.jwt.benchmarks.harness.AbstractJwtBenchmark;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public class LatteJWTJacksonBenchmark extends AbstractJwtBenchmark {
  @Override
  protected JwtBenchmarkAdapter createAdapter() {
    return new LatteJWTJacksonAdapter();
  }
}
