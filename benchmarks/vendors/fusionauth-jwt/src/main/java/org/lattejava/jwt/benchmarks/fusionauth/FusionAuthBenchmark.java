/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.fusionauth;

import org.lattejava.jwt.benchmarks.harness.AbstractJwtBenchmark;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public class FusionAuthBenchmark extends AbstractJwtBenchmark {

  @Override
  protected JwtBenchmarkAdapter createAdapter() {
    return new FusionAuthAdapter();
  }
}
