/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Per-library Main delegates here so the parity-check / JMH-launch logic lives in one place.
 *
 * Args:
 *   --parity-check                  Run ParityChecker against the adapter and exit.
 *   anything else                   Forwarded to JMH's CommandLineOptions parser.
 */
public final class BenchmarkRunner {

  /** Holds the args from main(String[]). Set by the per-library Main before calling run(). */
  public static final ThreadLocal<String[]> ARGS = ThreadLocal.withInitial(() -> new String[0]);

  public static void run(String libraryName,
                         Class<? extends AbstractJwtBenchmark> benchmarkClass,
                         JwtBenchmarkAdapter adapter) throws Exception {
    String[] args = ARGS.get();
    if (args.length > 0 && "--parity-check".equals(args[0])) {
      Fixtures fixtures = Fixtures.loadDefault();
      int code = ParityChecker.run(adapter, fixtures, libraryName);
      System.exit(code);
    }

    CommandLineOptions cli = new CommandLineOptions(args);
    Options opts = new OptionsBuilder()
        .parent(cli)
        .include(benchmarkClass.getSimpleName())
        .resultFormat(ResultFormatType.JSON)
        .build();
    new Runner(opts).run();
  }

  private BenchmarkRunner() {}
}
