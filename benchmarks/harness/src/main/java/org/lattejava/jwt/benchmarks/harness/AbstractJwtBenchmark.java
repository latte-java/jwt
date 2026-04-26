/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * Shared JMH @Benchmark surface. Per-library subclasses supply an adapter via
 * {@link #createAdapter()} — JMH's annotation processor walks the class hierarchy and
 * materializes the @Benchmark methods on each subclass.
 *
 * Throughput-only by default; decode-verify-validate methods carry an additional
 * @BenchmarkMode that includes Mode.AverageTime so the report shows both ops/sec
 * and average latency.
 *
 * @return values are returned to JMH so the framework suppresses dead-code elimination.
 */
@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public abstract class AbstractJwtBenchmark {

  protected JwtBenchmarkAdapter adapter;
  protected String hs256Token;
  protected String rs256Token;
  protected String es256Token;

  protected abstract JwtBenchmarkAdapter createAdapter();

  @Setup
  public void setup() throws Exception {
    Fixtures fixtures = Fixtures.loadDefault();
    adapter = createAdapter();
    adapter.prepare(fixtures);
    hs256Token = adapter.encode(BenchmarkAlgorithm.HS256);
    rs256Token = adapter.encode(BenchmarkAlgorithm.RS256);
    es256Token = adapter.encode(BenchmarkAlgorithm.ES256);
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public String hs256_encode() throws Exception {
    return adapter.encode(BenchmarkAlgorithm.HS256);
  }

  @Benchmark
  @BenchmarkMode({Mode.Throughput, Mode.AverageTime})
  public Object hs256_decode_verify_validate() throws Exception {
    return adapter.decodeVerifyValidate(BenchmarkAlgorithm.HS256, hs256Token);
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public String rs256_encode() throws Exception {
    return adapter.encode(BenchmarkAlgorithm.RS256);
  }

  @Benchmark
  @BenchmarkMode({Mode.Throughput, Mode.AverageTime})
  public Object rs256_decode_verify_validate() throws Exception {
    return adapter.decodeVerifyValidate(BenchmarkAlgorithm.RS256, rs256Token);
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public String es256_encode() throws Exception {
    return adapter.encode(BenchmarkAlgorithm.ES256);
  }

  @Benchmark
  @BenchmarkMode({Mode.Throughput, Mode.AverageTime})
  public Object es256_decode_verify_validate() throws Exception {
    return adapter.decodeVerifyValidate(BenchmarkAlgorithm.ES256, es256Token);
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public Object unsafe_decode() throws Exception {
    return adapter.unsafeDecode(hs256Token);
  }
}
