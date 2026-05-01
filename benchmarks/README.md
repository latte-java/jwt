# Benchmarks

JMH-based benchmark suite comparing `latte-jwt` against seven other Java JWT libraries:
`auth0/java-jwt`, `jose4j`, `nimbus-jose-jwt`, `jjwt`, `fusionauth-jwt`, `vertx-auth-jwt` —
plus a hand-rolled JCA baseline as a theoretical floor.

The full design is in [`../specs/benchmark-framework.md`](../specs/benchmark-framework.md).
The latest committed results are in [`BENCHMARKS.md`](BENCHMARKS.md).

## Running

```bash
# Full run (~2.5 hours with the canonical config: 3 forks × 3×10s measurement)
./run-benchmarks.sh

# Subset of libraries
./run-benchmarks.sh --libraries baseline,latte-jwt

# Quick dev loop (~10 min — 1 fork, shorter iterations)
./run-benchmarks.sh --quick

# Even faster smoke (~1-2 min, single library)
./run-benchmarks.sh --libraries baseline --quick --duration 2s

# Regenerate BENCHMARKS.md and the README's RS256 leaderboard from the latest result
./update-benchmarks.sh

# Compare two result files
./compare-results.sh results/A.json results/B.json --threshold 5
```

## Profiling

JMH ships a few built-in profilers; the orchestrator surfaces them via `--profile`
(repeatable). Most useful for digging into perf concerns:

```bash
# Allocation rate / B-per-op for one specific benchmark, on one library
./run-benchmarks.sh --libraries latte-jwt --profile gc --include 'hs256_decode_verify_validate$' --quick

# Sampled stack profiling — see where wall-clock time is going
./run-benchmarks.sh --libraries latte-jwt --profile stack --include 'hs256_encode$' --quick

# Multiple profilers in one trial
./run-benchmarks.sh --libraries latte-jwt --profile gc --profile safepoints --quick
```

Profiler choices: `gc` (allocation rate, the most useful for hunting heap churn),
`stack` (sampled stack frames), `safepoints` (safepoint pauses), `perf` (Linux only),
`async-profiler` (Linux/macOS, requires the `async-profiler` binary on `$ASYNC_PROFILER_HOME`
or system path). Run `java -cp <classpath> org.openjdk.jmh.Main -lprof` for the
full list available in the running JMH version.

The `--include <regex>` flag scopes the trial to a single benchmark method (matched
against the full `Class.method` name as a JMH regex). Without it, every method runs
under the requested profiler — useful for sweeping, slow for targeted investigation.

## Quiet-machine guidance

JMH numbers depend on what else the CPU is doing. For results worth quoting:

- **macOS:** connect AC power, disable Low Power Mode, close other applications. The
  orchestrator runs `pmset -g therm` and writes the result into the run-conditions sidecar JSON.
  If `CPU_Speed_Limit` is below 100, your CPU was throttled and absolute numbers are unreliable.
- **Linux:** set the `cpufreq` governor to `performance` and consider disabling Turbo Boost:

  ```bash
  echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
  echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo  # if Intel
  ```

- **All:** relative numbers between libraries remain meaningful even on a noisy machine;
  absolute ops/sec do not. Always re-run on your own hardware before quoting absolutes.

## Vert.x async caveat

`vertx-auth-jwt` exposes only async (`Future`-based) APIs. The adapter unwraps `Future`s
synchronously via `.toCompletionStage().toCompletableFuture().get()`. The unwrap overhead
is included in the reported result and should be considered when comparing absolute throughput.

## Adapter coverage of `unsafe_decode`

The `unsafe_decode` benchmark measures decoding a signed token *without* verifying the
signature — a real OAuth/OIDC pattern (read `kid`/`iss` to choose a key, verify in a second
pass). Library coverage:

| Library | unsafe_decode |
|---------|:---:|
| baseline | ✓ |
| latte-jwt | ✓ |
| auth0/java-jwt | ✓ (`JWT.decode`) |
| jose4j | ✓ (`JwtConsumerBuilder.setSkipSignatureVerification`) |
| nimbus-jose-jwt | ✓ (`SignedJWT.parse`) |
| fusionauth-jwt | ✓ (`JWTUtils.decodePayload`) |
| jjwt | N/A — 0.12+ has no public no-verify-signature API |
| vertx-auth-jwt | N/A — no public unsafe-decode API |

Libraries marked N/A are simply absent from the unsafe_decode leaderboard.

## Adding a library

1. Create `benchmarks/vendors/<lib>/project.latte` depending on `org.lattejava.jwt.benchmarks:harness:0.1.0-{integration}`,
   the new library, and JMH (core + annprocess).
2. Implement `org.lattejava.jwt.benchmarks.<lib>.<Lib>Adapter` against `JwtBenchmarkAdapter`.
3. Add a one-line `<Lib>Benchmark extends AbstractJwtBenchmark` and a `Main` that calls
   `BenchmarkRunner.run(...)`.
4. Add the library ID to `benchmarks.yaml`.
5. Pin the version in [`library-versions.md`](library-versions.md).
6. Update `main_class_for_library()` and `classpath_for_library()` in `run-benchmarks.sh`.
7. Update `prettyname()` in `compare-results.sh` and the awk libname mapping in
   `update-benchmarks.sh`.

The framework deliberately requires touching three scripts when adding a library — that
keeps the wiring explicit and discoverable rather than pretending to be reflective.

## Reproducibility

Fixtures in [`fixtures/`](fixtures/) are checked in: HMAC key (32 random bytes), RSA-2048
and EC P-256 key pairs (PKCS#8 / SPKI), and the canonical 10-claim payload. They are test
fixtures only — do not use in production.

The canonical claims have a fixed `iat = 1761408000` (a historical timestamp). The decoder's
notion of "now" is overridden to `iat + 30 minutes` for libraries that allow it. For
libraries that don't (Vert.x, auth0), the adapter regenerates `iat`/`exp` per `prepare()`
relative to wall-clock time so the token is fresh at trial start.

## Files in this directory

- `run-benchmarks.sh` — orchestrator (sanity → build → parity → measurement → merge → conditions sidecar)
- `update-benchmarks.sh` — regenerates `BENCHMARKS.md` and the README's RS256 leaderboard from the latest result
- `compare-results.sh` — diffs two merged result files
- `benchmarks.yaml` — library list, algorithms, JMH config
- `library-versions.md` — pinned versions per library (working notes)
- `fixtures/` — keys + canonical claims
- `harness/` — shared adapter contract + JMH abstract class + parity checker
- `vendors/<library-name>/` — per-library Latte project + adapter implementation. Every
  library being measured (including the JCA baseline and our own latte-jwt projects)
  lives here so the suite gives no preferential treatment to any vendor.
- `results/` — JSON outputs (only `latest.json` and `latest.conditions.json` are committed)
