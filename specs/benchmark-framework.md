# Benchmark Framework — Design

| | |
|---|---|
| **Status** | Draft |
| **Version / Scope** | Tooling (not part of any release) |
| **Owner** | Daniel DeGroff |
| **Created** | 2026-04-25 |
| **Last updated** | 2026-04-25 |

## Change log

- **2026-04-25** — Initial draft.

## Problem statement

`latte-jwt` aims to be the fastest pure-Java JWT library while staying zero-dependency. To make that claim defensible, we need reproducible head-to-head benchmarks against the other widely-used Java JWT libraries. Today there is no benchmark in this repository, and the only public reference (`skjolber/java-jwt-benchmark`) covers only RSA verification across five libraries. This spec defines a benchmark framework that:

1. Compares `latte-jwt` against seven other Java JWT libraries on the same hardware, JVM, fixtures, and JMH configuration.
2. Covers the operations a real OAuth/OIDC service performs (encode, decode + verify + validate), not just raw crypto.
3. Produces a checked-in `BENCHMARKS.md` report and a leaderboard summary in the project README, both regenerable from JSON results.
4. Makes adding a library straightforward (one new directory + one adapter class).

## Goals

- **Real-world bias.** Benchmarks measure full encode and decode-verify-validate paths, not just sign/verify primitives. JSON parsing cost is exposed via a parse-only benchmark; raw crypto cost via per-algorithm sign+verify benchmarks.
- **Fair across libraries.** Identical key material, identical claims payload, identical JMH parameters. The only variable is the library's code path.
- **Classpath-isolated per library.** Each library runs in its own JVM with only its declared dependencies on the runtime classpath, so transitive Jackson/BouncyCastle versions never collide.
- **Reproducible.** Checked-in fixtures + checked-in latest-snapshot JSON + a single `run-benchmarks.sh` invocation reproduces the report.
- **Low ceremony to extend.** Add a library = new `benchmarks/<lib>/` directory + new adapter. Add an algorithm = new entries in `algorithms` array + adapter method. Adding a benchmark *method* requires touching the shared harness only.

## Non-goals

- **Continuous integration.** Benchmarks are noisy and slow. The framework is run manually and committed snapshots represent the latest authoritative result.
- **Network benchmarks.** JWKS HTTP fetch performance is not measured. We are isolating in-process JWT operations.
- **JWE.** Encryption is out of scope for v1; only JWS (signed JWT) operations are benchmarked.
- **Cross-language comparisons.** Java only.
- **Production-grade observability.** No flame graphs, no allocation profiling beyond what JMH offers via `-prof gc`. (Profiles are easy to add later via JMH's plugin surface.)

## Libraries under test

| ID | Library | Notes |
|----|---------|-------|
| `baseline` | Hand-rolled JCA + zero-dep JSON | "Theoretical floor" reference, not a real library. Italicized in reports. |
| `latte-jwt` | `org.lattejava:jwt` | This project. Headline column. |
| `auth0-java-jwt` | `com.auth0:java-jwt` | Refuses `alg=none` by default → N/A in those cells. |
| `jose4j` | `org.bitbucket.b_c:jose4j` | |
| `nimbus-jose-jwt` | `com.nimbusds:nimbus-jose-jwt` | Heavyweight (full JOSE: JWE/JWS/JWK). |
| `jjwt` | `io.jsonwebtoken:jjwt-impl` + `jjwt-api` + `jjwt-jackson` | Multi-jar; we depend on the API + Jackson runtime. |
| `fusionauth-jwt` | `io.fusionauth:fusionauth-jwt` | The library this project forked from (pre-7.0). |
| `vertx-auth-jwt` | `io.vertx:vertx-auth-jwt` | Vert.x's API is async; adapter unwraps `Future`s synchronously. The adapter overhead is captured in the result and called out in `BENCHMARKS.md`. |
| `inverno-security-jose` | `io.inverno.mod:inverno-security-jose` | Adapter uses the public synchronous API surface only — no CDI container at runtime. |

Library versions are pinned in each per-library `project.latte` and bumped manually. The framework is not a continuous version-tracking tool.

## Architecture overview

### Directory layout

```
benchmarks/
├── README.md                     # how to run; linked from main README
├── BENCHMARKS.md                 # generated report (committed snapshot)
├── benchmarks.yaml               # runner config
├── run-benchmarks.sh             # orchestrator
├── update-benchmarks.sh          # regenerates BENCHMARKS.md from latest JSON
├── compare-results.sh            # diffs two JSON result files
├── results/                      # JSON outputs (committed: latest only; older gitignored)
├── fixtures/                     # shared keys + canonical claims payload
│   ├── README.md                 # "FIXTURES — DO NOT USE IN PRODUCTION"
│   ├── hmac-256.key              # 32 random bytes (raw)
│   ├── rsa-2048-private.pem      # PKCS#8
│   ├── rsa-2048-public.pem       # SPKI
│   ├── ec-p256-private.pem       # PKCS#8
│   ├── ec-p256-public.pem        # SPKI
│   └── claims.json               # canonical 10-claim payload
├── harness/                      # shared module: adapter interface + abstract JMH class
├── baseline/                     # hand-rolled JCA-only "theoretical floor"
├── latte-jwt/
├── auth0-java-jwt/
├── jose4j/
├── nimbus-jose-jwt/
├── jjwt/
├── fusionauth-jwt/
├── vertx-auth-jwt/
└── inverno-security-jose/
```

Each per-library directory contains:

```
benchmarks/<lib>/
├── project.latte                 # depends on `harness` + that library only
└── src/main/java/org/lattejava/jwt/benchmarks/<lib>/
    ├── <Lib>Adapter.java         # implements harness.JwtBenchmarkAdapter
    ├── <Lib>Benchmark.java       # extends harness.AbstractJwtBenchmark, supplies createAdapter()
    └── Main.java                 # JMH OptionsBuilder entrypoint
```

### Build & runtime model (Option 3 — shared contract, isolated runtime)

The shared `harness` module defines:

- **`interface JwtBenchmarkAdapter`** — the contract every library implements. Methods receive only the prepared inputs; setup of keys, parsed claims, etc. happens in each adapter's constructor or a `prepare()` call invoked during `@Setup(Level.Trial)`.
- **`abstract class AbstractJwtBenchmark`** — owns the JMH `@State`, `@Setup`, and `@Benchmark` methods. Subclasses provide an adapter instance via `protected abstract JwtBenchmarkAdapter createAdapter();`. Pre-encoded tokens (one per algorithm) are computed once during `@Setup(Level.Trial)` so the decode benchmarks measure decode, not encode-then-decode.

JMH's annotation processor walks the class hierarchy when generating its synthetic benchmark stubs, so the per-library subclass is enough to materialize all `@Benchmark` methods at compile time. This is a standard JMH pattern.

Each per-library project compiles against:
- `harness` (shared types)
- `org.openjdk.jmh:jmh-core` + `org.openjdk.jmh:jmh-generator-annprocess` (compile-only)
- That single library

It produces a runnable JAR whose `Main` invokes JMH programmatically:

```java
public static void main(String[] args) throws Exception {
  Options opts = new OptionsBuilder()
      .include(LatteJwtBenchmark.class.getSimpleName())
      .resultFormat(ResultFormatType.JSON)
      .build();
  new Runner(opts).run();
}
```

The orchestrator passes JMH-native CLI args through (`-wi`, `-i`, `-w`, `-r`, `-f`, `-rff`, etc.), so JMH's standard option parser does the heavy lifting.

**Runtime isolation:** Each library's JAR runs in its own JVM (one orchestrator-launched `java -jar` invocation per library). No transitive dependencies cross between libraries. JMH's `@Fork` is set to 1 — additional forks only buy variance reduction within one library, and we get cross-library JVM freshness for free from the orchestrator's per-library invocation.

### Build risk: Latte + JMH annotation processing

JMH's annotation processor is auto-discovered by `javac` via `META-INF/services/javax.annotation.processing.Processor` when `jmh-generator-annprocess` is on the compile classpath. The Latte `java` plugin should honor this by default — but it has not been verified for this project. Before scaling to eight libraries, the following must be proven on the `latte-jwt` adapter alone:

1. `latte build` produces `META-INF/BenchmarkList` and the synthetic `<Class>_<method>_jmhTest` classes.
2. `java -jar build/jars/latte-jwt-bench-*.jar -l` lists all expected `@Benchmark` methods.

**If the annotation processor is not auto-discovered**, the fallbacks in priority order are:
1. Pass `-processor org.openjdk.jmh.generators.BenchmarkProcessor` via `java.settings.compilerArguments` in `project.latte`.
2. Generate `META-INF/BenchmarkList` once with a separate Maven/Gradle scratch project, check it into the harness module, and let Latte ship it on the JAR. Less elegant but unblocks shipping.
3. As a last resort, hand-write a non-annotation-driven benchmark loop using `OptionsBuilder.include(...)` + manually-maintained subclasses. This loses some JMH ergonomics but stays statistically valid.

The fallback choice is recorded in `benchmarks/README.md` if it ends up needed.

## Operation matrix

### Algorithms

| Family | Choice | Rationale |
|--------|--------|-----------|
| HMAC | HS256 | 256-bit shared secret; standard for symmetric token use. |
| RSA | RS256-2048 | Smallest recommended modulus; RS256 dominates real-world use. |
| ECDSA | ES256-P256 | Smallest standard EC curve for JWT. |
| none | `alg=none` | Tests JSON-parse + serialization cost without crypto. |

Larger keys (RSA-3072/4096, P-384, P-521) are deliberately out of scope: they make crypto slower without changing relative library performance. Adding them later is a one-line YAML change + one new fixture pair.

EdDSA (Ed25519) is also deferred — library coverage is uneven across the eight libraries and the matrix is already nine cells per library. Coverage will be audited at version-pin time, then EdDSA added in a follow-up if at least six of eight libraries support it via a stable public API.

### Operations

For each library, nine `@Benchmark` methods:

| ID | Algorithm | What it measures |
|----|-----------|------------------|
| `hs256_encode` | HS256 | Build claims → HMAC-SHA-256 → base64url string. |
| `hs256_decode_verify_validate` | HS256 | Parse → verify HMAC → check `exp`/`nbf`/`iss`/`aud`. |
| `rs256_encode` | RS256 | Build claims → RSA sign → base64url string. |
| `rs256_decode_verify_validate` | RS256 | Parse → verify RSA → check claims. |
| `es256_encode` | ES256 | Build claims → ECDSA sign (DER→JOSE) → base64url string. |
| `es256_decode_verify_validate` | ES256 | Parse → verify ECDSA (JOSE→DER) → check claims. |
| `parse_only` | (signed token) | Parse JSON of a signed token; do not verify signature. Measures pure JSON-parse cost. |
| `none_encode` | `none` | Serialize claims with `alg=none` header; no crypto. |
| `none_decode` | `none` | Parse a `none`-alg token; no crypto. |

Libraries that refuse `alg=none` (auth0/java-jwt, optionally jose4j depending on version) emit `N/A` in `none_encode` and `none_decode`. The adapter signals this by throwing a sentinel `UnsupportedOperationException` from those methods; the result merger preserves N/A in the report.

The baseline implements **seven of nine** benchmarks: the six per-algorithm encode/decode-verify-validate methods plus `parse_only`. It does not implement `none_encode` or `none_decode` — the baseline is the minimum honest crypto path, and `alg=none` skips the crypto entirely, which would defeat the comparison the baseline exists to enable. Baseline's `parse_only` uses `LatteJSONProcessor` (the project's own zero-dep parser) to keep the floor honest about JSON-parse cost; baseline reports `N/A` for the two `none` cells.

### Adapter interface

```java
public interface JwtBenchmarkAdapter {
  String encode(BenchmarkAlgorithm alg);
  Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token);
  Object parseOnly(String token);
  String noneEncode();
  Object noneDecode(String token);
}

public enum BenchmarkAlgorithm { HS256, RS256, ES256 }
```

The enum is named `BenchmarkAlgorithm` to avoid clashing with the project's `org.lattejava.jwt.Algorithm` interface inside `latte-jwt`'s adapter — that adapter imports both types.

Adapter implementations are stateless after construction. All `Algorithm`-keyed pre-built signers, verifiers, and pre-encoded tokens are stashed on the adapter instance during `prepare()`, called once from `AbstractJwtBenchmark`'s `@Setup(Level.Trial)`.

## Fixtures

### Keys

All fixture keys are random and committed to the repo with a top-level warning:

> **`fixtures/README.md`** — These keys are test fixtures used to make benchmark inputs reproducible. They are not, and have never been, used to sign anything outside this benchmark suite. Do not use them in production. Do not paste their public keys into JWKS endpoints.

- `hmac-256.key` — 32 bytes from `/dev/urandom`, raw.
- `rsa-2048-private.pem`, `rsa-2048-public.pem` — generated via `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` + `openssl rsa -pubout`.
- `ec-p256-private.pem`, `ec-p256-public.pem` — generated via `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` + `openssl ec -pubout`.

PEM format is PKCS#8 for private, SPKI (`SubjectPublicKeyInfo`) for public — both library-agnostic.

### Canonical claims payload

```json
{
  "iss": "https://benchmarks.lattejava.org",
  "sub": "5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f",
  "aud": "benchmark-audience",
  "iat": 1761408000,
  "nbf": 1761408000,
  "exp": 1761411600,
  "jti": "01JK6V2N5W3YE4XJ5Y7Z8A9BC0",
  "scope": "openid profile email",
  "email": "test@example.com",
  "email_verified": true
}
```

Ten claims (~270 bytes serialized). Issued-at is a fixed historical Unix timestamp; expiration is 1 hour later. The `decode_verify_validate` benchmarks override the decoder's notion of "now" to 30 minutes after `iat` — this guarantees `nbf` passes and `exp` does not throw, on every run, regardless of wall-clock time.

For libraries whose decoder API does not let "now" be fixed externally (Vert.x, possibly auth0), the adapter regenerates the token on each `prepare()` with `iat = now()` and `exp = now() + 1h`. The pre-encoded token is then stable for the trial. This is documented in the per-library adapter Javadoc.

## Runner config: `benchmarks.yaml`

```yaml
libraries:
  - baseline
  - latte-jwt
  - auth0-java-jwt
  - jose4j
  - nimbus-jose-jwt
  - jjwt
  - fusionauth-jwt
  - vertx-auth-jwt
  - inverno-security-jose

algorithms: [HS256, RS256, ES256, none]
operations: [encode, decodeVerifyValidate, parseOnly, noneEncode, noneDecode]

jmh:
  warmup-iterations:      1
  warmup-time:            15s
  measurement-iterations: 1
  measurement-time:       30s
  forks:                  1
  threads:                1
  mode:                   throughput

output:
  json-dir:  results/
  label:     ""
```

The YAML is **runner config only** — it selects what to run and how, but does not define benchmark code. Adding a benchmark *method* requires editing the harness module; adding an *algorithm* or *library* edits YAML + a fixture or adapter.

## Orchestrator: `run-benchmarks.sh`

### CLI flags

```
--libraries  <list>      Subset of yaml.libraries (comma-separated)
--algorithms <list>      Subset of yaml.algorithms
--operations <list>      Subset of yaml.operations
--label      <name>      Appended to results filename
--duration   <time>      Shortcut: sets warmup-time AND measurement-time
--quick                  Preset: 5s warmup, 10s measurement, 1 fork
--no-build               Skip `latte build`, reuse existing JARs
--update                 Also regenerate BENCHMARKS.md after run completes
-h, --help               Print usage and exit
```

CLI flags override YAML for the duration of the invocation; they do not rewrite the YAML.

### Flow

1. **Parse** — load YAML, apply CLI overrides, validate.
2. **Sanity check** — `latte` on PATH, `java -version` ≥ 21, `fixtures/` populated, every selected `benchmarks/<lib>/` directory exists.
3. **Per library, in YAML order:**
   - `cd benchmarks/<lib> && latte build` (skipped under `--no-build`).
   - `java -jar build/jars/<lib>-bench-*.jar <jmh-args> -rf json -rff results/<lib>-<ts>.json` — invoked from the repo root with full classpath isolation (each invocation = its own JVM).
   - Non-zero exit: log to stderr, mark library as failed, continue.
4. **Merge** — concatenate per-library JSON arrays into `results/<timestamp>[-<label>].json`. JMH's native JSON schema is preserved; this file is what `compare-results.sh` and `update-benchmarks.sh` consume.
5. **Update report** — if `--update`, run `update-benchmarks.sh` against the freshly merged file.

### Failure handling

- A failed library does not abort the run. Subsequent libraries continue. The merged JSON contains entries for libraries that succeeded; failed libraries are reported in `BENCHMARKS.md` with an explanatory note rather than an empty row.
- A failed sanity check (missing fixtures, wrong Java version) aborts before any benchmarks run — no half-results.

## Report formats

### `update-benchmarks.sh`

Reads the most recent `results/*.json` and rewrites `BENCHMARKS.md` between sentinel comments:

```html
<!-- BENCHMARKS:START -->
... auto-generated tables ...
<!-- BENCHMARKS:END -->
```

The surrounding prose (intro, methodology notes, link back to README) is hand-edited and preserved across regenerations. The generator is a Bash script using `jq` for JSON traversal and standard `printf`-based table emission — no Python, no extra runtime dependencies.

### `BENCHMARKS.md` shape

```
# JWT Library Benchmarks

(Hand-edited intro: how to read, hardware/JVM caveat, link back to README.)

## Overall leaderboard — decode-verify-validate (the headline op)

(Aggregate score across HS256/RS256/ES256 decode-verify-validate.)

<!-- BENCHMARKS:START -->

## Throughput by algorithm (ops/sec, higher is better)

### HS256 — encode
(leaderboard table)

### HS256 — decode + verify + validate
(leaderboard table)

### RS256 — encode
(leaderboard table)

### RS256 — decode + verify + validate
(leaderboard table)

### ES256 — encode
(leaderboard table)

### ES256 — decode + verify + validate
(leaderboard table)

## Supporting operations

### Parse-only (no signature verification)
(leaderboard table)

### `alg=none` — encode
(leaderboard table; libs that refuse render as N/A)

### `alg=none` — decode
(leaderboard table; libs that refuse render as N/A)

## Run conditions
- Hardware: <captured>
- JVM:      <captured>
- Date:     <captured>
- Config:   warmup 1×15s, measurement 1×30s, 1 fork, 1 thread
- Full JSON: results/<filename>.json

<!-- BENCHMARKS:END -->
```

### Leaderboard table format

Each table is sorted by ops/sec descending. Two percentage columns:

```markdown
| # | Library              |   ops/sec |  vs leader | vs latte-jwt |
|--:|----------------------|----------:|-----------:|-------------:|
| 1 | <fastest>            |   <ops/s> |    100.0 % |        ...   |
| 2 | <second>             |   <ops/s> |       ...  |        ...   |
| ...                                                                |
|   | _baseline (JCA)_     |  _<ops/s>_|     <...> |        <...>  |
```

- `vs leader` — leaderboard standard.
- `vs latte-jwt` — explicit project positioning.
- `baseline` is rendered in italics, ranked separately at the bottom regardless of speed (it is a reference, not a competitor).

Confidence intervals from JMH (`± stdev`) are folded into the cell when the interval exceeds 5 % of the median; narrower intervals are omitted to keep the table readable. The threshold is implemented in `update-benchmarks.sh` and can be tuned via a `--ci-threshold` flag.

### Top-of-page summary

A single aggregate-leaderboard table at the top of `BENCHMARKS.md` ranks libraries by mean of their three `decode_verify_validate` ops/sec values (HS256, RS256, ES256). This is the single number a reader most often wants — "who's fastest at the most common operation."

### `README.md` `## Performance` section

One leaderboard table for **RS256 decode-verify-validate** (the dominant cost in real OAuth/OIDC services), plus a paragraph linking to `BENCHMARKS.md`. Hardware and JVM footer match the HTTP project's `README.md` style. Regenerated by `update-benchmarks.sh` between its own sentinel markers.

## Open questions / future work

1. **`@Param`-driven payload variation.** Right now we use one canonical payload. JMH `@Param` lets us add `claimsSize ∈ {minimal, normal, large}` cheaply later, expanding the matrix without restructuring.
2. **GC profile.** `-prof gc` adds allocation-rate columns; useful for identifying libraries that thrash the heap. Defer until v1 stabilizes.
3. **EdDSA.** Add Ed25519 once we know which libraries support it cleanly (audit during library-version pinning).
4. **CI smoke run.** Eventually a `--quick` run on PRs to catch performance regressions, gated on a stable runner. Out of scope for v1.
5. **Multi-threaded benchmarks.** Threads = 1 for v1 (single-threaded throughput is what real services scale by replicating processes). Adding `-t auto` is a one-line change once we want it.
6. **Tooling for `vertx-auth-jwt`.** If the async-unwrap overhead turns out to be larger than the underlying crypto cost, the lib's adapter is misleading by design — we will document this prominently rather than hide it.
