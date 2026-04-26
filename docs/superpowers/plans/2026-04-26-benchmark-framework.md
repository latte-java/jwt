# Benchmark Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a JMH-based benchmark framework that compares `latte-jwt` against seven other Java JWT libraries plus a hand-rolled JCA baseline, producing a reproducible `BENCHMARKS.md` report and a leaderboard summary in the project README.

**Architecture:** Per-library Latte project for compile-time dependency isolation; per-library JVM at runtime for true classpath isolation; shared `harness` module providing `JwtBenchmarkAdapter` interface and `AbstractJwtBenchmark` JMH class. YAML-driven runner config; Bash orchestrator with pre-flight parity check; JSON results merged into `BENCHMARKS.md` regenerated from JSON.

**Tech Stack:** Java 21, Latte CLI (`latte build`), JMH 1.37, Bash + `jq` for orchestration. No Python, no extra runtimes.

**Reference:** Spec at `specs/benchmark-framework.md` (status: Approved, 2026-04-26). The spec is authoritative; if implementation reveals a discrepancy, update the spec rather than silently deviate.

---

## Task ordering and review checkpoints

Tasks 0 and 1 are spikes that prove out toolchain assumptions. **Do not skip them.** They unblock everything that follows; if they fail, the fallbacks documented in the spec become the path forward and the rest of the plan adapts accordingly.

After Task 9 (latte-jwt adapter passes parity), the plumbing is fully proven. Tasks 10–22 fan out and are largely parallelizable in subagent-driven mode. Tasks 23–28 produce the human-facing artifacts.

Recommended commit cadence: one commit per task (each task ends in a `git commit` step). Some larger tasks have a mid-task commit explicitly called out.

---

## Task 0: Latte + JMH annotation-processor spike

**Why first:** The spec calls this out as the single biggest unverified assumption (§ "Build risk"). Writing eight adapters before confirming the build emits `META-INF/BenchmarkList` is wasted work if it fails.

**Files:**
- Create: `benchmarks/spike/project.latte`
- Create: `benchmarks/spike/src/main/java/org/lattejava/jwt/benchmarks/spike/HelloBenchmark.java`

- [ ] **Step 1: Create the spike project.latte**

```groovy
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
jmhVersion = "1.37"

project(group: "org.lattejava.jwt.benchmarks", name: "spike", version: "0.1.0", licenses: ["MIT"]) {
  workflow {
    standard()
  }

  dependencies {
    group(name: "compile") {
      dependency(id: "org.openjdk.jmh:jmh-core:${jmhVersion}")
      dependency(id: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}")
    }
  }

  publications {
    standard()
  }
}

dependency = loadPlugin(id: "org.lattejava.plugin:dependency:0.1.5")
java = loadPlugin(id: "org.lattejava.plugin:java:0.1.7")
idea = loadPlugin(id: "org.lattejava.plugin:idea:0.1.5")

java.settings.javaVersion = "21"

target(name: "clean", description: "Cleans the build directory") {
  java.clean()
}

target(name: "build", description: "Compiles the Java source files and creates a JAR") {
  java.compileMain()
  java.jar()
}
```

- [ ] **Step 2: Create the spike benchmark class**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.spike;

import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class HelloBenchmark {
  @Benchmark
  public int addOneAndOne() {
    return 1 + 1;
  }
}
```

- [ ] **Step 3: Build the spike**

Run: `cd benchmarks/spike && latte build`

Expected: build succeeds, JAR is produced under `build/jars/`.

- [ ] **Step 4: Verify META-INF/BenchmarkList was generated**

Run: `unzip -l benchmarks/spike/build/jars/spike-0.1.0.jar | grep -E 'BenchmarkList|HelloBenchmark'`

Expected output includes:
- `META-INF/BenchmarkList`
- `org/lattejava/jwt/benchmarks/spike/HelloBenchmark.class`
- A synthetic `HelloBenchmark_addOneAndOne_jmhTest.class` (or similar; JMH names vary slightly by version)

If `META-INF/BenchmarkList` is missing, the annotation processor was not run. Apply fallback 1 from the spec (§ "Build risk"): add `java.settings.compilerArguments = "-processor org.openjdk.jmh.generators.BenchmarkProcessor"` to the spike's `build` target and rebuild. If still missing, escalate to fallback 2 or 3 and update the spec.

- [ ] **Step 5: Verify JMH lists the benchmark at runtime**

Run: `java -cp benchmarks/spike/build/jars/spike-0.1.0.jar:$(latte print-dependency-tree --format=classpath 2>/dev/null || echo '') org.openjdk.jmh.Main -l`

(If the classpath helper above doesn't work, use `find ~/.latte -name 'jmh-core-*.jar' -o -name 'jmh-generator-annprocess-*.jar'` to assemble the classpath manually. Latte's local cache typically lives under `~/.latte/cache/` or similar; check `latte print-dependency-tree` output.)

Expected: `org.lattejava.jwt.benchmarks.spike.HelloBenchmark.addOneAndOne` appears in the listing.

- [ ] **Step 6: Run the spike for ~5 seconds to confirm it executes**

Run: `java -cp <built classpath> org.openjdk.jmh.Main -wi 0 -i 1 -r 5s -f 0 HelloBenchmark`

Expected: JMH prints results without error. (`-f 0` disables forking — keeps the spike fast.)

- [ ] **Step 7: Document outcome and commit**

If the spike worked unmodified, write a short note in `specs/benchmark-framework.md` § "Build risk" recording that the auto-discovery path works on this Latte version. If a fallback was needed, document which fallback and why.

```bash
git add benchmarks/spike specs/benchmark-framework.md
git commit -m "spike: prove Latte + JMH annotation processing"
```

The `benchmarks/spike/` directory stays in the repo as a quick-reference template; it is removed in the final task once all per-library projects exist and the harness pattern is established.

---

## Task 1: Initialize benchmarks/ directory + library version table

**Files:**
- Create: `benchmarks/README.md` (placeholder; expanded in Task 27)
- Create: `benchmarks/.gitignore`
- Create: `benchmarks/library-versions.md` (working notes, not user-facing)

- [ ] **Step 1: Create benchmarks/.gitignore**

```
# Build outputs
*/build/

# Result files — keep only the most recent committed snapshot
results/*.json
!results/latest.json
```

- [ ] **Step 2: Create a placeholder benchmarks/README.md**

```markdown
# Benchmarks

JMH-based benchmark suite comparing `latte-jwt` against seven other Java JWT libraries.

Full details, methodology, and operator guidance arrive in a later task. See [`specs/benchmark-framework.md`](../specs/benchmark-framework.md) for the design.
```

- [ ] **Step 3: Look up the latest stable release of each library**

For each artifact below, check Maven Central (https://central.sonatype.com/) for the latest stable version as of today. Use the **latest non-RC, non-beta release**.

Record the resolved versions in `benchmarks/library-versions.md`:

```markdown
# Library versions

Pinned at adapter-authoring time. Bump manually via the per-library `project.latte`.

| Library         | Group : Artifact                    | Version |
|-----------------|-------------------------------------|---------|
| JMH             | org.openjdk.jmh:jmh-core            | 1.37    |
| JMH (annproc)   | org.openjdk.jmh:jmh-generator-annprocess | 1.37    |
| auth0/java-jwt  | com.auth0:java-jwt                  | <fill>  |
| jose4j          | org.bitbucket.b_c:jose4j            | <fill>  |
| nimbus-jose-jwt | com.nimbusds:nimbus-jose-jwt        | <fill>  |
| jjwt-api        | io.jsonwebtoken:jjwt-api            | <fill>  |
| jjwt-impl       | io.jsonwebtoken:jjwt-impl           | <fill>  |
| jjwt-jackson    | io.jsonwebtoken:jjwt-jackson        | <fill>  |
| fusionauth-jwt  | io.fusionauth:fusionauth-jwt        | <fill>  |
| vertx-auth-jwt  | io.vertx:vertx-auth-jwt             | <fill>  |
| inverno-jose    | io.inverno.mod:inverno-security-jose | <fill> |
```

Replace each `<fill>` with the actual current version. JMH 1.37 is the current stable release; pin it.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/.gitignore benchmarks/README.md benchmarks/library-versions.md
git commit -m "feat(benchmarks): scaffold benchmarks/ + library version table"
```

---

## Task 2: Generate fixtures (keys + canonical claims)

**Files:**
- Create: `benchmarks/fixtures/README.md`
- Create: `benchmarks/fixtures/hmac-256.key`
- Create: `benchmarks/fixtures/rsa-2048-private.pem`
- Create: `benchmarks/fixtures/rsa-2048-public.pem`
- Create: `benchmarks/fixtures/ec-p256-private.pem`
- Create: `benchmarks/fixtures/ec-p256-public.pem`
- Create: `benchmarks/fixtures/claims.json`

- [ ] **Step 1: Generate the HMAC key**

Run: `head -c 32 /dev/urandom > benchmarks/fixtures/hmac-256.key`

Verify: `wc -c benchmarks/fixtures/hmac-256.key` shows 32.

- [ ] **Step 2: Generate the RSA-2048 key pair**

Run:
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out benchmarks/fixtures/rsa-2048-private.pem
openssl rsa -in benchmarks/fixtures/rsa-2048-private.pem -pubout -out benchmarks/fixtures/rsa-2048-public.pem
```

Verify: both files start with `-----BEGIN`. Private starts with `-----BEGIN PRIVATE KEY-----` (PKCS#8). Public starts with `-----BEGIN PUBLIC KEY-----` (SPKI).

- [ ] **Step 3: Generate the EC-P256 key pair**

Run:
```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out benchmarks/fixtures/ec-p256-private.pem
openssl ec -in benchmarks/fixtures/ec-p256-private.pem -pubout -out benchmarks/fixtures/ec-p256-public.pem
```

Verify the same headers as Step 2.

- [ ] **Step 4: Write the canonical claims payload**

Create `benchmarks/fixtures/claims.json` exactly as specified in `specs/benchmark-framework.md` § "Canonical claims payload":

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

- [ ] **Step 5: Write the fixtures README**

Create `benchmarks/fixtures/README.md`:

```markdown
# Fixtures — DO NOT USE IN PRODUCTION

These keys are test fixtures used to make benchmark inputs reproducible. They are not, and have never been, used to sign anything outside this benchmark suite. Do not use them in production. Do not paste their public keys into JWKS endpoints.

## Files

- `hmac-256.key` — 32 random bytes (raw) for HS256.
- `rsa-2048-private.pem`, `rsa-2048-public.pem` — RSA-2048 key pair (PKCS#8 / SPKI).
- `ec-p256-private.pem`, `ec-p256-public.pem` — EC P-256 key pair (PKCS#8 / SPKI).
- `claims.json` — canonical 10-claim payload (~270 bytes serialized). `iat` is a fixed historical timestamp; `exp` is `iat + 1 hour`.

## Time handling at decode

The `decode_verify_validate` benchmarks override the decoder's notion of "now" to 30 minutes after `iat` to guarantee `nbf` passes and `exp` doesn't throw, on every run, regardless of wall-clock time. For libraries whose decoder API doesn't allow externally-fixed time, the adapter regenerates the token in `prepare()` with `iat = now()` and `exp = now() + 1h`.
```

- [ ] **Step 6: Commit**

```bash
git add benchmarks/fixtures
git commit -m "feat(benchmarks): add canonical fixtures (keys + claims)"
```

---

## Task 3: Harness module — project.latte + core types

**Files:**
- Create: `benchmarks/harness/project.latte`
- Create: `benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/BenchmarkAlgorithm.java`
- Create: `benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/JwtBenchmarkAdapter.java`

- [ ] **Step 1: Create the harness project.latte**

```groovy
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
jmhVersion = "1.37"

project(group: "org.lattejava.jwt.benchmarks", name: "harness", version: "0.1.0", licenses: ["MIT"]) {
  workflow {
    standard()
  }

  dependencies {
    group(name: "compile") {
      dependency(id: "org.openjdk.jmh:jmh-core:${jmhVersion}")
      dependency(id: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}")
    }
  }

  publications {
    standard()
  }
}

dependency = loadPlugin(id: "org.lattejava.plugin:dependency:0.1.5")
java = loadPlugin(id: "org.lattejava.plugin:java:0.1.7")
idea = loadPlugin(id: "org.lattejava.plugin:idea:0.1.5")

java.settings.javaVersion = "21"

target(name: "clean") { java.clean() }
target(name: "build") { java.compileMain(); java.jar() }
target(name: "int", dependsOn: ["build"]) { dependency.integrate() }
```

- [ ] **Step 2: Create the BenchmarkAlgorithm enum**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

/**
 * Benchmark-axis algorithm. Named to avoid clashing with `org.lattejava.jwt.Algorithm`
 * inside the latte-jwt adapter — that adapter imports both types.
 */
public enum BenchmarkAlgorithm {
  HS256,
  RS256,
  ES256
}
```

- [ ] **Step 3: Create the JwtBenchmarkAdapter interface**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

/**
 * Per-library contract for the benchmark harness. Implementations are stateless after
 * construction; all keys, signers, verifiers, and pre-encoded tokens are stashed during
 * {@link #prepare(Fixtures)} which the harness calls once per JMH trial.
 *
 * Adapters that cannot implement {@link #unsafeDecode(String)} (no public no-verify API)
 * throw {@link UnsupportedOperationException} from that method. The orchestrator's parity
 * check tolerates this; the result merger records N/A.
 */
public interface JwtBenchmarkAdapter {

  /** One-time setup. Called from JMH @Setup(Level.Trial). */
  void prepare(Fixtures fixtures) throws Exception;

  /** Encode the canonical claims payload using {@code alg}. */
  String encode(BenchmarkAlgorithm alg) throws Exception;

  /** Parse, verify signature, validate claims (`exp`/`nbf`/`iss`/`aud`). */
  Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception;

  /**
   * Decode a signed token using the library's public unsafe-decode API — base64 + JSON
   * parse, no signature verification, no claim validation.
   *
   * @throws UnsupportedOperationException if the library exposes no such API
   */
  Object unsafeDecode(String token) throws Exception;
}
```

- [ ] **Step 4: Build the harness to confirm it compiles**

Run: `cd benchmarks/harness && latte build`

Expected: compile succeeds, JAR is produced.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/harness
git commit -m "feat(benchmarks/harness): adapter contract + algorithm enum"
```

---

## Task 4: Harness — Fixtures loader

**Files:**
- Create: `benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/Fixtures.java`

- [ ] **Step 1: Write the Fixtures loader**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Fixture material shared across all adapters. Construct via {@link #load(Path)} pointing
 * at the {@code benchmarks/fixtures/} directory; instances are immutable and thread-safe.
 *
 * The canonical claims JSON is exposed as both raw bytes and a UTF-8 string — adapters
 * choose whichever shape their JSON layer prefers.
 */
public final class Fixtures {
  public final byte[] hmacKey;
  public final PrivateKey rsaPrivate;
  public final PublicKey rsaPublic;
  public final PrivateKey ecPrivate;
  public final PublicKey ecPublic;
  public final byte[] claimsJsonBytes;
  public final String claimsJson;

  private Fixtures(byte[] hmacKey, PrivateKey rsaPrivate, PublicKey rsaPublic,
                   PrivateKey ecPrivate, PublicKey ecPublic, byte[] claimsJsonBytes) {
    this.hmacKey = hmacKey;
    this.rsaPrivate = rsaPrivate;
    this.rsaPublic = rsaPublic;
    this.ecPrivate = ecPrivate;
    this.ecPublic = ecPublic;
    this.claimsJsonBytes = claimsJsonBytes;
    this.claimsJson = new String(claimsJsonBytes, StandardCharsets.UTF_8);
  }

  public static Fixtures load(Path fixturesDir) throws Exception {
    byte[] hmacKey = Files.readAllBytes(fixturesDir.resolve("hmac-256.key"));
    PrivateKey rsaPriv = readPrivateKey(fixturesDir.resolve("rsa-2048-private.pem"), "RSA");
    PublicKey  rsaPub  = readPublicKey (fixturesDir.resolve("rsa-2048-public.pem"),  "RSA");
    PrivateKey ecPriv  = readPrivateKey(fixturesDir.resolve("ec-p256-private.pem"),  "EC");
    PublicKey  ecPub   = readPublicKey (fixturesDir.resolve("ec-p256-public.pem"),   "EC");
    byte[] claims = Files.readAllBytes(fixturesDir.resolve("claims.json"));
    return new Fixtures(hmacKey, rsaPriv, rsaPub, ecPriv, ecPub, claims);
  }

  /**
   * Resolve the fixtures directory from the {@code BENCHMARK_FIXTURES} environment variable,
   * falling back to {@code ./benchmarks/fixtures} relative to the current working directory.
   * The orchestrator sets the env var to an absolute path.
   */
  public static Fixtures loadDefault() throws Exception {
    String envPath = System.getenv("BENCHMARK_FIXTURES");
    Path dir = envPath != null ? Path.of(envPath) : Path.of("benchmarks", "fixtures");
    return load(dir);
  }

  private static PrivateKey readPrivateKey(Path path, String algorithm) throws Exception {
    byte[] der = pemToDer(Files.readString(path));
    return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
  }

  private static PublicKey readPublicKey(Path path, String algorithm) throws Exception {
    byte[] der = pemToDer(Files.readString(path));
    return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
  }

  private static byte[] pemToDer(String pem) throws IOException {
    String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                     .replaceAll("-----END [^-]+-----", "")
                     .replaceAll("\\s+", "");
    return Base64.getDecoder().decode(body);
  }
}
```

- [ ] **Step 2: Build to confirm**

Run: `cd benchmarks/harness && latte build`

Expected: compile succeeds.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/Fixtures.java
git commit -m "feat(benchmarks/harness): Fixtures loader (PEM/JSON)"
```

---

## Task 5: Harness — AbstractJwtBenchmark JMH class

**Files:**
- Create: `benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/AbstractJwtBenchmark.java`

- [ ] **Step 1: Write the abstract benchmark**

```java
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
    return adapter.decodeVerifyValidate(BenchmarkAlgorithm.ES256, hs256Token);
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public Object unsafe_decode() throws Exception {
    return adapter.unsafeDecode(hs256Token);
  }
}
```

- [ ] **Step 2: Build harness**

Run: `cd benchmarks/harness && latte build`

Expected: compile succeeds. (No `@Benchmark` methods are processed yet — the abstract class is library-agnostic; JMH's annotation processor only triggers when a concrete subclass exists in a compilation unit.)

- [ ] **Step 3: Commit**

```bash
git add benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/AbstractJwtBenchmark.java
git commit -m "feat(benchmarks/harness): AbstractJwtBenchmark JMH surface"
```

---

## Task 6: Harness — Parity checker + Main entrypoint pattern

**Files:**
- Create: `benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/ParityChecker.java`
- Create: `benchmarks/harness/src/main/java/org/lattejava/jwt/benchmarks/harness/BenchmarkRunner.java`

- [ ] **Step 1: Write ParityChecker**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

/**
 * Pre-flight smoke test invoked by each per-library Main when launched with --parity-check.
 *
 * For each algorithm, the adapter encodes the canonical claims, decodes its own output, and
 * the round-tripped result is asserted non-null (libraries return wildly different decoded
 * shapes — DecodedJWT, Jws, JwtClaims, etc. — so we verify the call succeeds rather than
 * structurally inspect). For unsafe_decode, the same call is made; UnsupportedOperationException
 * is treated as N/A and not a failure.
 *
 * Exit code 0 = all checks pass (or N/A where applicable).
 * Exit code 1 = any non-N/A check failed.
 */
public final class ParityChecker {

  public static int run(JwtBenchmarkAdapter adapter, Fixtures fixtures, String libraryName) {
    int failures = 0;
    try {
      adapter.prepare(fixtures);
    } catch (Exception e) {
      System.err.println("[" + libraryName + "] prepare() failed: " + e);
      e.printStackTrace(System.err);
      return 1;
    }

    for (BenchmarkAlgorithm alg : BenchmarkAlgorithm.values()) {
      try {
        String token = adapter.encode(alg);
        if (token == null || token.isEmpty()) {
          System.err.println("[" + libraryName + "] " + alg + " encode produced null/empty");
          failures++;
          continue;
        }
        Object decoded = adapter.decodeVerifyValidate(alg, token);
        if (decoded == null) {
          System.err.println("[" + libraryName + "] " + alg + " decode returned null");
          failures++;
        } else {
          System.out.println("[" + libraryName + "] " + alg + " parity OK");
        }
      } catch (Exception e) {
        System.err.println("[" + libraryName + "] " + alg + " parity FAILED: " + e);
        e.printStackTrace(System.err);
        failures++;
      }
    }

    // unsafe_decode (HS256 token) — UnsupportedOperationException is N/A, not a failure
    try {
      String token = adapter.encode(BenchmarkAlgorithm.HS256);
      Object decoded = adapter.unsafeDecode(token);
      if (decoded == null) {
        System.err.println("[" + libraryName + "] unsafe_decode returned null");
        failures++;
      } else {
        System.out.println("[" + libraryName + "] unsafe_decode parity OK");
      }
    } catch (UnsupportedOperationException e) {
      System.out.println("[" + libraryName + "] unsafe_decode N/A (no public unsafe-decode API)");
    } catch (Exception e) {
      System.err.println("[" + libraryName + "] unsafe_decode parity FAILED: " + e);
      e.printStackTrace(System.err);
      failures++;
    }

    return failures == 0 ? 0 : 1;
  }

  private ParityChecker() {}
}
```

- [ ] **Step 2: Write BenchmarkRunner — the shared Main pattern**

```java
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

  /** Holds the args from main(String[]). Set by the per-library Main before calling run(). */
  public static final ThreadLocal<String[]> ARGS = ThreadLocal.withInitial(() -> new String[0]);

  private BenchmarkRunner() {}
}
```

- [ ] **Step 3: Build harness**

Run: `cd benchmarks/harness && latte build`

Expected: compile succeeds.

- [ ] **Step 4: Publish harness locally**

Run: `cd benchmarks/harness && latte int`

Expected: harness JAR is published to the local Latte integration repo. This makes it discoverable as `org.lattejava.jwt.benchmarks:harness:0.1.0` for per-library projects.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/harness
git commit -m "feat(benchmarks/harness): ParityChecker + BenchmarkRunner"
```

---

## Task 7: Baseline adapter (hand-rolled JCA, no external deps)

**Why this first among the adapters:** zero external library dependencies — proves the harness + Latte multi-module wiring works without any third-party noise. The baseline is also the "theoretical floor" the spec exposes in `BENCHMARKS.md`.

**Files:**
- Create: `benchmarks/baseline/project.latte`
- Create: `benchmarks/baseline/src/main/java/org/lattejava/jwt/benchmarks/baseline/BaselineAdapter.java`
- Create: `benchmarks/baseline/src/main/java/org/lattejava/jwt/benchmarks/baseline/BaselineBenchmark.java`
- Create: `benchmarks/baseline/src/main/java/org/lattejava/jwt/benchmarks/baseline/Main.java`

- [ ] **Step 1: Create benchmarks/baseline/project.latte**

```groovy
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
jmhVersion = "1.37"

project(group: "org.lattejava.jwt.benchmarks", name: "baseline", version: "0.1.0", licenses: ["MIT"]) {
  workflow { standard() }

  dependencies {
    group(name: "compile") {
      dependency(id: "org.lattejava.jwt.benchmarks:harness:0.1.0")
      dependency(id: "org.openjdk.jmh:jmh-core:${jmhVersion}")
      dependency(id: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}")
    }
  }

  publications { standard() }
}

dependency = loadPlugin(id: "org.lattejava.plugin:dependency:0.1.5")
java       = loadPlugin(id: "org.lattejava.plugin:java:0.1.7")
idea       = loadPlugin(id: "org.lattejava.plugin:idea:0.1.5")

java.settings.javaVersion = "21"

target(name: "clean") { java.clean() }
target(name: "build") { java.compileMain(); java.jar() }
```

- [ ] **Step 2: Implement BaselineAdapter using JCA + handwritten base64/JSON**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.baseline;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

/**
 * Theoretical-floor reference: the minimum honest JWT path on top of plain JCA.
 * Uses precomputed header bytes per algorithm and hand-rolls base64url + a
 * one-shot sign call. No external dependencies.
 *
 * Validation is simplified: presence-only checks on iss/aud, numeric exp/nbf
 * windowing against a fixed "now" — enough to be honest, not enough to be a
 * real library.
 */
public final class BaselineAdapter implements JwtBenchmarkAdapter {

  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64D = Base64.getUrlDecoder();

  // Pre-built header.payload pairs keyed by algorithm.
  private byte[] hs256HeaderPayload;
  private byte[] rs256HeaderPayload;
  private byte[] es256HeaderPayload;

  private byte[] hmacKey;
  private java.security.PrivateKey rsaPrivate;
  private java.security.PublicKey  rsaPublic;
  private java.security.PrivateKey ecPrivate;
  private java.security.PublicKey  ecPublic;
  private byte[] claimsJson;
  // Fixed "now" = iat + 30 minutes, in epoch seconds.
  private long fixedNowEpochSeconds;

  @Override
  public void prepare(Fixtures fixtures) {
    this.hmacKey = fixtures.hmacKey;
    this.rsaPrivate = fixtures.rsaPrivate;
    this.rsaPublic  = fixtures.rsaPublic;
    this.ecPrivate  = fixtures.ecPrivate;
    this.ecPublic   = fixtures.ecPublic;
    this.claimsJson = fixtures.claimsJsonBytes;
    this.fixedNowEpochSeconds = 1761408000L + 1800L;

    this.hs256HeaderPayload = headerPayload("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    this.rs256HeaderPayload = headerPayload("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
    this.es256HeaderPayload = headerPayload("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
  }

  private byte[] headerPayload(String headerJson) {
    String header = B64.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
    String payload = B64.encodeToString(claimsJson);
    return (header + "." + payload).getBytes(StandardCharsets.US_ASCII);
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) throws Exception {
    return switch (alg) {
      case HS256 -> encodeHmac();
      case RS256 -> encodeAsymmetric(rs256HeaderPayload, "SHA256withRSA", rsaPrivate, false);
      case ES256 -> encodeAsymmetric(es256HeaderPayload, "SHA256withECDSA", ecPrivate, true);
    };
  }

  private String encodeHmac() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
    byte[] sig = mac.doFinal(hs256HeaderPayload);
    return new String(hs256HeaderPayload, StandardCharsets.US_ASCII) + "." + B64.encodeToString(sig);
  }

  private String encodeAsymmetric(byte[] headerPayload, String jcaAlg,
                                  java.security.PrivateKey key, boolean derToJose) throws Exception {
    Signature sig = Signature.getInstance(jcaAlg);
    sig.initSign(key);
    sig.update(headerPayload);
    byte[] raw = sig.sign();
    byte[] out = derToJose ? EcdsaSigConverter.derToJose(raw, 32) : raw;
    return new String(headerPayload, StandardCharsets.US_ASCII) + "." + B64.encodeToString(out);
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    int firstDot = token.indexOf('.');
    int secondDot = token.indexOf('.', firstDot + 1);
    if (firstDot < 0 || secondDot < 0) throw new IllegalArgumentException("malformed");
    String headerPayload = token.substring(0, secondDot);
    byte[] signature = B64D.decode(token.substring(secondDot + 1));
    byte[] payload = B64D.decode(token.substring(firstDot + 1, secondDot));

    switch (alg) {
      case HS256 -> {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        byte[] expected = mac.doFinal(headerPayload.getBytes(StandardCharsets.US_ASCII));
        if (!java.security.MessageDigest.isEqual(expected, signature)) {
          throw new SecurityException("HMAC mismatch");
        }
      }
      case RS256 -> {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(rsaPublic);
        sig.update(headerPayload.getBytes(StandardCharsets.US_ASCII));
        if (!sig.verify(signature)) throw new SecurityException("RSA verify failed");
      }
      case ES256 -> {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(ecPublic);
        sig.update(headerPayload.getBytes(StandardCharsets.US_ASCII));
        byte[] der = EcdsaSigConverter.joseToDer(signature, 32);
        if (!sig.verify(der)) throw new SecurityException("ECDSA verify failed");
      }
    }
    validate(payload);
    return payload;
  }

  private void validate(byte[] payload) {
    String body = new String(payload, StandardCharsets.UTF_8);
    long exp = readEpochSeconds(body, "\"exp\":");
    long nbf = readEpochSeconds(body, "\"nbf\":");
    if (fixedNowEpochSeconds < nbf) throw new IllegalStateException("nbf in future");
    if (fixedNowEpochSeconds >= exp) throw new IllegalStateException("expired");
    if (!body.contains("\"iss\":\"https://benchmarks.lattejava.org\"")) throw new IllegalStateException("iss");
    if (!body.contains("\"aud\":\"benchmark-audience\"")) throw new IllegalStateException("aud");
  }

  private static long readEpochSeconds(String body, String fieldKey) {
    int idx = body.indexOf(fieldKey);
    if (idx < 0) throw new IllegalStateException("missing " + fieldKey);
    int start = idx + fieldKey.length();
    int end = start;
    while (end < body.length() && Character.isDigit(body.charAt(end))) end++;
    return Long.parseLong(body, start, end, 10);
  }

  @Override
  public Object unsafeDecode(String token) {
    int firstDot = token.indexOf('.');
    int secondDot = token.indexOf('.', firstDot + 1);
    return B64D.decode(token.substring(firstDot + 1, secondDot));
  }
}
```

- [ ] **Step 3: Add EcdsaSigConverter helper**

Create `benchmarks/baseline/src/main/java/org/lattejava/jwt/benchmarks/baseline/EcdsaSigConverter.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.baseline;

/**
 * Convert ECDSA signatures between DER (JCA's native format) and JOSE concat-r-s
 * (JWS's required format per RFC 7518). For P-256, each component is 32 bytes.
 */
final class EcdsaSigConverter {
  static byte[] derToJose(byte[] der, int componentLen) {
    int rOff = 4;
    int rLen = der[3] & 0xff;
    if (der[rOff] == 0x00) { rOff++; rLen--; }
    int sOff = 4 + (der[3] & 0xff) + 2;
    int sLen = der[sOff - 1] & 0xff;
    if (der[sOff] == 0x00) { sOff++; sLen--; }

    byte[] out = new byte[componentLen * 2];
    System.arraycopy(der, rOff, out, componentLen - rLen, rLen);
    System.arraycopy(der, sOff, out, componentLen + componentLen - sLen, sLen);
    return out;
  }

  static byte[] joseToDer(byte[] jose, int componentLen) {
    byte[] r = trimLeadingZeros(jose, 0, componentLen);
    byte[] s = trimLeadingZeros(jose, componentLen, componentLen);
    int rPad = (r[0] & 0x80) != 0 ? 1 : 0;
    int sPad = (s[0] & 0x80) != 0 ? 1 : 0;
    int totalLen = 2 + r.length + rPad + 2 + s.length + sPad;
    byte[] out = new byte[2 + totalLen];
    int p = 0;
    out[p++] = 0x30;
    out[p++] = (byte) totalLen;
    out[p++] = 0x02;
    out[p++] = (byte) (r.length + rPad);
    if (rPad == 1) out[p++] = 0x00;
    System.arraycopy(r, 0, out, p, r.length); p += r.length;
    out[p++] = 0x02;
    out[p++] = (byte) (s.length + sPad);
    if (sPad == 1) out[p++] = 0x00;
    System.arraycopy(s, 0, out, p, s.length);
    return out;
  }

  private static byte[] trimLeadingZeros(byte[] src, int off, int len) {
    int start = off;
    int end = off + len;
    while (start < end - 1 && src[start] == 0) start++;
    byte[] out = new byte[end - start];
    System.arraycopy(src, start, out, 0, out.length);
    return out;
  }

  private EcdsaSigConverter() {}
}
```

- [ ] **Step 4: Implement BaselineBenchmark subclass**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.baseline;

import org.lattejava.jwt.benchmarks.harness.AbstractJwtBenchmark;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public class BaselineBenchmark extends AbstractJwtBenchmark {
  @Override
  protected JwtBenchmarkAdapter createAdapter() {
    return new BaselineAdapter();
  }
}
```

- [ ] **Step 5: Implement Main**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.baseline;

import org.lattejava.jwt.benchmarks.harness.BenchmarkRunner;

public final class Main {
  public static void main(String[] args) throws Exception {
    BenchmarkRunner.ARGS.set(args);
    BenchmarkRunner.run("baseline", BaselineBenchmark.class, new BaselineAdapter());
  }
}
```

- [ ] **Step 6: Build baseline**

Run: `cd benchmarks/baseline && latte build`

Expected: compile succeeds, JAR produced. Confirm `META-INF/BenchmarkList` is present (`unzip -l` the JAR).

- [ ] **Step 7: Run parity check**

Run from repo root:
```bash
BENCHMARK_FIXTURES=$(pwd)/benchmarks/fixtures \
  java -jar benchmarks/baseline/build/jars/baseline-0.1.0.jar --parity-check
```

Expected output includes `[baseline] HS256 parity OK`, `RS256 parity OK`, `ES256 parity OK`, `unsafe_decode parity OK`. Exit code 0.

- [ ] **Step 8: Smoke-run JMH for ~10 seconds total**

Run: `BENCHMARK_FIXTURES=$(pwd)/benchmarks/fixtures java -jar benchmarks/baseline/build/jars/baseline-0.1.0.jar -wi 0 -i 1 -r 2s -f 0`

Expected: JMH executes all seven `@Benchmark` methods and prints results without error.

- [ ] **Step 9: Commit**

```bash
git add benchmarks/baseline
git commit -m "feat(benchmarks/baseline): JCA-only theoretical-floor adapter"
```

---

## Task 8: latte-jwt adapter

**Files:**
- Create: `benchmarks/latte-jwt/project.latte`
- Create: `benchmarks/latte-jwt/src/main/java/org/lattejava/jwt/benchmarks/lattejwt/LatteJwtAdapter.java`
- Create: `benchmarks/latte-jwt/src/main/java/org/lattejava/jwt/benchmarks/lattejwt/LatteJwtBenchmark.java`
- Create: `benchmarks/latte-jwt/src/main/java/org/lattejava/jwt/benchmarks/lattejwt/Main.java`

- [ ] **Step 1: Make sure latte-jwt is published locally**

Run from repo root: `latte int`

Expected: latte-jwt JAR is published as `org.lattejava:jwt:0.1.0`.

- [ ] **Step 2: Create benchmarks/latte-jwt/project.latte**

```groovy
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
jmhVersion = "1.37"

project(group: "org.lattejava.jwt.benchmarks", name: "latte-jwt-bench", version: "0.1.0", licenses: ["MIT"]) {
  workflow { standard() }

  dependencies {
    group(name: "compile") {
      dependency(id: "org.lattejava.jwt.benchmarks:harness:0.1.0")
      dependency(id: "org.lattejava:jwt:0.1.0")
      dependency(id: "org.openjdk.jmh:jmh-core:${jmhVersion}")
      dependency(id: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}")
    }
  }

  publications { standard() }
}

dependency = loadPlugin(id: "org.lattejava.plugin:dependency:0.1.5")
java       = loadPlugin(id: "org.lattejava.plugin:java:0.1.7")
idea       = loadPlugin(id: "org.lattejava.plugin:idea:0.1.5")

java.settings.javaVersion = "21"

target(name: "clean") { java.clean() }
target(name: "build") { java.compileMain(); java.jar() }
```

- [ ] **Step 3: Implement LatteJwtAdapter**

Read `specs/7.0-architecture.md` (referenced from CLAUDE.md) and the latte-jwt source in `src/main/java/org/lattejava/jwt/` to confirm the actual API names — the snippet below is the expected shape, but verify each `Signers.forHMAC` / `Verifiers.byKid` / `JWTEncoder.encode` call against the current code before coding. If any name has drifted, prefer the latte-jwt source over this snippet.

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.lattejwt;

import java.time.Instant;
import java.util.Map;
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.Signers;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.Verifiers;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class LatteJwtAdapter implements JwtBenchmarkAdapter {

  private Signer hs256Signer, rs256Signer, es256Signer;
  private Verifier hs256Verifier, rs256Verifier, es256Verifier;
  private JWTEncoder encoder;
  private JWTDecoder hs256Decoder, rs256Decoder, es256Decoder;
  private JWT canonicalJwt;

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    hs256Signer  = Signers.forHMAC(Algorithm.of("HS256"), fixtures.hmacKey);
    rs256Signer  = Signers.forAsymmetric(Algorithm.of("RS256"), fixtures.rsaPrivate);
    es256Signer  = Signers.forAsymmetric(Algorithm.of("ES256"), fixtures.ecPrivate);

    hs256Verifier = Verifiers.forHMAC(Algorithm.of("HS256"), fixtures.hmacKey);
    rs256Verifier = Verifiers.forAsymmetric(Algorithm.of("RS256"), fixtures.rsaPublic);
    es256Verifier = Verifiers.forAsymmetric(Algorithm.of("ES256"), fixtures.ecPublic);

    encoder = new JWTEncoder();
    Instant fixedNow = Instant.ofEpochSecond(1761408000L + 1800L);
    hs256Decoder = JWTDecoder.builder().fixedTime(fixedNow).build();
    rs256Decoder = JWTDecoder.builder().fixedTime(fixedNow).build();
    es256Decoder = JWTDecoder.builder().fixedTime(fixedNow).build();

    canonicalJwt = JWT.builder()
        .issuer("https://benchmarks.lattejava.org")
        .subject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .audience("benchmark-audience")
        .issuedAt(Instant.ofEpochSecond(1761408000L))
        .notBefore(Instant.ofEpochSecond(1761408000L))
        .expiration(Instant.ofEpochSecond(1761411600L))
        .id("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .otherClaims(Map.of(
            "scope", "openid profile email",
            "email", "test@example.com",
            "email_verified", Boolean.TRUE))
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    return switch (alg) {
      case HS256 -> encoder.encode(canonicalJwt, hs256Signer);
      case RS256 -> encoder.encode(canonicalJwt, rs256Signer);
      case ES256 -> encoder.encode(canonicalJwt, es256Signer);
    };
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    return switch (alg) {
      case HS256 -> hs256Decoder.decode(token, VerifierResolver.of(hs256Verifier));
      case RS256 -> rs256Decoder.decode(token, VerifierResolver.of(rs256Verifier));
      case ES256 -> es256Decoder.decode(token, VerifierResolver.of(es256Verifier));
    };
  }

  @Override
  public Object unsafeDecode(String token) {
    // latte-jwt exposes a no-verify decode for inspecting kid/iss before key selection.
    // Use whichever public method exists in the current source — likely something like
    // JWTDecoder.parseUnsafe(token) or JWT.parseClaimsOnly(token). Verify in code.
    return JWTDecoder.parseUnsafe(token);
  }
}
```

If `JWT.builder()` or `JWTDecoder.parseUnsafe` doesn't match the actual API, find the closest equivalent in the current source and update accordingly. The contract is `prepare → encode → decodeVerifyValidate → unsafeDecode`; the exact internal calls are implementation detail.

- [ ] **Step 4: LatteJwtBenchmark subclass**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.lattejwt;

import org.lattejava.jwt.benchmarks.harness.AbstractJwtBenchmark;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public class LatteJwtBenchmark extends AbstractJwtBenchmark {
  @Override
  protected JwtBenchmarkAdapter createAdapter() {
    return new LatteJwtAdapter();
  }
}
```

- [ ] **Step 5: Main**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.lattejwt;

import org.lattejava.jwt.benchmarks.harness.BenchmarkRunner;

public final class Main {
  public static void main(String[] args) throws Exception {
    BenchmarkRunner.ARGS.set(args);
    BenchmarkRunner.run("latte-jwt", LatteJwtBenchmark.class, new LatteJwtAdapter());
  }
}
```

- [ ] **Step 6: Build, parity-check, smoke-run**

Run:
```bash
cd benchmarks/latte-jwt && latte build
cd ../..
BENCHMARK_FIXTURES=$(pwd)/benchmarks/fixtures \
  java -jar benchmarks/latte-jwt/build/jars/latte-jwt-bench-0.1.0.jar --parity-check
BENCHMARK_FIXTURES=$(pwd)/benchmarks/fixtures \
  java -jar benchmarks/latte-jwt/build/jars/latte-jwt-bench-0.1.0.jar -wi 0 -i 1 -r 2s -f 0
```

Expected: parity check passes 4 lines `parity OK`. Smoke run completes all seven benchmarks without error.

- [ ] **Step 7: Commit**

```bash
git add benchmarks/latte-jwt
git commit -m "feat(benchmarks/latte-jwt): adapter + benchmark + main"
```

---

## Task 9: benchmarks.yaml runner config

**Files:**
- Create: `benchmarks/benchmarks.yaml`

- [ ] **Step 1: Write the YAML exactly per the spec**

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

algorithms: [HS256, RS256, ES256]
operations: [encode, decodeVerifyValidate, unsafeDecode]

jmh:
  warmup-iterations:      2
  warmup-time:            5s
  measurement-iterations: 3
  measurement-time:       10s
  forks:                  3
  threads:                1
  mode:                   throughput

output:
  json-dir:  results/
  label:     ""
```

- [ ] **Step 2: Commit**

```bash
git add benchmarks/benchmarks.yaml
git commit -m "feat(benchmarks): runner config (benchmarks.yaml)"
```

---

## Task 10: run-benchmarks.sh — sanity check + parity phases

**Files:**
- Create: `benchmarks/run-benchmarks.sh`

- [ ] **Step 1: Write the orchestrator (phase 1 — sanity, build, parity)**

The full orchestrator is large; this task implements the pre-measurement phases. The measurement phase comes in Task 11.

```bash
#!/usr/bin/env bash
# Copyright (c) 2026, The Latte Project. License: MIT.
set -euo pipefail

# ── locate repo + benchmarks dir
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
BENCH_DIR="${SCRIPT_DIR}"
RESULTS_DIR="${BENCH_DIR}/results"
FIXTURES_DIR="${BENCH_DIR}/fixtures"
mkdir -p "${RESULTS_DIR}"

# ── defaults (override via CLI)
LIBRARIES=""
ALGORITHMS=""
OPERATIONS=""
LABEL=""
DURATION=""
QUICK=0
NO_BUILD=0
DO_UPDATE=0

usage() {
  cat <<'EOF'
Usage: run-benchmarks.sh [options]

  --libraries  <list>   Subset of libraries (comma-separated)
  --algorithms <list>   Subset of algorithms (comma-separated)
  --operations <list>   Subset of operations (comma-separated)
  --label      <name>   Appended to results filename
  --duration   <time>   Shortcut: sets warmup-time AND measurement-time (e.g. 5s)
  --quick               Preset: 5s warmup, 10s measurement, 1 fork
  --no-build            Skip latte build, reuse existing JARs
  --update              Run update-benchmarks.sh after the run completes
  -h, --help            This message
EOF
}

# ── arg parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --libraries)  LIBRARIES="$2";  shift 2 ;;
    --algorithms) ALGORITHMS="$2"; shift 2 ;;
    --operations) OPERATIONS="$2"; shift 2 ;;
    --label)      LABEL="$2";      shift 2 ;;
    --duration)   DURATION="$2";   shift 2 ;;
    --quick)      QUICK=1;         shift   ;;
    --no-build)   NO_BUILD=1;      shift   ;;
    --update)     DO_UPDATE=1;     shift   ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# ── load YAML (parse a few keys via grep/sed; full YAML parser would be overkill)
yaml_libraries() { sed -n '/^libraries:/,/^[a-zA-Z]/p' "${BENCH_DIR}/benchmarks.yaml" | sed -n 's/^  - //p'; }
yaml_jmh()       { grep -E "^[[:space:]]+$1:" "${BENCH_DIR}/benchmarks.yaml" | head -1 | awk '{print $2}'; }

DEFAULT_LIBS="$(yaml_libraries | paste -sd ',' -)"
LIBS_TO_RUN="${LIBRARIES:-${DEFAULT_LIBS}}"
WARMUP_ITERS="$(yaml_jmh warmup-iterations)"
WARMUP_TIME="$(yaml_jmh warmup-time)"
MEASURE_ITERS="$(yaml_jmh measurement-iterations)"
MEASURE_TIME="$(yaml_jmh measurement-time)"
FORKS="$(yaml_jmh forks)"
THREADS="$(yaml_jmh threads)"

if (( QUICK == 1 )); then
  WARMUP_TIME="5s"; MEASURE_TIME="10s"; FORKS=1
fi
if [[ -n "${DURATION}" ]]; then
  WARMUP_TIME="${DURATION}"; MEASURE_TIME="${DURATION}"
fi

# ── sanity check
echo "→ sanity check"
command -v latte >/dev/null || { echo "latte not on PATH" >&2; exit 1; }
java -version 2>&1 | head -1 | grep -qE 'version "(2[1-9]|[3-9][0-9])' || {
  echo "Java 21+ required" >&2
  java -version >&2
  exit 1
}
[[ -d "${FIXTURES_DIR}" ]] || { echo "fixtures missing: ${FIXTURES_DIR}" >&2; exit 1; }
[[ -f "${FIXTURES_DIR}/claims.json" ]] || { echo "fixtures incomplete (no claims.json)" >&2; exit 1; }
IFS=',' read -ra LIBS_ARRAY <<< "${LIBS_TO_RUN}"
for lib in "${LIBS_ARRAY[@]}"; do
  [[ -d "${BENCH_DIR}/${lib}" ]] || { echo "library dir missing: ${lib}" >&2; exit 1; }
done
echo "  ok"

# ── build
if (( NO_BUILD == 0 )); then
  echo "→ build"
  for lib in "${LIBS_ARRAY[@]}"; do
    echo "  building ${lib}…"
    ( cd "${BENCH_DIR}/${lib}" && latte build ) >"${RESULTS_DIR}/.${lib}.build.log" 2>&1 || {
      echo "build failed for ${lib} — see ${RESULTS_DIR}/.${lib}.build.log" >&2
      exit 1
    }
  done
fi

# ── parity check
echo "→ parity check"
for lib in "${LIBS_ARRAY[@]}"; do
  jar="$(ls "${BENCH_DIR}/${lib}/build/jars/"*.jar | head -1)"
  echo "  ${lib}…"
  BENCHMARK_FIXTURES="${FIXTURES_DIR}" java -jar "${jar}" --parity-check || {
    echo "parity FAILED for ${lib}" >&2
    exit 1
  }
done
echo "  ok"

# stub: measurement phase implemented in Task 11
echo "(measurement phase not yet implemented — run later tasks)"
```

- [ ] **Step 2: Make executable + run sanity/build/parity against the two adapters built so far**

```bash
chmod +x benchmarks/run-benchmarks.sh
benchmarks/run-benchmarks.sh --libraries baseline,latte-jwt
```

Expected: sanity check passes, builds both libraries, parity check prints `parity OK` for each, then prints the placeholder.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/run-benchmarks.sh
git commit -m "feat(benchmarks): orchestrator phase 1 (sanity/build/parity)"
```

---

## Task 11: run-benchmarks.sh — measurement phase + JSON merge

- [ ] **Step 1: Replace the stub at the bottom of run-benchmarks.sh with the measurement loop**

Replace:
```bash
# stub: measurement phase implemented in Task 11
echo "(measurement phase not yet implemented — run later tasks)"
```

With:
```bash
# ── measurement
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SUFFIX=""
[[ -n "${LABEL}" ]] && SUFFIX="-${LABEL}"
MERGED="${RESULTS_DIR}/${TS}${SUFFIX}.json"
TMP_DIR="$(mktemp -d)"

JMH_ARGS=(
  -wi "${WARMUP_ITERS}" -w "${WARMUP_TIME}"
  -i  "${MEASURE_ITERS}" -r  "${MEASURE_TIME}"
  -f  "${FORKS}" -t  "${THREADS}"
  -rf json
)

declare -a SUCCESS=()
declare -a FAILED=()

echo "→ measurement"
for lib in "${LIBS_ARRAY[@]}"; do
  jar="$(ls "${BENCH_DIR}/${lib}/build/jars/"*.jar | head -1)"
  out="${TMP_DIR}/${lib}.json"
  echo "  ${lib} → ${out}"
  if BENCHMARK_FIXTURES="${FIXTURES_DIR}" java -jar "${jar}" "${JMH_ARGS[@]}" -rff "${out}"; then
    SUCCESS+=("${lib}")
  else
    echo "    ${lib} measurement FAILED — continuing" >&2
    FAILED+=("${lib}")
  fi
done

# ── merge JSON arrays
echo "→ merge"
jq -s 'add' "${TMP_DIR}"/*.json > "${MERGED}"
cp "${MERGED}" "${RESULTS_DIR}/latest.json"

echo
echo "  results: ${MERGED}"
echo "  latest:  ${RESULTS_DIR}/latest.json"
echo "  succeeded: ${SUCCESS[*]:-(none)}"
[[ ${#FAILED[@]} -gt 0 ]] && echo "  failed:    ${FAILED[*]}"

# ── update report
if (( DO_UPDATE == 1 )); then
  "${BENCH_DIR}/update-benchmarks.sh" "${MERGED}"
fi
```

- [ ] **Step 2: Run a `--quick` end-to-end against baseline+latte-jwt**

Run: `benchmarks/run-benchmarks.sh --libraries baseline,latte-jwt --quick`

Expected: sanity → build → parity → measurement (each library runs ~7×30s under --quick) → merge → final summary line. Should produce `benchmarks/results/<timestamp>.json` and `benchmarks/results/latest.json`.

- [ ] **Step 3: Inspect the merged JSON shape**

Run: `jq '. | length' benchmarks/results/latest.json`

Expected: a number of records (7 ops × 1 mode for encode + 7 × 2 modes for decode-verify-validate methods aggregated across both libraries — the exact count depends on JMH's own grouping).

- [ ] **Step 4: Commit**

```bash
git add benchmarks/run-benchmarks.sh
git commit -m "feat(benchmarks): orchestrator phase 2 (measurement + merge)"
```

---

## Task 12: run-benchmarks.sh — run-condition capture sidecar

**Files:**
- Modify: `benchmarks/run-benchmarks.sh`

- [ ] **Step 1: Add capture function near the top of the script (after `usage()`)**

```bash
capture_run_conditions() {
  local out="$1"
  {
    echo '{'
    printf '  "uname": %s,\n' "$(uname -a | jq -Rs .)"
    if [[ "$(uname -s)" == "Darwin" ]]; then
      printf '  "hardware": %s,\n' "$(system_profiler SPHardwareDataType 2>/dev/null | jq -Rs .)"
      printf '  "thermal":  %s,\n' "$(pmset -g therm 2>/dev/null | jq -Rs .)"
    else
      printf '  "hardware": %s,\n' "$(lscpu 2>/dev/null | jq -Rs .)"
      if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        printf '  "cpufreq_governor": %s,\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor | jq -Rs .)"
      fi
    fi
    printf '  "java": %s,\n' "$(java -XshowSettings:properties -version 2>&1 | grep -E '^\s+(java\.version|os\.|sun\.arch|java\.vm)' | jq -Rs .)"
    printf '  "jmh_args": "%s",\n' "${JMH_ARGS[*]}"
    printf '  "captured_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo '}'
  } > "${out}"
}
```

- [ ] **Step 2: Call it after the merge step**

In the merge section, after `cp "${MERGED}" "${RESULTS_DIR}/latest.json"`, add:

```bash
capture_run_conditions "${MERGED%.json}.conditions.json"
cp "${MERGED%.json}.conditions.json" "${RESULTS_DIR}/latest.conditions.json"
```

- [ ] **Step 3: Add `latest.conditions.json` to the gitignore allow-list**

Edit `benchmarks/.gitignore`:

```
# Build outputs
*/build/

# Result files — keep only the most recent committed snapshots
results/*.json
!results/latest.json
!results/latest.conditions.json
```

- [ ] **Step 4: Re-run quick + verify the conditions sidecar exists**

```bash
benchmarks/run-benchmarks.sh --libraries baseline,latte-jwt --quick
jq . benchmarks/results/latest.conditions.json
```

Expected: prints a JSON object with `uname`, `hardware`, `java`, `jmh_args`, `captured_at`.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/run-benchmarks.sh benchmarks/.gitignore
git commit -m "feat(benchmarks): capture run conditions to sidecar JSON"
```

---

## Task 13: auth0-java-jwt adapter

**Files:**
- Create: `benchmarks/auth0-java-jwt/project.latte`
- Create: `benchmarks/auth0-java-jwt/src/main/java/org/lattejava/jwt/benchmarks/auth0/Auth0Adapter.java`
- Create: `benchmarks/auth0-java-jwt/src/main/java/org/lattejava/jwt/benchmarks/auth0/Auth0Benchmark.java`
- Create: `benchmarks/auth0-java-jwt/src/main/java/org/lattejava/jwt/benchmarks/auth0/Main.java`

- [ ] **Step 1: Create project.latte**

Use the version from `benchmarks/library-versions.md` for `auth0VERSION` below.

```groovy
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
jmhVersion = "1.37"
auth0Version = "<from library-versions.md>"

project(group: "org.lattejava.jwt.benchmarks", name: "auth0-java-jwt-bench", version: "0.1.0", licenses: ["MIT"]) {
  workflow { standard() }
  dependencies {
    group(name: "compile") {
      dependency(id: "org.lattejava.jwt.benchmarks:harness:0.1.0")
      dependency(id: "com.auth0:java-jwt:${auth0Version}")
      dependency(id: "org.openjdk.jmh:jmh-core:${jmhVersion}")
      dependency(id: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}")
    }
  }
  publications { standard() }
}

dependency = loadPlugin(id: "org.lattejava.plugin:dependency:0.1.5")
java       = loadPlugin(id: "org.lattejava.plugin:java:0.1.7")
idea       = loadPlugin(id: "org.lattejava.plugin:idea:0.1.5")

java.settings.javaVersion = "21"

target(name: "clean") { java.clean() }
target(name: "build") { java.compileMain(); java.jar() }
```

- [ ] **Step 2: Implement Auth0Adapter**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

/**
 * auth0/java-jwt adapter. The library does not let "now" be set externally on the verifier,
 * so the adapter regenerates iat/exp at prepare() time relative to System.currentTimeMillis,
 * keeping the token stable for the duration of the trial.
 */
public final class Auth0Adapter implements JwtBenchmarkAdapter {

  private Algorithm hs256Alg, rs256Alg, es256Alg;
  private JWTVerifier hs256Verifier, rs256Verifier, es256Verifier;
  private long iatMs, expMs;

  @Override
  public void prepare(Fixtures fixtures) {
    hs256Alg = Algorithm.HMAC256(fixtures.hmacKey);
    rs256Alg = Algorithm.RSA256((RSAPublicKey) fixtures.rsaPublic, (RSAPrivateKey) fixtures.rsaPrivate);
    es256Alg = Algorithm.ECDSA256((ECPublicKey) fixtures.ecPublic, (ECPrivateKey) fixtures.ecPrivate);

    long now = System.currentTimeMillis();
    iatMs = now;
    expMs = now + 3_600_000L;

    hs256Verifier = JWT.require(hs256Alg)
        .withIssuer("https://benchmarks.lattejava.org")
        .withAudience("benchmark-audience")
        .build();
    rs256Verifier = JWT.require(rs256Alg)
        .withIssuer("https://benchmarks.lattejava.org")
        .withAudience("benchmark-audience")
        .build();
    es256Verifier = JWT.require(es256Alg)
        .withIssuer("https://benchmarks.lattejava.org")
        .withAudience("benchmark-audience")
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    Algorithm algo = switch (alg) {
      case HS256 -> hs256Alg;
      case RS256 -> rs256Alg;
      case ES256 -> es256Alg;
    };
    return JWT.create()
        .withIssuer("https://benchmarks.lattejava.org")
        .withSubject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .withAudience("benchmark-audience")
        .withIssuedAt(new Date(iatMs))
        .withNotBefore(new Date(iatMs))
        .withExpiresAt(new Date(expMs))
        .withJWTId("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .withClaim("scope", "openid profile email")
        .withClaim("email", "test@example.com")
        .withClaim("email_verified", true)
        .sign(algo);
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    return switch (alg) {
      case HS256 -> hs256Verifier.verify(token);
      case RS256 -> rs256Verifier.verify(token);
      case ES256 -> es256Verifier.verify(token);
    };
  }

  @Override
  public Object unsafeDecode(String token) {
    // JWT.decode() returns a DecodedJWT without verifying signature.
    DecodedJWT decoded = JWT.decode(token);
    return decoded;
  }
}
```

- [ ] **Step 3: Auth0Benchmark + Main**

Following the latte-jwt pattern: a one-class `Auth0Benchmark extends AbstractJwtBenchmark` returning `new Auth0Adapter()` from `createAdapter()`, and a `Main` that calls `BenchmarkRunner.run("auth0-java-jwt", Auth0Benchmark.class, new Auth0Adapter())`.

- [ ] **Step 4: Build, parity-check, smoke-run**

```bash
cd benchmarks/auth0-java-jwt && latte build
cd ../..
BENCHMARK_FIXTURES=$(pwd)/benchmarks/fixtures \
  java -jar benchmarks/auth0-java-jwt/build/jars/auth0-java-jwt-bench-0.1.0.jar --parity-check
BENCHMARK_FIXTURES=$(pwd)/benchmarks/fixtures \
  java -jar benchmarks/auth0-java-jwt/build/jars/auth0-java-jwt-bench-0.1.0.jar -wi 0 -i 1 -r 2s -f 0
```

Expected: parity passes 4/4 (auth0 has `JWT.decode()` for unsafe path); smoke run succeeds.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/auth0-java-jwt
git commit -m "feat(benchmarks/auth0-java-jwt): adapter"
```

---

## Task 14: jose4j adapter

**Files:**
- Create: `benchmarks/jose4j/project.latte`
- Create: `benchmarks/jose4j/src/main/java/org/lattejava/jwt/benchmarks/jose4j/Jose4jAdapter.java`
- Create: `benchmarks/jose4j/src/main/java/org/lattejava/jwt/benchmarks/jose4j/Jose4jBenchmark.java`
- Create: `benchmarks/jose4j/src/main/java/org/lattejava/jwt/benchmarks/jose4j/Main.java`

- [ ] **Step 1: project.latte (depend on `org.bitbucket.b_c:jose4j:<version>`)**

Same template as Task 13's project.latte; substitute group/artifact and `jose4jVersion` from `library-versions.md`.

- [ ] **Step 2: Implement Jose4jAdapter**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.jose4j;

import javax.crypto.spec.SecretKeySpec;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.HmacKey;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class Jose4jAdapter implements JwtBenchmarkAdapter {

  private HmacKey hmacKey;
  private java.security.PrivateKey rsaPrivate, ecPrivate;
  private java.security.PublicKey  rsaPublic,  ecPublic;
  private JwtClaims claims;
  private JwtConsumer hs256Consumer, rs256Consumer, es256Consumer;
  private JwtConsumer unsafeConsumer;

  @Override
  public void prepare(Fixtures fixtures) {
    hmacKey = new HmacKey(fixtures.hmacKey);
    rsaPrivate = fixtures.rsaPrivate; rsaPublic = fixtures.rsaPublic;
    ecPrivate  = fixtures.ecPrivate;  ecPublic  = fixtures.ecPublic;

    claims = new JwtClaims();
    claims.setIssuer("https://benchmarks.lattejava.org");
    claims.setSubject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f");
    claims.setAudience("benchmark-audience");
    claims.setIssuedAt(NumericDate.fromSeconds(1761408000L));
    claims.setNotBefore(NumericDate.fromSeconds(1761408000L));
    claims.setExpirationTime(NumericDate.fromSeconds(1761411600L));
    claims.setJwtId("01JK6V2N5W3YE4XJ5Y7Z8A9BC0");
    claims.setStringClaim("scope", "openid profile email");
    claims.setStringClaim("email", "test@example.com");
    claims.setClaim("email_verified", Boolean.TRUE);

    NumericDate fixedNow = NumericDate.fromSeconds(1761408000L + 1800L);
    hs256Consumer = newConsumer(hmacKey, fixedNow);
    rs256Consumer = newConsumer(rsaPublic, fixedNow);
    es256Consumer = newConsumer(ecPublic,  fixedNow);
    unsafeConsumer = new JwtConsumerBuilder()
        .setSkipAllValidators()
        .setDisableRequireSignature()
        .setSkipSignatureVerification()
        .build();
  }

  private static JwtConsumer newConsumer(java.security.Key verificationKey, NumericDate fixedNow) {
    return new JwtConsumerBuilder()
        .setVerificationKey(verificationKey)
        .setExpectedIssuer("https://benchmarks.lattejava.org")
        .setExpectedAudience("benchmark-audience")
        .setEvaluationTime(fixedNow)
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) throws Exception {
    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(claims.toJson());
    switch (alg) {
      case HS256 -> { jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256); jws.setKey(new SecretKeySpec(hmacKey.getKey(), "HmacSHA256")); }
      case RS256 -> { jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); jws.setKey(rsaPrivate); }
      case ES256 -> { jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256); jws.setKey(ecPrivate); }
    }
    return jws.getCompactSerialization();
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    return switch (alg) {
      case HS256 -> hs256Consumer.processToClaims(token);
      case RS256 -> rs256Consumer.processToClaims(token);
      case ES256 -> es256Consumer.processToClaims(token);
    };
  }

  @Override
  public Object unsafeDecode(String token) throws Exception {
    JwtContext ctx = unsafeConsumer.process(token);
    return ctx.getJwtClaims();
  }
}
```

- [ ] **Step 3: Jose4jBenchmark + Main**

Same one-class subclass + Main pattern as Task 13.

- [ ] **Step 4: Build + parity + smoke run**

Same commands as Task 13, substituting paths.

Expected: parity 4/4. If `setSkipSignatureVerification()` is rejected (some jose4j versions require explicit per-key acknowledgment), adjust to `setEnableRequireIntegrity(false)` or whichever name the version exposes — verify against the artifact's Javadoc.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/jose4j
git commit -m "feat(benchmarks/jose4j): adapter"
```

---

## Task 15: nimbus-jose-jwt adapter

**Files:**
- Create: `benchmarks/nimbus-jose-jwt/project.latte`
- Create: `benchmarks/nimbus-jose-jwt/src/main/java/org/lattejava/jwt/benchmarks/nimbus/NimbusAdapter.java`
- Create: `benchmarks/nimbus-jose-jwt/src/main/java/org/lattejava/jwt/benchmarks/nimbus/NimbusBenchmark.java`
- Create: `benchmarks/nimbus-jose-jwt/src/main/java/org/lattejava/jwt/benchmarks/nimbus/Main.java`

- [ ] **Step 1: project.latte (depend on `com.nimbusds:nimbus-jose-jwt:<version>`)**

Same template; pin from `library-versions.md`.

- [ ] **Step 2: Implement NimbusAdapter**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.nimbus;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class NimbusAdapter implements JwtBenchmarkAdapter {

  private JWSSigner hs256Signer, rs256Signer, es256Signer;
  private JWSVerifier hs256Verifier, rs256Verifier, es256Verifier;
  private JWTClaimsSet canonicalClaims;
  private final Date fixedNow = new Date(1761408000_000L + 1_800_000L);

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    hs256Signer  = new MACSigner(fixtures.hmacKey);
    rs256Signer  = new RSASSASigner((RSAPrivateKey) fixtures.rsaPrivate);
    es256Signer  = new ECDSASigner((ECPrivateKey) fixtures.ecPrivate);
    hs256Verifier = new MACVerifier(fixtures.hmacKey);
    rs256Verifier = new RSASSAVerifier((RSAPublicKey) fixtures.rsaPublic);
    es256Verifier = new ECDSAVerifier((ECPublicKey) fixtures.ecPublic);

    canonicalClaims = new JWTClaimsSet.Builder()
        .issuer("https://benchmarks.lattejava.org")
        .subject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .audience("benchmark-audience")
        .issueTime(new Date(1761408000_000L))
        .notBeforeTime(new Date(1761408000_000L))
        .expirationTime(new Date(1761411600_000L))
        .jwtID("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .claim("scope", "openid profile email")
        .claim("email", "test@example.com")
        .claim("email_verified", true)
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) throws Exception {
    SignedJWT jwt = new SignedJWT(headerFor(alg), canonicalClaims);
    jwt.sign(switch (alg) {
      case HS256 -> hs256Signer;
      case RS256 -> rs256Signer;
      case ES256 -> es256Signer;
    });
    return jwt.serialize();
  }

  private static JWSHeader headerFor(BenchmarkAlgorithm alg) {
    return new JWSHeader(switch (alg) {
      case HS256 -> JWSAlgorithm.HS256;
      case RS256 -> JWSAlgorithm.RS256;
      case ES256 -> JWSAlgorithm.ES256;
    });
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    SignedJWT jwt = SignedJWT.parse(token);
    JWSVerifier v = switch (alg) {
      case HS256 -> hs256Verifier;
      case RS256 -> rs256Verifier;
      case ES256 -> es256Verifier;
    };
    if (!jwt.verify(v)) throw new SecurityException("nimbus verify failed");
    JWTClaimsSet cs = jwt.getJWTClaimsSet();
    Date exp = cs.getExpirationTime(), nbf = cs.getNotBeforeTime();
    if (exp != null && fixedNow.after(exp)) throw new IllegalStateException("expired");
    if (nbf != null && fixedNow.before(nbf)) throw new IllegalStateException("nbf");
    if (!"https://benchmarks.lattejava.org".equals(cs.getIssuer())) throw new IllegalStateException("iss");
    if (cs.getAudience() == null || !cs.getAudience().contains("benchmark-audience")) throw new IllegalStateException("aud");
    return cs;
  }

  @Override
  public Object unsafeDecode(String token) throws Exception {
    return JWSObject.parse(token);
  }
}
```

- [ ] **Step 3: NimbusBenchmark + Main, build, parity, smoke run, commit**

Same pattern as Tasks 13–14.

```bash
git add benchmarks/nimbus-jose-jwt
git commit -m "feat(benchmarks/nimbus-jose-jwt): adapter"
```

---

## Task 16: jjwt adapter

**Files:**
- Create: `benchmarks/jjwt/project.latte`
- Create: `benchmarks/jjwt/src/main/java/org/lattejava/jwt/benchmarks/jjwt/JjwtAdapter.java`
- Create: `benchmarks/jjwt/src/main/java/org/lattejava/jwt/benchmarks/jjwt/JjwtBenchmark.java`
- Create: `benchmarks/jjwt/src/main/java/org/lattejava/jwt/benchmarks/jjwt/Main.java`

- [ ] **Step 1: project.latte — three jjwt artifacts**

```groovy
jjwtVersion = "<from library-versions.md>"
// …
group(name: "compile") {
  dependency(id: "org.lattejava.jwt.benchmarks:harness:0.1.0")
  dependency(id: "io.jsonwebtoken:jjwt-api:${jjwtVersion}")
  dependency(id: "io.jsonwebtoken:jjwt-impl:${jjwtVersion}")
  dependency(id: "io.jsonwebtoken:jjwt-jackson:${jjwtVersion}")
  dependency(id: "org.openjdk.jmh:jmh-core:${jmhVersion}")
  dependency(id: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}")
}
```

- [ ] **Step 2: Implement JjwtAdapter**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.jjwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.AbstractDeserializer;
import java.security.Key;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class JjwtAdapter implements JwtBenchmarkAdapter {

  private Key hmacKey;
  private Key rsaPrivate, rsaPublic;
  private Key ecPrivate,  ecPublic;
  private JwtParser hs256Parser, rs256Parser, es256Parser;
  private JwtParser unsafeParser;
  private final long iatMs = 1761408000_000L;
  private final long expMs = 1761411600_000L;
  private final java.time.Clock fixedClock = java.time.Clock.fixed(
      java.time.Instant.ofEpochSecond(1761408000L + 1800L), java.time.ZoneOffset.UTC);

  @Override
  public void prepare(Fixtures fixtures) {
    hmacKey   = new SecretKeySpec(fixtures.hmacKey, "HmacSHA256");
    rsaPrivate = fixtures.rsaPrivate; rsaPublic = fixtures.rsaPublic;
    ecPrivate  = fixtures.ecPrivate;  ecPublic  = fixtures.ecPublic;

    hs256Parser = Jwts.parser().verifyWith((javax.crypto.SecretKey) hmacKey).clock(() -> Date.from(fixedClock.instant())).requireIssuer("https://benchmarks.lattejava.org").requireAudience("benchmark-audience").build();
    rs256Parser = Jwts.parser().verifyWith((java.security.PublicKey) rsaPublic).clock(() -> Date.from(fixedClock.instant())).requireIssuer("https://benchmarks.lattejava.org").requireAudience("benchmark-audience").build();
    es256Parser = Jwts.parser().verifyWith((java.security.PublicKey) ecPublic).clock(() -> Date.from(fixedClock.instant())).requireIssuer("https://benchmarks.lattejava.org").requireAudience("benchmark-audience").build();
    // jjwt 0.12+ requires explicit acknowledgment for unsigned parsing; for SIGNED no-verify
    // we use the structural parse without a key — inspect Jwts.parser().build().parse(token).
    unsafeParser = Jwts.parser().unsecured().build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    return Jwts.builder()
        .issuer("https://benchmarks.lattejava.org")
        .subject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .audience().add("benchmark-audience").and()
        .issuedAt(new Date(iatMs))
        .notBefore(new Date(iatMs))
        .expiration(new Date(expMs))
        .id("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .claim("scope", "openid profile email")
        .claim("email", "test@example.com")
        .claim("email_verified", true)
        .signWith(switch (alg) {
          case HS256 -> hmacKey;
          case RS256 -> rsaPrivate;
          case ES256 -> ecPrivate;
        })
        .compact();
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    Jws<Claims> jws = switch (alg) {
      case HS256 -> hs256Parser.parseSignedClaims(token);
      case RS256 -> rs256Parser.parseSignedClaims(token);
      case ES256 -> es256Parser.parseSignedClaims(token);
    };
    return jws;
  }

  @Override
  public Object unsafeDecode(String token) {
    // jjwt's structural parse: drops signature segment, returns header+claims.
    // Use io.jsonwebtoken.Jwt (unsigned-shape) parse path. If the API in the pinned version
    // forbids parsing a signed token without verification, throw UnsupportedOperationException
    // so the orchestrator records N/A.
    int lastDot = token.lastIndexOf('.');
    String unsignedToken = token.substring(0, lastDot + 1); // strip the signature
    return unsafeParser.parse(unsignedToken);
  }
}
```

- [ ] **Step 3: JjwtBenchmark + Main, build, parity, smoke run, commit**

If `unsafeDecode` cannot be made to work against the pinned version's public API without trickery (e.g. requires reading internal classes), throw `UnsupportedOperationException` instead and let the orchestrator record N/A. Note the decision in `benchmarks/library-versions.md`.

```bash
git add benchmarks/jjwt
git commit -m "feat(benchmarks/jjwt): adapter"
```

---

## Task 17: fusionauth-jwt adapter

**Files:**
- Create: `benchmarks/fusionauth-jwt/project.latte`
- Create: `benchmarks/fusionauth-jwt/src/main/java/org/lattejava/jwt/benchmarks/fusionauth/FusionAuthAdapter.java`
- Create: `benchmarks/fusionauth-jwt/src/main/java/org/lattejava/jwt/benchmarks/fusionauth/FusionAuthBenchmark.java`
- Create: `benchmarks/fusionauth-jwt/src/main/java/org/lattejava/jwt/benchmarks/fusionauth/Main.java`

- [ ] **Step 1: project.latte (depend on `io.fusionauth:fusionauth-jwt:<version>`)**

- [ ] **Step 2: Implement FusionAuthAdapter**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.fusionauth;

import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.ec.ECVerifier;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class FusionAuthAdapter implements JwtBenchmarkAdapter {

  private Signer hs256Signer, rs256Signer, es256Signer;
  private Verifier hs256Verifier, rs256Verifier, es256Verifier;
  private final ZonedDateTime fixedNow = ZonedDateTime.ofInstant(
      java.time.Instant.ofEpochSecond(1761408000L + 1800L), ZoneOffset.UTC);

  @Override
  public void prepare(Fixtures fixtures) {
    String hmacBase64 = java.util.Base64.getEncoder().encodeToString(fixtures.hmacKey);
    hs256Signer = HMACSigner.newSHA256Signer(hmacBase64);
    rs256Signer = RSASigner.newSHA256Signer(toPem(fixtures.rsaPrivate, "PRIVATE KEY"));
    es256Signer = ECSigner.newSHA256Signer(toPem(fixtures.ecPrivate,  "PRIVATE KEY"));

    hs256Verifier = HMACVerifier.newVerifier(fixtures.hmacKey);
    rs256Verifier = RSAVerifier.newVerifier(toPem(fixtures.rsaPublic, "PUBLIC KEY"));
    es256Verifier = ECVerifier.newVerifier(toPem(fixtures.ecPublic,   "PUBLIC KEY"));
  }

  private static String toPem(java.security.Key key, String label) {
    String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
    return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    JWT jwt = new JWT()
        .setIssuer("https://benchmarks.lattejava.org")
        .setSubject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .setAudience("benchmark-audience")
        .setIssuedAt(ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond(1761408000L), ZoneOffset.UTC))
        .setNotBefore(ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond(1761408000L), ZoneOffset.UTC))
        .setExpiration(ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond(1761411600L), ZoneOffset.UTC))
        .setUniqueId("01JK6V2N5W3YE4XJ5Y7Z8A9BC0");
    jwt.addClaim("scope", "openid profile email");
    jwt.addClaim("email", "test@example.com");
    jwt.addClaim("email_verified", true);
    return io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, switch (alg) {
      case HS256 -> hs256Signer;
      case RS256 -> rs256Signer;
      case ES256 -> es256Signer;
    });
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    Verifier v = switch (alg) {
      case HS256 -> hs256Verifier;
      case RS256 -> rs256Verifier;
      case ES256 -> es256Verifier;
    };
    JWT decoded = JWT.getDecoder().decode(token, v);
    if (decoded.expiration != null && fixedNow.isAfter(decoded.expiration)) throw new IllegalStateException("expired");
    if (decoded.notBefore != null && fixedNow.isBefore(decoded.notBefore)) throw new IllegalStateException("nbf");
    if (!"https://benchmarks.lattejava.org".equals(decoded.issuer)) throw new IllegalStateException("iss");
    if (!decoded.audience.contains("benchmark-audience")) throw new IllegalStateException("aud");
    return decoded;
  }

  @Override
  public Object unsafeDecode(String token) {
    // fusionauth-jwt: JWTUtils.decodePayload exposes the claims without verifying.
    return JWTUtils.decodePayload(token);
  }
}
```

- [ ] **Step 3: FusionAuthBenchmark + Main, build, parity, smoke run, commit**

```bash
git add benchmarks/fusionauth-jwt
git commit -m "feat(benchmarks/fusionauth-jwt): adapter"
```

---

## Task 18: vertx-auth-jwt adapter

**Files:**
- Create: `benchmarks/vertx-auth-jwt/project.latte`
- Create: `benchmarks/vertx-auth-jwt/src/main/java/org/lattejava/jwt/benchmarks/vertx/VertxAdapter.java`
- Create: `benchmarks/vertx-auth-jwt/src/main/java/org/lattejava/jwt/benchmarks/vertx/VertxBenchmark.java`
- Create: `benchmarks/vertx-auth-jwt/src/main/java/org/lattejava/jwt/benchmarks/vertx/Main.java`

**Caveat (per spec):** Vert.x's API is async (`Future`-based). The adapter unwraps `Future`s synchronously via `.toCompletionStage().toCompletableFuture().get()`; the unwrap overhead is captured in the result and called out in `benchmarks/README.md`.

- [ ] **Step 1: project.latte (depend on `io.vertx:vertx-auth-jwt:<version>` + `io.vertx:vertx-core:<version>`)**

vertx-auth-jwt may not pull vertx-core as a transitive dep — verify by reading the artifact's POM and add explicitly if needed.

- [ ] **Step 2: Implement VertxAdapter**

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.vertx;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.authorization.JWTAuthorization;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class VertxAdapter implements JwtBenchmarkAdapter {

  private Vertx vertx;
  private JWTAuth hs256Auth, rs256Auth, es256Auth;
  private JsonObject canonicalClaims;

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    vertx = Vertx.vertx();
    hs256Auth = JWTAuth.create(vertx, new JWTAuthOptions().addPubSecKey(
        new PubSecKeyOptions().setAlgorithm("HS256").setBuffer(new String(fixtures.hmacKey))));
    rs256Auth = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions().setAlgorithm("RS256").setBuffer(pem(fixtures.rsaPrivate, "PRIVATE KEY")))
        .addPubSecKey(new PubSecKeyOptions().setAlgorithm("RS256").setBuffer(pem(fixtures.rsaPublic,  "PUBLIC KEY"))));
    es256Auth = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions().setAlgorithm("ES256").setBuffer(pem(fixtures.ecPrivate, "PRIVATE KEY")))
        .addPubSecKey(new PubSecKeyOptions().setAlgorithm("ES256").setBuffer(pem(fixtures.ecPublic,  "PUBLIC KEY"))));

    canonicalClaims = new JsonObject(new String(fixtures.claimsJsonBytes));
  }

  private static String pem(java.security.Key key, String label) {
    String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
    return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    JWTAuth auth = switch (alg) { case HS256 -> hs256Auth; case RS256 -> rs256Auth; case ES256 -> es256Auth; };
    JWTOptions opts = new JWTOptions().setAlgorithm(alg.name());
    return auth.generateToken(canonicalClaims, opts);
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    JWTAuth auth = switch (alg) { case HS256 -> hs256Auth; case RS256 -> rs256Auth; case ES256 -> es256Auth; };
    Future<User> fut = auth.authenticate(new JsonObject().put("token", token));
    return fut.toCompletionStage().toCompletableFuture().get();
  }

  @Override
  public Object unsafeDecode(String token) {
    // vertx-auth-jwt does not expose a public no-verify decode API on JWTAuth.
    throw new UnsupportedOperationException("vertx-auth-jwt has no public unsafe-decode API");
  }
}
```

- [ ] **Step 3: VertxBenchmark + Main, build, parity, smoke run, commit**

Parity check should pass 3/3 algorithms; `unsafe_decode` records N/A (UnsupportedOperationException is expected).

```bash
git add benchmarks/vertx-auth-jwt
git commit -m "feat(benchmarks/vertx-auth-jwt): adapter (unsafe_decode N/A)"
```

---

## Task 19: inverno-security-jose adapter

**Files:**
- Create: `benchmarks/inverno-security-jose/project.latte`
- Create: `benchmarks/inverno-security-jose/src/main/java/org/lattejava/jwt/benchmarks/inverno/InvernoAdapter.java`
- Create: `benchmarks/inverno-security-jose/src/main/java/org/lattejava/jwt/benchmarks/inverno/InvernoBenchmark.java`
- Create: `benchmarks/inverno-security-jose/src/main/java/org/lattejava/jwt/benchmarks/inverno/Main.java`

**Note:** Inverno's typical entry point is via its CDI container, but per the spec the adapter uses the public synchronous API surface only — no CDI container at runtime. Read https://inverno.io/docs/release/dev/api/inverno-modules/io.inverno.mod.security.jose/module-summary.html to find the direct service classes.

- [ ] **Step 1: project.latte (depend on `io.inverno.mod:inverno-security-jose:<version>`)**

If inverno-security-jose pulls in a heavy transitive web of dependencies, verify the JAR still runs in a pure-Java context (no CDI bootstrap) before continuing.

- [ ] **Step 2: Implement InvernoAdapter using the direct (non-CDI) JWTService and JWSService classes**

The exact class names are version-dependent. Read the Javadoc, find the synchronous JWS sign / verify path, and implement against it. Keep the adapter shape identical to the others — `prepare` builds signers/verifiers, `encode` calls the sync sign API, `decodeVerifyValidate` calls the sync verify API.

For `unsafeDecode`: if Inverno exposes `JOSEObject.parse(token)` or similar that returns a parsed-but-unverified shape, use it. Otherwise throw `UnsupportedOperationException`.

- [ ] **Step 3: InvernoBenchmark + Main, build, parity, smoke run, commit**

If the dependency surface or threading model is incompatible with a flat JVM bench run (e.g. requires CDI bootstrap), document the blocker in `benchmarks/library-versions.md` and either skip Inverno (drop it from `benchmarks.yaml`) or implement a minimal stub adapter that reports N/A on every operation. The spec already accommodates failed libraries gracefully.

```bash
git add benchmarks/inverno-security-jose
git commit -m "feat(benchmarks/inverno-security-jose): adapter"
```

---

## Task 20: Full eight-library run

- [ ] **Step 1: Run a quick end-to-end across all libraries**

Run: `benchmarks/run-benchmarks.sh --quick`

Expected: sanity → builds all 8 libs → parity 4/4 (or 3/4 with N/A for vertx and possibly Inverno) → measurement → merge → run-conditions sidecar.

- [ ] **Step 2: Inspect merged JSON**

```bash
jq '[.[] | {benchmark, mode, score: .primaryMetric.score}]' benchmarks/results/latest.json | head -40
```

Expected: one record per (library, benchmark-method, mode) combination. Scores are non-zero finite floats.

- [ ] **Step 3: Commit nothing — this is a smoke run, but archive the result file outside the repo if desired**

This task is an integration checkpoint, not a code change. If parity fails for any library, fix that adapter before continuing.

---

## Task 21: update-benchmarks.sh — leaderboard generator

**Files:**
- Create: `benchmarks/update-benchmarks.sh`

- [ ] **Step 1: Implement the generator skeleton**

```bash
#!/usr/bin/env bash
# Copyright (c) 2026, The Latte Project. License: MIT.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESULTS_FILE="${1:-${SCRIPT_DIR}/results/latest.json}"
CONDITIONS_FILE="${RESULTS_FILE%.json}.conditions.json"
[[ -f "${CONDITIONS_FILE}" ]] || CONDITIONS_FILE="${SCRIPT_DIR}/results/latest.conditions.json"
TARGET="${SCRIPT_DIR}/BENCHMARKS.md"

CI_THRESHOLD="${CI_THRESHOLD:-5}"  # percent

# extract per-(library, op, mode) score from JMH JSON
extract() {
  jq -r '
    .[] | {
      lib:   (.benchmark | split(".") | .[-2]),
      op:    (.benchmark | split(".") | .[-1]),
      mode:  .mode,
      score: .primaryMetric.score,
      err:   .primaryMetric.scoreError,
      unit:  .primaryMetric.scoreUnit
    } | [.lib, .op, .mode, .score, .err, .unit] | @tsv
  ' "${RESULTS_FILE}"
}

# render one leaderboard for a given (op, mode) selector
render_leaderboard() {
  local op="$1"
  local mode="$2"
  local title="$3"
  local rows
  rows=$(extract | awk -F'\t' -v op="${op}" -v mode="${mode}" '$2==op && $3==mode { print }')
  [[ -z "${rows}" ]] && return 0

  local leader_score
  leader_score=$(echo "${rows}" | sort -t$'\t' -k4 -gr | head -1 | awk -F'\t' '{print $4}')
  local latte_score
  latte_score=$(echo "${rows}" | awk -F'\t' '$1=="LatteJwtBenchmark" {print $4}')

  echo "### ${title}"
  echo
  echo "| # | Library | ops/sec | vs leader | vs latte-jwt |"
  echo "|--:|---------|--------:|----------:|-------------:|"
  echo "${rows}" | sort -t$'\t' -k4 -gr | awk -F'\t' -v ld="${leader_score}" -v lt="${latte_score}" '
    BEGIN { rank = 0 }
    $1 != "BaselineBenchmark" {
      rank++
      printf "| %d | %s | %.0f | %.1f %% | %s |\n", rank, libname($1), $4, ($4/ld)*100, (lt>0 ? sprintf("%.1f %%",($4/lt)*100) : "—")
    }
    function libname(b) {
      gsub(/Benchmark$/, "", b);
      return tolower(b);
    }
  '
  # baseline italic row appended at bottom
  echo "${rows}" | awk -F'\t' -v ld="${leader_score}" -v lt="${latte_score}" '
    $1 == "BaselineBenchmark" {
      printf "| | _baseline (JCA)_ | _%.0f_ | _%.1f %%_ | _%s_ |\n", $4, ($4/ld)*100, (lt>0 ? sprintf("%.1f %%",($4/lt)*100) : "—")
    }
  '
  echo
}

# the body content between sentinels
generate_body() {
  echo "<!-- BENCHMARKS:START -->"
  echo
  echo "## Throughput by algorithm (ops/sec, higher is better)"
  echo
  render_leaderboard "hs256_encode"                "thrpt" "HS256 — encode"
  render_leaderboard "hs256_decode_verify_validate" "thrpt" "HS256 — decode + verify + validate"
  render_leaderboard "rs256_encode"                "thrpt" "RS256 — encode"
  render_leaderboard "rs256_decode_verify_validate" "thrpt" "RS256 — decode + verify + validate"
  render_leaderboard "es256_encode"                "thrpt" "ES256 — encode"
  render_leaderboard "es256_decode_verify_validate" "thrpt" "ES256 — decode + verify + validate"
  echo
  echo "## Supporting operations"
  echo
  render_leaderboard "unsafe_decode"               "thrpt" "Unsafe decode (no signature verification)"
  echo
  echo "## Run conditions"
  if [[ -f "${CONDITIONS_FILE}" ]]; then
    echo '```json'
    jq . "${CONDITIONS_FILE}"
    echo '```'
  fi
  echo
  echo "<!-- BENCHMARKS:END -->"
}

# assemble final BENCHMARKS.md (preserve hand-edited prose outside sentinels)
if [[ -f "${TARGET}" ]] && grep -q 'BENCHMARKS:START' "${TARGET}"; then
  awk -v body="$(generate_body)" '
    /BENCHMARKS:START/ { print body; in_block=1; next }
    /BENCHMARKS:END/   { in_block=0; next }
    !in_block          { print }
  ' "${TARGET}" > "${TARGET}.tmp" && mv "${TARGET}.tmp" "${TARGET}"
else
  cat > "${TARGET}" <<EOF
# JWT Library Benchmarks

(Hand-edited intro: how to read, hardware/JVM caveat, link back to README.)

$(generate_body)
EOF
fi

echo "wrote ${TARGET}"
```

- [ ] **Step 2: Make executable + run against latest results**

```bash
chmod +x benchmarks/update-benchmarks.sh
benchmarks/update-benchmarks.sh
cat benchmarks/BENCHMARKS.md
```

Expected: a Markdown file with seven leaderboards (encode/decode for three algorithms + unsafe_decode), plus the run conditions block.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/update-benchmarks.sh benchmarks/BENCHMARKS.md
git commit -m "feat(benchmarks): leaderboard generator + initial BENCHMARKS.md"
```

---

## Task 22: update-benchmarks.sh — top-of-page aggregate summary

- [ ] **Step 1: Add aggregate-leaderboard rendering**

Insert into `update-benchmarks.sh` between the title-section and the START sentinel.

```bash
render_aggregate() {
  echo "## Overall leaderboard — decode-verify-validate (the headline op)"
  echo
  echo "Mean ops/sec across HS256, RS256, ES256 decode-verify-validate (Throughput mode):"
  echo
  echo "| # | Library | mean ops/sec |"
  echo "|--:|---------|-------------:|"
  extract | awk -F'\t' '$2 ~ /_decode_verify_validate$/ && $3=="thrpt" {
    sum[$1] += $4
    n[$1]++
  }
  END {
    for (lib in sum) printf "%s\t%.0f\n", lib, sum[lib]/n[lib]
  }' | sort -t$'\t' -k2 -gr | awk -F'\t' '
    BEGIN { rank = 0 }
    $1 != "BaselineBenchmark" {
      rank++
      gsub(/Benchmark$/, "", $1);
      printf "| %d | %s | %.0f |\n", rank, tolower($1), $2
    }
  '
  extract | awk -F'\t' '$2 ~ /_decode_verify_validate$/ && $3=="thrpt" && $1=="BaselineBenchmark" {
    sum += $4
    n++
  }
  END {
    if (n>0) printf "| | _baseline (JCA)_ | _%.0f_ |\n", sum/n
  }'
  echo
}
```

Then call `render_aggregate` from inside the `else` branch of the `BENCHMARKS.md` assembly (the from-scratch creation), and inject it into the existing file just after the title in the `awk` rewrite path.

- [ ] **Step 2: Re-run + inspect**

```bash
benchmarks/update-benchmarks.sh
cat benchmarks/BENCHMARKS.md
```

Expected: aggregate table near the top, plus the per-algorithm leaderboards.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/update-benchmarks.sh benchmarks/BENCHMARKS.md
git commit -m "feat(benchmarks): aggregate decode-vv leaderboard at top"
```

---

## Task 23: compare-results.sh — diff two result files

**Files:**
- Create: `benchmarks/compare-results.sh`

- [ ] **Step 1: Implement compare-results.sh**

```bash
#!/usr/bin/env bash
# Copyright (c) 2026, The Latte Project. License: MIT.
# Usage: compare-results.sh <baseline.json> <candidate.json> [--threshold N] [--algorithm <hs256|rs256|es256>]
set -euo pipefail

THRESHOLD=5
ALG_FILTER=""
BASELINE=""
CANDIDATE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --algorithm) ALG_FILTER="$2"; shift 2 ;;
    *)
      if   [[ -z "${BASELINE}"  ]]; then BASELINE="$1";  shift
      elif [[ -z "${CANDIDATE}" ]]; then CANDIDATE="$1"; shift
      else echo "Unexpected: $1" >&2; exit 2; fi ;;
  esac
done

[[ -f "${BASELINE}"  ]] || { echo "Missing baseline:  ${BASELINE}"  >&2; exit 2; }
[[ -f "${CANDIDATE}" ]] || { echo "Missing candidate: ${CANDIDATE}" >&2; exit 2; }

extract() {
  jq -r '
    .[] | select(.mode=="thrpt") |
    [(.benchmark | split(".") | .[-2]),
     (.benchmark | split(".") | .[-1]),
     .primaryMetric.score] | @tsv
  ' "$1"
}

declare -A B C
while IFS=$'\t' read -r lib op score; do B["${lib}|${op}"]="${score}"; done < <(extract "${BASELINE}")
while IFS=$'\t' read -r lib op score; do C["${lib}|${op}"]="${score}"; done < <(extract "${CANDIDATE}")

regressed=0
echo "| Op | Library | Baseline | Candidate | Δ % | Flag |"
echo "|----|---------|---------:|----------:|----:|:----:|"
for key in "${!B[@]}"; do
  lib="${key%%|*}"
  op="${key##*|}"
  [[ -n "${ALG_FILTER}" && "${op}" != "${ALG_FILTER}"* ]] && continue
  base="${B[${key}]}"
  cand="${C[${key}]:-}"
  [[ -z "${cand}" ]] && continue
  delta=$(awk -v b="${base}" -v c="${cand}" 'BEGIN { printf "%.1f", ((c-b)/b)*100 }')
  flag=""
  abs_delta=$(awk -v d="${delta}" 'BEGIN { printf "%.1f", (d<0?-d:d) }')
  if awk -v d="${abs_delta}" -v t="${THRESHOLD}" 'BEGIN { exit !(d>=t) }'; then
    if awk -v d="${delta}" 'BEGIN { exit !(d<0) }'; then
      flag="▼"
      regressed=1
    else
      flag="▲"
    fi
  fi
  printf "| %s | %s | %.0f | %.0f | %s %% | %s |\n" \
    "${op}" "$(echo "${lib}" | sed 's/Benchmark$//' | tr 'A-Z' 'a-z')" "${base}" "${cand}" "${delta}" "${flag}"
done

exit ${regressed}
```

- [ ] **Step 2: Smoke test**

```bash
chmod +x benchmarks/compare-results.sh
# diff a result file against itself — every Δ should be 0.0%, exit 0
benchmarks/compare-results.sh benchmarks/results/latest.json benchmarks/results/latest.json
```

Expected: full table with all 0.0 % deltas, exit 0.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/compare-results.sh
git commit -m "feat(benchmarks): compare-results.sh diff tool"
```

---

## Task 24: README.md performance section

**Files:**
- Modify: `README.md` (project root)

- [ ] **Step 1: Find the appropriate insertion point**

Read the project README and identify where a `## Performance` section fits. Likely near the top features bullets, before the "## License" or detailed sections.

- [ ] **Step 2: Add the performance section with sentinel markers**

Insert:

```markdown
## Performance

`latte-jwt` is the fastest pure-Java JWT library while remaining zero-dependency. Decoding and verifying an `RS256` token — the dominant cost in real OAuth/OIDC services — is the most-quoted comparison:

<!-- README:PERFORMANCE:START -->

(generated table goes here)

<!-- README:PERFORMANCE:END -->

Full methodology and per-algorithm leaderboards in [`benchmarks/BENCHMARKS.md`](benchmarks/BENCHMARKS.md).
```

- [ ] **Step 3: Extend update-benchmarks.sh to also rewrite the README's RS256 decode table**

Add to `benchmarks/update-benchmarks.sh` after `BENCHMARKS.md` is rewritten:

```bash
README="${SCRIPT_DIR}/../README.md"
if [[ -f "${README}" ]] && grep -q 'README:PERFORMANCE:START' "${README}"; then
  README_BODY="$(render_leaderboard "rs256_decode_verify_validate" "thrpt" "RS256 — decode + verify + validate")"
  awk -v body="${README_BODY}" '
    /README:PERFORMANCE:START/ { print; print body; in_block=1; next }
    /README:PERFORMANCE:END/   { in_block=0; print; next }
    !in_block { print }
  ' "${README}" > "${README}.tmp" && mv "${README}.tmp" "${README}"
fi
```

- [ ] **Step 4: Run + verify**

```bash
benchmarks/update-benchmarks.sh
git diff README.md
```

Expected: the README's performance section now contains the RS256 decode-verify-validate leaderboard.

- [ ] **Step 5: Commit**

```bash
git add README.md benchmarks/update-benchmarks.sh
git commit -m "feat(benchmarks): integrate RS256 leaderboard into README"
```

---

## Task 25: benchmarks/README.md — operator guidance

**Files:**
- Modify: `benchmarks/README.md`

- [ ] **Step 1: Replace the placeholder with full operator-facing content**

```markdown
# Benchmarks

JMH-based benchmark suite comparing `latte-jwt` against seven other Java JWT libraries:
`auth0/java-jwt`, `jose4j`, `nimbus-jose-jwt`, `jjwt`, `fusionauth-jwt`, `vertx-auth-jwt`,
`inverno-security-jose` — plus a hand-rolled JCA baseline as a theoretical floor.

The full design is in [`../specs/benchmark-framework.md`](../specs/benchmark-framework.md).
The latest committed results are in [`BENCHMARKS.md`](BENCHMARKS.md).

## Running

```bash
# Full run (~2.5 hours)
./run-benchmarks.sh

# Subset of libraries
./run-benchmarks.sh --libraries baseline,latte-jwt

# Quick dev loop (~10 min, 1 fork, shorter iterations)
./run-benchmarks.sh --quick

# Regenerate BENCHMARKS.md from the latest result
./update-benchmarks.sh

# Compare two result files
./compare-results.sh results/A.json results/B.json --threshold 5
```

## Quiet-machine guidance

JMH numbers depend on what else the CPU is doing. For results worth quoting:

- **macOS:** connect AC power, disable Low Power Mode, close other applications. The
  orchestrator runs `pmset -g therm` and warns if `CPU_Speed_Limit < 100`.
- **Linux:** set the `cpufreq` governor to `performance` and consider disabling Turbo Boost:
  ```bash
  echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
  echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo  # if Intel
  ```
- **All:** relative numbers between libraries remain meaningful even on a noisy machine;
  absolute ops/sec do not.

## Vert.x async caveat

`vertx-auth-jwt` exposes only async (`Future`-based) APIs. The adapter unwraps `Future`s
synchronously via `.toCompletionStage().toCompletableFuture().get()`. The unwrap overhead
is included in the reported result and should be considered when comparing absolute throughput.

## Adding a library

1. Create `benchmarks/<lib>/project.latte` depending on `org.lattejava.jwt.benchmarks:harness:0.1.0`,
   the new library, and JMH.
2. Implement `org.lattejava.jwt.benchmarks.<lib>.<Lib>Adapter` against `JwtBenchmarkAdapter`.
3. Add a one-line `<Lib>Benchmark extends AbstractJwtBenchmark` and a `Main`.
4. Add the library ID to `benchmarks.yaml`.
5. Pin the version in [`library-versions.md`](library-versions.md).
```

- [ ] **Step 2: Commit**

```bash
git add benchmarks/README.md
git commit -m "docs(benchmarks): operator-facing README"
```

---

## Task 26: Final clean run + commit BENCHMARKS.md snapshot

- [ ] **Step 1: Quiet the machine**

Per `benchmarks/README.md` § "Quiet-machine guidance", close other applications, ensure AC power, disable Low Power Mode (macOS) or set `performance` governor (Linux).

- [ ] **Step 2: Remove the spike directory**

```bash
git rm -r benchmarks/spike
git commit -m "chore(benchmarks): remove spike scaffolding"
```

- [ ] **Step 3: Run the full benchmark**

```bash
benchmarks/run-benchmarks.sh --update
```

Expected: ~2.5 hours runtime (proportional to actual hardware). Produces `benchmarks/results/latest.json`, `benchmarks/results/latest.conditions.json`, and a regenerated `benchmarks/BENCHMARKS.md` + `README.md` performance section.

- [ ] **Step 4: Inspect outputs**

```bash
cat benchmarks/BENCHMARKS.md
git diff README.md
```

Confirm: aggregate table at top, seven per-leaderboard tables, run conditions block, README's RS256 leaderboard updated.

- [ ] **Step 5: Commit the snapshot**

```bash
git add benchmarks/results/latest.json benchmarks/results/latest.conditions.json \
        benchmarks/BENCHMARKS.md README.md
git commit -m "feat(benchmarks): initial committed snapshot"
```

- [ ] **Step 6: Move spec to In Progress / Implemented**

Per `specs/README.md` lifecycle: with the framework now landed, flip the spec status:

```bash
# specs/benchmark-framework.md: Status: Approved → Implemented
# specs/README.md index row: Status: Approved → Implemented, Last updated: today
```

Add a change-log entry noting the framework is shipped, then commit:

```bash
git add specs/benchmark-framework.md specs/README.md
git commit -m "docs(specs): benchmark framework Implemented"
```

---

## Self-review checklist (already performed by the plan author)

**Spec coverage:**
- ✅ Per-library project layout + JVM isolation (Tasks 7–8, 13–19)
- ✅ Shared harness (Tasks 3–6)
- ✅ Fixtures (Task 2)
- ✅ Three algorithms × encode + decode-verify-validate + unsafe_decode (= seven benchmarks per library) (Task 5)
- ✅ Mode.AverageTime on decode methods (Task 5)
- ✅ JMH config 3 forks × 3 measurement × 10s (Task 9)
- ✅ Pre-flight parity check (Task 6 + Task 10)
- ✅ Run-condition capture sidecar (Task 12)
- ✅ benchmarks.yaml runner config (Task 9)
- ✅ run-benchmarks.sh orchestrator with all CLI flags (Tasks 10–12)
- ✅ Result merger (jq) (Task 11)
- ✅ update-benchmarks.sh leaderboard generator with sentinel markers (Tasks 21–22)
- ✅ compare-results.sh (Task 23)
- ✅ README.md performance section integration (Task 24)
- ✅ benchmarks/README.md operator guidance (Task 25)
- ✅ License headers (MIT 7.0) on new files
- ✅ .gitignore rule for results/ (Task 1, refined Task 12)

**Type/name consistency:**
- `JwtBenchmarkAdapter` interface: identical signature across all adapter implementations
- `BenchmarkAlgorithm` enum: HS256, RS256, ES256 (no `none`) used uniformly
- `BenchmarkRunner.run(libraryName, benchmarkClass, adapter)` signature matches every Main
- Benchmark method IDs (`hs256_encode`, `unsafe_decode`, etc.) match between AbstractJwtBenchmark and the spec

**Risks called out in tasks:**
- Latte+JMH annotation processing not auto-wired → Task 0 verifies, fallbacks documented
- Latte multi-module dep on harness → Task 6 publishes via `latte int` (local repo); per-library `project.latte` references the published coordinate
- Inverno may require CDI bootstrap incompatible with flat JVM → Task 19 has graceful skip path
- jjwt unsafe-decode path may require parsing an unsigned-shaped token → Task 16 documents; throws UnsupportedOperationException as fallback
