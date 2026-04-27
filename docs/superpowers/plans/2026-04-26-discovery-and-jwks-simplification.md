# Discovery + JWKS Simplification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement spec `specs/7.0-discovery-and-jwks-simplification.md` (rev 3): promote OIDC discovery to a first-class type (`OpenIDConnectConfiguration` + `OpenIDConnect.discover`), rename `JWKSource` → `JWKS` with raw-JWK lookup and new factories, replace process-global hardening config with per-instance `FetchLimits` (with same-origin redirect default), add `failFast` build mode, and delete the OAuth-only metadata classes.

**Architecture:** New top-level types `OpenIDConnectConfiguration`, `OpenIDConnectException`, `FetchLimits` (in `org.lattejava.jwt`). New static methods `OpenIDConnect.discover(...)` / `discoverFromWellKnown(...)` performing fetch + parse + issuer-equality validation. Class rename `JWKSource` → `JWKS` with new instance methods (`get(kid)`, `keys()`, `keyIds()`), new factories (`fromConfiguration`, `of(...)`, `fetchOnce(...)`), and the construction-time discovery hop replacing per-refresh discovery (locked once successful). Hardened JSON parsing extracted to `internal/HardenedJSON`. Same-origin redirect policy on every hop, opt-out via `FetchLimits.allowCrossOriginRedirects(true)`. OAuth-only classes (`AuthorizationServerMetaData`, `ServerMetaDataHelper`, `JSONWebKeySetHelper`) deleted; `oauth2/` package removed (and from `module-info.java`).

**Tech Stack:** Java 21, TestNG, the Latte CLI build (`latte build`, `latte test`, `latte test --jca`, `latte test --fips`). Zero compile-scope dependencies — do not add any. Project-specific rules in `.claude/rules/code-conventions.md` (acronyms uppercase, alphabetized members, no blank lines between fields, sentence-style Javadoc, class-member ordering by visibility) and `.claude/rules/error-messages.md` (`[value]` brackets in exception/log messages) are non-negotiable.

**Spec sections referenced:** Implements §1–§5 of `specs/7.0-discovery-and-jwks-simplification.md` (rev 3). §6 (changelog) is project documentation produced at release time, not in this plan. §7 items are explicitly out of scope.

**Branch:** `robotdan/simpler` (worktree at `.worktrees/robotdan/simpler`).

**Conventions for every task:**
- TDD discipline: write the failing test first, run it, watch it fail with the expected reason, then implement.
- One commit per task. Use Conventional Commits style (`feat:`, `refactor:`, `test:`, `chore:`); keep the subject ≤72 chars.
- Run `latte test --jca` at minimum before committing each task. Run the full `latte test` (both JCA and FIPS) before the final verification task.
- Run a single class with `latte test --jca --test=ClassName` (simple class name, not FQN).
- Acronyms upper-case throughout (`URI` not `Uri`, `JSON` not `Json`, `JWKS` not `Jwks`).
- All exception/log messages wrap runtime values in `[value]` (never `'value'` or `"value"`).
- License header: brand-new code uses the MIT header `Copyright (c) 2026, The Latte Project, All Rights Reserved` (see `src/main/java/org/lattejava/jwt/jwks/JWKSource.java` lines 1-22 for the exact text). Inherited Apache-2.0 files keep their existing headers.
- Inside a class, member ordering: static fields → instance fields → constructors (by parameter count) → static methods (by visibility, then alphabetical) → instance methods (by visibility, then alphabetical) → inner classes → nested classes. No blank lines between fields.

---

## Task 1: `FetchLimits` (per-instance hardening config)

**Spec reference:** §4.

**Files:**
- Create: `src/main/java/org/lattejava/jwt/FetchLimits.java`
- Test: `src/test/java/org/lattejava/jwt/FetchLimitsTest.java`

This is a pure value type. It carries the limits today expressed as static volatile fields on `JSONWebKeySetHelper` and `ServerMetaDataHelper`, plus the new `allowCrossOriginRedirects` flag. No callers yet — it gets wired into discovery (Task 6) and JWKS fetches (Tasks 11–13).

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/FetchLimitsTest.java`:

```java
/* MIT header — copy from src/main/java/org/lattejava/jwt/jwks/JWKSource.java lines 1-22 */
package org.lattejava.jwt;

import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;

public class FetchLimitsTest extends BaseTest {
  @Test
  public void builder_allows_zero_redirects() {
    // Zero disables redirect following -- explicitly permitted.
    FetchLimits limits = FetchLimits.builder().maxRedirects(0).build();
    assertEquals(limits.maxRedirects(), 0);
  }

  @Test
  public void builder_is_reusable() {
    FetchLimits.Builder b = FetchLimits.builder().maxResponseBytes(1000);
    FetchLimits a = b.build();
    FetchLimits c = b.maxResponseBytes(2000).build();
    assertEquals(a.maxResponseBytes(), 1000);
    assertEquals(c.maxResponseBytes(), 2000);
  }

  @Test
  public void builder_overrides_each_field() {
    FetchLimits limits = FetchLimits.builder()
        .allowCrossOriginRedirects(true)
        .allowDuplicateJSONKeys(true)
        .maxArrayElements(100)
        .maxNestingDepth(8)
        .maxNumberLength(500)
        .maxObjectMembers(50)
        .maxRedirects(7)
        .maxResponseBytes(2048)
        .build();
    assertEquals(limits.allowCrossOriginRedirects(), true);
    assertEquals(limits.allowDuplicateJSONKeys(), true);
    assertEquals(limits.maxArrayElements(), 100);
    assertEquals(limits.maxNestingDepth(), 8);
    assertEquals(limits.maxNumberLength(), 500);
    assertEquals(limits.maxObjectMembers(), 50);
    assertEquals(limits.maxRedirects(), 7);
    assertEquals(limits.maxResponseBytes(), 2048);
  }

  @Test
  public void builder_rejects_negative_redirects() {
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxRedirects(-1));
  }

  @Test
  public void builder_rejects_zero_or_negative_numeric_limits() {
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxResponseBytes(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxResponseBytes(-1));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxNestingDepth(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxNumberLength(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxObjectMembers(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxArrayElements(0));
  }

  @Test
  public void defaults_match_documented_values() {
    FetchLimits d = FetchLimits.defaults();
    assertEquals(d.maxResponseBytes(), 1024 * 1024);
    assertEquals(d.maxRedirects(), 3);
    assertEquals(d.maxNestingDepth(), 16);
    assertEquals(d.maxNumberLength(), 1000);
    assertEquals(d.maxObjectMembers(), 1000);
    assertEquals(d.maxArrayElements(), 10000);
    assertFalse(d.allowDuplicateJSONKeys());
    assertFalse(d.allowCrossOriginRedirects());
  }

  @Test
  public void defaults_returns_singleton() {
    assertSame(FetchLimits.defaults(), FetchLimits.defaults());
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=FetchLimitsTest`
Expected: compilation failure — `FetchLimits` does not exist.

- [ ] **Step 3: Implement `FetchLimits`**

Create `src/main/java/org/lattejava/jwt/FetchLimits.java`:

```java
/* MIT header */
package org.lattejava.jwt;

import java.util.Objects;

/**
 * Per-instance hardening limits for HTTP fetches and JSON parsing performed
 * by {@link org.lattejava.jwt.jwks.JWKS} and {@link OpenIDConnect#discover(String)}.
 * Replaces the volatile static configuration that lived on the deleted
 * {@code JSONWebKeySetHelper} and {@code ServerMetaDataHelper}.
 *
 * <p>Instances are immutable. {@link #defaults()} returns a shared singleton.
 * Defaults match historical behavior exactly for the carried-forward fields;
 * {@link #allowCrossOriginRedirects()} is new in 7.0 and defaults to
 * {@code false} (stricter than 6.x, which had no origin check).</p>
 *
 * <p>The response cap and JSON parser caps cannot be disabled — the
 * corresponding setters reject zero or negative values. {@link #maxRedirects()}
 * is the exception: zero is permitted and disables redirect following.</p>
 */
public final class FetchLimits {
  private static final FetchLimits DEFAULTS = new FetchLimits(new Builder());
  private final boolean allowCrossOriginRedirects;
  private final boolean allowDuplicateJSONKeys;
  private final int maxArrayElements;
  private final int maxNestingDepth;
  private final int maxNumberLength;
  private final int maxObjectMembers;
  private final int maxRedirects;
  private final int maxResponseBytes;

  private FetchLimits(Builder b) {
    this.allowCrossOriginRedirects = b.allowCrossOriginRedirects;
    this.allowDuplicateJSONKeys = b.allowDuplicateJSONKeys;
    this.maxArrayElements = b.maxArrayElements;
    this.maxNestingDepth = b.maxNestingDepth;
    this.maxNumberLength = b.maxNumberLength;
    this.maxObjectMembers = b.maxObjectMembers;
    this.maxRedirects = b.maxRedirects;
    this.maxResponseBytes = b.maxResponseBytes;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static FetchLimits defaults() {
    return DEFAULTS;
  }

  public boolean allowCrossOriginRedirects() { return allowCrossOriginRedirects; }
  public boolean allowDuplicateJSONKeys() { return allowDuplicateJSONKeys; }
  public int maxArrayElements() { return maxArrayElements; }
  public int maxNestingDepth() { return maxNestingDepth; }
  public int maxNumberLength() { return maxNumberLength; }
  public int maxObjectMembers() { return maxObjectMembers; }
  public int maxRedirects() { return maxRedirects; }
  public int maxResponseBytes() { return maxResponseBytes; }

  /**
   * Reusable, mutable builder. Each {@link #build()} returns a fresh
   * immutable {@link FetchLimits}.
   */
  public static final class Builder {
    private boolean allowCrossOriginRedirects = false;
    private boolean allowDuplicateJSONKeys = false;
    private int maxArrayElements = 10_000;
    private int maxNestingDepth = 16;
    private int maxNumberLength = 1000;
    private int maxObjectMembers = 1000;
    private int maxRedirects = 3;
    private int maxResponseBytes = 1024 * 1024;

    private Builder() {}

    /**
     * Permit redirects whose (scheme, host, port) differ from the original
     * request. Default: {@code false}. Setting this to {@code true} is a
     * deliberate security trade-off — a DNS hijack or CDN takeover targeting
     * the original host can silently swap the verifier's keys via a 302 to
     * attacker-controlled infrastructure. Real OIDC providers rarely require
     * cross-origin redirects mid-fetch.
     */
    public Builder allowCrossOriginRedirects(boolean allow) {
      this.allowCrossOriginRedirects = allow;
      return this;
    }

    public Builder allowDuplicateJSONKeys(boolean allow) {
      this.allowDuplicateJSONKeys = allow;
      return this;
    }

    public FetchLimits build() {
      return new FetchLimits(this);
    }

    public Builder maxArrayElements(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxArrayElements must be > 0 but found [" + n + "]");
      this.maxArrayElements = n;
      return this;
    }

    public Builder maxNestingDepth(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxNestingDepth must be > 0 but found [" + n + "]");
      this.maxNestingDepth = n;
      return this;
    }

    public Builder maxNumberLength(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxNumberLength must be > 0 but found [" + n + "]");
      this.maxNumberLength = n;
      return this;
    }

    public Builder maxObjectMembers(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxObjectMembers must be > 0 but found [" + n + "]");
      this.maxObjectMembers = n;
      return this;
    }

    public Builder maxRedirects(int n) {
      if (n < 0) throw new IllegalArgumentException("maxRedirects must be >= 0 but found [" + n + "]");
      this.maxRedirects = n;
      return this;
    }

    public Builder maxResponseBytes(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxResponseBytes must be > 0; the response cap cannot be disabled");
      this.maxResponseBytes = n;
      return this;
    }
  }
}
```

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=FetchLimitsTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/FetchLimits.java src/test/java/org/lattejava/jwt/FetchLimitsTest.java
git commit -m "feat: add FetchLimits per-instance hardening config (spec §4)"
```

---

## Task 2: `HardenedJSON.parse(InputStream, FetchLimits)` (internal hardened-parse utility)

**Spec reference:** §5.2 (`parseJSON` migration to `internal/HardenedJSON`).

**Files:**
- Create: `src/main/java/org/lattejava/jwt/internal/HardenedJSON.java`
- Test: `src/test/java/org/lattejava/jwt/internal/HardenedJSONTest.java`

Replaces `JSONWebKeySetHelper.parseJSON` (lines 374-390 of `JSONWebKeySetHelper.java`). Reads the input stream fully and parses as a top-level JSON object using the `LatteJSONProcessor` constructor that takes hardening parameters. The function is package-private (used only by `JWKS` and `OpenIDConnect` internals).

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/internal/HardenedJSONTest.java`:

```java
/* MIT header */
package org.lattejava.jwt.internal;

import org.lattejava.jwt.FetchLimits;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;

public class HardenedJSONTest extends BaseTest {
  @Test
  public void parse_enforces_array_element_cap() {
    StringBuilder sb = new StringBuilder("{\"keys\":[");
    for (int i = 0; i < 5; i++) {
      if (i > 0) sb.append(',');
      sb.append("{}");
    }
    sb.append("]}");
    FetchLimits tight = FetchLimits.builder().maxArrayElements(3).build();
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(stream(sb.toString()), tight));
  }

  @Test
  public void parse_enforces_nesting_depth_cap() {
    String deep = "{\"a\":{\"b\":{\"c\":{\"d\":{}}}}}";
    FetchLimits tight = FetchLimits.builder().maxNestingDepth(2).build();
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(stream(deep), tight));
  }

  @Test
  public void parse_rejects_duplicate_keys_by_default() {
    String dup = "{\"k\":1,\"k\":2}";
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(stream(dup), FetchLimits.defaults()));
  }

  @Test
  public void parse_returns_top_level_object() throws Exception {
    Map<String, Object> map = HardenedJSON.parse(stream("{\"k\":\"v\",\"n\":3}"), FetchLimits.defaults());
    assertEquals(map.get("k"), "v");
    assertEquals(((Number) map.get("n")).intValue(), 3);
  }

  private ByteArrayInputStream stream(String s) {
    return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=HardenedJSONTest`
Expected: compilation failure — `HardenedJSON` does not exist.

- [ ] **Step 3: Implement `HardenedJSON`**

Create `src/main/java/org/lattejava/jwt/internal/HardenedJSON.java`:

```java
/* MIT header */
package org.lattejava.jwt.internal;

import org.lattejava.jwt.FetchLimits;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.LatteJSONProcessor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * Package-private hardened JSON parser for JWKS and OIDC discovery
 * responses. The caller supplies an {@link InputStream} that is already
 * wrapped with the per-hop response-byte cap (see
 * {@code AbstractHTTPHelper.LimitedInputStream}); this method enforces only
 * the in-memory parse-time caps. {@link JSONProcessingException} is the
 * single failure surface.
 */
public final class HardenedJSON {
  private HardenedJSON() {}

  /**
   * Read {@code is} fully and parse the bytes as a top-level JSON object
   * subject to the parser caps in {@code limits}.
   *
   * @throws JSONProcessingException if the bytes do not parse as a JSON
   *     object, if any cap is exceeded, or if the input stream raises an
   *     {@link IOException} while being drained
   */
  public static Map<String, Object> parse(InputStream is, FetchLimits limits) {
    LatteJSONProcessor processor = new LatteJSONProcessor(
        limits.maxNestingDepth(),
        limits.maxNumberLength(),
        limits.maxObjectMembers(),
        limits.maxArrayElements(),
        limits.allowDuplicateJSONKeys());
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int n;
      while ((n = is.read(buffer)) != -1) {
        out.write(buffer, 0, n);
      }
      return processor.deserialize(out.toByteArray());
    } catch (IOException e) {
      throw new JSONProcessingException("Failed to read response stream", e);
    }
  }
}
```

Note: `JSONProcessingException` already exists at `org.lattejava.jwt.JSONProcessingException`. The `LatteJSONProcessor(int, int, int, int, boolean)` constructor with hardening parameters is what `JSONWebKeySetHelper.parseJSON` uses today (line 375). Verify the constructor signature is what we want by reading `LatteJSONProcessor.java` first.

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=HardenedJSONTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/internal/HardenedJSON.java src/test/java/org/lattejava/jwt/internal/HardenedJSONTest.java
git commit -m "feat(internal): add HardenedJSON.parse for JWKS/discovery responses"
```

---

## Task 3: Same-origin redirect support in `AbstractHTTPHelper`

**Spec reference:** §3.7 (redirect policy).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/internal/http/AbstractHTTPHelper.java`
- Test: `src/test/java/org/lattejava/jwt/internal/http/AbstractHTTPHelperTest.java` (create)

Add a new `get(...)` overload that takes a `boolean sameOriginRedirectsOnly` parameter. Inside the redirect-following loop, when the flag is `true`, compare the (scheme, host, port) of the redirect target against the original request URL and throw the supplied exception if they differ. The existing overload's behavior is preserved for backwards compat during the migration; it gets removed in Task 15 once `JSONWebKeySetHelper` is gone.

The new overload's signature:

```java
protected static <T> T get(HttpURLConnection urlConnection,
    int maxResponseBytes, int maxRedirects, boolean sameOriginRedirectsOnly,
    BiFunction<HttpURLConnection, InputStream, T> consumer,
    BiFunction<String, Throwable, ? extends RuntimeException> exception)
```

Implementation: refactor the existing overload to call the new one with `sameOriginRedirectsOnly=false`. The new overload performs the origin comparison just before assigning `current = buildURLConnection(nextURL.toString(), ...)`. Origin = `(scheme, host, port)` after defaulting port (`getDefaultPort()` when explicit port is `-1`). Exception message format:

```
"Refusing cross-origin redirect from [<scheme>://<host>:<port>] to [<scheme>://<host>:<port>]"
```

Note both scopes:
- `protected` visibility is correct because all callers are subclasses of `AbstractHTTPHelper` (`JSONWebKeySetHelper`, `ServerMetaDataHelper`) — and after the migration, we will call it from `JWKS` and `OpenIDConnect`. Either keep `protected` and add a thin package-protected static facade in `internal.http` (e.g. `HTTPGet`), OR change to `static` package-private. Recommended: change `get` and `buildURLConnection` to package-private (drop `protected`) since `JWKS` and `OpenIDConnect` live in different packages but can route through a small package-private dispatcher. Easier: bump them to `public static` while we are mid-migration; revisit visibility in Task 15 cleanup.

For this task: bump `buildURLConnection` and the new `get` overload to `public static`. The old `get` overload stays `protected static` (still used by `JSONWebKeySetHelper` / `ServerMetaDataHelper` until they are deleted).

- [ ] **Step 1: Write the failing test**

Create `src/test/java/org/lattejava/jwt/internal/http/AbstractHTTPHelperTest.java`:

```java
/* MIT header */
package org.lattejava.jwt.internal.http;

import com.sun.net.httpserver.HttpServer;
import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class AbstractHTTPHelperTest extends BaseTest {
  @Test
  public void get_with_same_origin_only_allows_same_origin_redirects() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int port = server.getAddress().getPort();
    server.createContext("/redirect", ex -> {
      ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + port + "/target");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    server.createContext("/target", ex -> {
      byte[] body = "ok".getBytes();
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.start();
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/redirect").openConnection();
      String body = AbstractHTTPHelper.get(conn, 1024, 3, true,
          (c, is) -> readAll(is),
          IllegalStateException::new);
      assertEquals(body, "ok");
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void get_with_same_origin_only_rejects_cross_origin_redirect() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/redirect", ex -> {
      ex.getResponseHeaders().add("Location", "http://localhost:1/target");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    server.start();
    try {
      int port = server.getAddress().getPort();
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/redirect").openConnection();
      IllegalStateException ex = assertThrows(IllegalStateException.class,
          () -> AbstractHTTPHelper.get(conn, 1024, 3, true,
              (c, is) -> readAll(is),
              IllegalStateException::new));
      assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"),
          "Unexpected message: " + ex.getMessage());
      assertTrue(ex.getMessage().contains("127.0.0.1"));
      assertTrue(ex.getMessage().contains("localhost"));
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void get_without_same_origin_only_follows_cross_origin_redirect() throws Exception {
    // The existing overload (4-arg) has the legacy permissive behavior; verify
    // the new overload with sameOriginRedirectsOnly=false matches it.
    HttpServer src = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    HttpServer dst = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int srcPort = src.getAddress().getPort();
    int dstPort = dst.getAddress().getPort();
    src.createContext("/r", ex -> {
      ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + dstPort + "/t");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    dst.createContext("/t", ex -> {
      byte[] body = "ok".getBytes();
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    src.start();
    dst.start();
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + srcPort + "/r").openConnection();
      String body = AbstractHTTPHelper.get(conn, 1024, 3, false,
          (c, is) -> readAll(is),
          IllegalStateException::new);
      assertEquals(body, "ok");
    } finally {
      src.stop(0);
      dst.stop(0);
    }
  }

  private static String readAll(InputStream is) {
    try {
      return new String(is.readAllBytes());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=AbstractHTTPHelperTest`
Expected: compilation failure — the 6-arg `get` overload does not exist.

- [ ] **Step 3: Implement the new overload**

In `src/main/java/org/lattejava/jwt/internal/http/AbstractHTTPHelper.java`, change the visibility of `buildURLConnection` from `protected` to `public`. Refactor the existing `get(...)` to delegate to a new overload:

```java
public static <T> T get(HttpURLConnection urlConnection, int maxResponseBytes, int maxRedirects,
    BiFunction<HttpURLConnection, InputStream, T> consumer,
    BiFunction<String, Throwable, ? extends RuntimeException> exception) {
  return get(urlConnection, maxResponseBytes, maxRedirects, false, consumer, exception);
}

public static <T> T get(HttpURLConnection urlConnection, int maxResponseBytes, int maxRedirects,
    boolean sameOriginRedirectsOnly,
    BiFunction<HttpURLConnection, InputStream, T> consumer,
    BiFunction<String, Throwable, ? extends RuntimeException> exception) {
  if (maxResponseBytes <= 0) {
    throw new IllegalArgumentException("maxResponseBytes must be > 0; the response cap cannot be disabled");
  }
  HttpURLConnection current = urlConnection;
  String originalEndpoint = current.getURL().toString();
  URL originalURL = current.getURL();
  int redirectsFollowed = 0;
  while (true) {
    String endpoint = current.getURL().toString();
    try {
      current.setRequestMethod("GET");
    } catch (java.net.ProtocolException e) {
      throw exception.apply("Failed to prepare the request to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
    }
    current.setInstanceFollowRedirects(false);

    try {
      current.connect();
    } catch (IOException e) {
      throw exception.apply("Failed to connect to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
    }

    int status;
    try {
      status = current.getResponseCode();
    } catch (IOException e) {
      throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
    }

    if (status >= 300 && status <= 399 && status != 304 && status != 305 && status != 306) {
      if (redirectsFollowed >= maxRedirects) {
        throw new TooManyRedirectsException("Failed to make a request to [" + originalEndpoint + "] after exceeding maximum redirect count [" + maxRedirects + "]");
      }
      String location = current.getHeaderField("Location");
      if (location == null || location.isEmpty()) {
        throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]: status [" + status + "] returned without a Location header", null);
      }
      URL nextURL;
      try {
        nextURL = new URL(current.getURL(), location);
      } catch (IOException e) {
        throw exception.apply("Failed to parse redirect Location header [" + MessageSanitizer.forMessage(location) + "] from [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }
      if (sameOriginRedirectsOnly && !sameOrigin(originalURL, nextURL)) {
        throw exception.apply(
            "Refusing cross-origin redirect from [" + originString(originalURL) + "] to [" + originString(nextURL) + "]",
            null);
      }
      try {
        InputStream errorBody = current.getErrorStream();
        if (errorBody != null) {
          errorBody.close();
        }
      } catch (IOException ignored) {
      }
      current = buildURLConnection(nextURL.toString(), exception);
      redirectsFollowed++;
      continue;
    }

    if (status < 200 || status > 299) {
      Map<String, List<String>> headers;
      try {
        headers = current.getHeaderFields();
      } catch (RuntimeException ignored) {
        headers = Collections.emptyMap();
      }
      HTTPResponseException httpEx = new HTTPResponseException(status, headers);
      throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]: status code [" + status + "] returned", httpEx);
    }

    try (InputStream is = new LimitedInputStream(new BufferedInputStream(current.getInputStream()), maxResponseBytes)) {
      return consumer.apply(current, is);
    } catch (IOException e) {
      throw exception.apply("Failed to parse the response as JSON from [" + MessageSanitizer.forMessage(endpoint) + "]", e);
    }
  }
}

private static int effectivePort(URL url) {
  int p = url.getPort();
  return (p == -1) ? url.getDefaultPort() : p;
}

private static String originString(URL url) {
  return url.getProtocol() + "://" + url.getHost() + ":" + effectivePort(url);
}

private static boolean sameOrigin(URL a, URL b) {
  return a.getProtocol().equalsIgnoreCase(b.getProtocol())
      && a.getHost().equalsIgnoreCase(b.getHost())
      && effectivePort(a) == effectivePort(b);
}
```

Bump `buildURLConnection` from `protected static` to `public static` (callers in other packages — `JWKS`, `OpenIDConnect` — will use it directly).

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=AbstractHTTPHelperTest`
Expected: PASS. Also run the existing test suite to confirm no regressions: `latte test --jca`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/internal/http/AbstractHTTPHelper.java src/test/java/org/lattejava/jwt/internal/http/AbstractHTTPHelperTest.java
git commit -m "feat(http): add same-origin redirect option on AbstractHTTPHelper.get"
```

---

## Task 4: `OpenIDConnectException`

**Spec reference:** §1.3.

**Files:**
- Create: `src/main/java/org/lattejava/jwt/OpenIDConnectException.java`
- Test: covered indirectly by Task 6 tests.

A new `RuntimeException` for all discovery-fetch failures. **Does not** extend `JWTException` — the spec is explicit on this (discovery is not a JWT operation; mixing under `JWTException` would mislead `catch` blocks).

- [ ] **Step 1: Implement (no separate test file — covered in Task 6)**

Create `src/main/java/org/lattejava/jwt/OpenIDConnectException.java`:

```java
/* MIT header */
package org.lattejava.jwt;

/**
 * Thrown by {@link OpenIDConnect#discover(String)} and
 * {@link OpenIDConnect#discoverFromWellKnown(String)} for any discovery-fetch
 * failure: network error, non-2xx HTTP response, JSON parse error, missing
 * {@code jwks_uri} or {@code issuer} field, oversize response, redirect
 * overflow, cross-origin redirect rejection, and the OIDC Discovery 1.0 §4.3
 * issuer-equality mismatch.
 *
 * <p>Intentionally does <strong>not</strong> extend {@link JWTException}.
 * Discovery is a precursor to JWT verification, not a JWT operation. Putting
 * it under {@code JWTException} would mislead {@code catch} blocks targeting
 * JWT-specific failures.</p>
 */
public class OpenIDConnectException extends RuntimeException {
  public OpenIDConnectException(String message) {
    super(message);
  }

  public OpenIDConnectException(String message, Throwable cause) {
    super(message, cause);
  }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `latte build`
Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```bash
git add src/main/java/org/lattejava/jwt/OpenIDConnectException.java
git commit -m "feat: add OpenIDConnectException (RuntimeException, not JWTException)"
```

---

## Task 5: `OpenIDConnectConfiguration` POJO

**Spec reference:** §1 (entire section). Rev 3 typed surface; **no public `fromMap`**.

**Files:**
- Create: `src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java`
- Test: `src/test/java/org/lattejava/jwt/OpenIDConnectConfigurationTest.java`

This is the largest single file. Use `oauth2/AuthorizationServerMetaData.java` as the structural template (constructor → static `immutableCopy` → public accessors → `toSerializableMap` → `equals`/`hashCode`/`toJSON`/`toString` → `builder()` → `Builder`), but with the **rev-3 typed accessor list** (23 fields, NOT the 25+ fields from `AuthorizationServerMetaData`):

| Wire name (snake_case) | Accessor (camelCase, acronyms uppercase) | Type |
|---|---|---|
| `acr_values_supported` | `acrValuesSupported` | `List<String>` |
| `authorization_endpoint` | `authorizationEndpoint` | `String` |
| `claims_supported` | `claimsSupported` | `List<String>` |
| `code_challenge_methods_supported` | `codeChallengeMethodsSupported` | `List<String>` |
| `end_session_endpoint` | `endSessionEndpoint` | `String` |
| `grant_types_supported` | `grantTypesSupported` | `List<String>` |
| `id_token_signing_alg_values_supported` | `idTokenSigningAlgValuesSupported` | `List<String>` |
| `introspection_endpoint` | `introspectionEndpoint` | `String` |
| `issuer` | `issuer` | `String` |
| `jwks_uri` | `jwksURI` | `String` |
| `registration_endpoint` | `registrationEndpoint` | `String` |
| `request_parameter_supported` | `requestParameterSupported` | `Boolean` |
| `request_uri_parameter_supported` | `requestURIParameterSupported` | `Boolean` |
| `require_request_uri_registration` | `requireRequestURIRegistration` | `Boolean` |
| `response_modes_supported` | `responseModesSupported` | `List<String>` |
| `response_types_supported` | `responseTypesSupported` | `List<String>` |
| `revocation_endpoint` | `revocationEndpoint` | `String` |
| `scopes_supported` | `scopesSupported` | `List<String>` |
| `subject_types_supported` | `subjectTypesSupported` | `List<String>` |
| `token_endpoint` | `tokenEndpoint` | `String` |
| `token_endpoint_auth_methods_supported` | `tokenEndpointAuthMethodsSupported` | `List<String>` |
| `token_endpoint_auth_signing_alg_values_supported` | `tokenEndpointAuthSigningAlgValuesSupported` | `List<String>` |
| `userinfo_endpoint` | `userinfoEndpoint` | `String` |

Plus `otherClaims() : Map<String, Object>` for everything else (encryption fields, i18n, informational links, session-management, front/back-channel logout, introspection/revocation auth-method sublists — all of these go to `otherClaims`).

**Key rev-3 differences from `AuthorizationServerMetaData`:**
- No public `fromMap(Map)` factory. The library's only network entry point is `OpenIDConnect.discover(...)` (Task 6). Applications that already parsed JSON elsewhere construct via `builder()`.
- Acronym casing fixed: `jwksURI` (not `jwksUri`), `requestURIParameterSupported`, `requireRequestURIRegistration`.
- `toSerializableMap()` and `toJSON()` omit null-valued typed fields (no `"key": null`).
- `toSerializableMap()` flattens `otherClaims()` to top-level alongside typed fields. Typed and `otherClaims` cannot share a key (the `Builder.claim(...)` method enforces this).
- `toString()` returns `toJSON()`.

**Internal helper for Task 6:** add a **package-private** static `static OpenIDConnectConfiguration fromMap(Map<String, Object> map)` that walks the map and routes recognized keys to typed setters, unrecognized keys to `Builder.claim(...)`. This is *not* part of the public API; it exists so `OpenIDConnect.discover` (same package, `org.lattejava.jwt`) can use it. Mark it package-private (no `public`).

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/OpenIDConnectConfigurationTest.java`:

```java
/* MIT header */
package org.lattejava.jwt;

import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class OpenIDConnectConfigurationTest extends BaseTest {
  @Test
  public void builder_is_reusable_independent_collections() {
    OpenIDConnectConfiguration.Builder b = OpenIDConnectConfiguration.builder().issuer("a");
    OpenIDConnectConfiguration first = b.build();
    OpenIDConnectConfiguration second = b.issuer("b").build();
    assertEquals(first.issuer(), "a");
    assertEquals(second.issuer(), "b");
  }

  @Test
  public void claim_rejects_typed_field_keys() {
    OpenIDConnectConfiguration.Builder b = OpenIDConnectConfiguration.builder();
    assertThrows(IllegalArgumentException.class, () -> b.claim("issuer", "x"));
    assertThrows(IllegalArgumentException.class, () -> b.claim("jwks_uri", "x"));
    assertThrows(IllegalArgumentException.class, () -> b.claim("token_endpoint", "x"));
  }

  @Test
  public void equals_and_hashCode() {
    OpenIDConnectConfiguration a = OpenIDConnectConfiguration.builder().issuer("x").build();
    OpenIDConnectConfiguration b = OpenIDConnectConfiguration.builder().issuer("x").build();
    OpenIDConnectConfiguration c = OpenIDConnectConfiguration.builder().issuer("y").build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertFalse(a.equals(c));
  }

  @Test
  public void list_accessors_return_unmodifiable_views() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .scopesSupported(List.of("openid", "profile"))
        .build();
    assertThrows(UnsupportedOperationException.class, () -> cfg.scopesSupported().add("email"));
  }

  @Test
  public void otherClaims_returns_unmodifiable_view() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .claim("mfa_challenge_endpoint", "https://example.com/mfa")
        .build();
    assertThrows(UnsupportedOperationException.class, () -> cfg.otherClaims().put("x", "y"));
  }

  @Test
  public void toJSON_round_trip_via_LatteJSONProcessor() throws Exception {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("https://example.com")
        .jwksURI("https://example.com/.well-known/jwks.json")
        .responseTypesSupported(List.of("code", "id_token"))
        .requireRequestURIRegistration(true)
        .claim("mfa_challenge_endpoint", "https://example.com/mfa")
        .build();
    String json = cfg.toJSON();
    Map<String, Object> reparsed = new LatteJSONProcessor().deserialize(json.getBytes());
    assertEquals(reparsed.get("issuer"), "https://example.com");
    assertEquals(reparsed.get("jwks_uri"), "https://example.com/.well-known/jwks.json");
    assertEquals(reparsed.get("require_request_uri_registration"), true);
    assertEquals(reparsed.get("mfa_challenge_endpoint"), "https://example.com/mfa");
    // unset typed fields are absent from the JSON, not present-with-null
    assertFalse(reparsed.containsKey("token_endpoint"));
  }

  @Test
  public void toSerializableMap_flattens_otherClaims_to_top_level() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("x")
        .claim("vendor_extension", 42)
        .build();
    Map<String, Object> map = cfg.toSerializableMap();
    assertEquals(map.get("issuer"), "x");
    assertEquals(map.get("vendor_extension"), 42);
  }

  @Test
  public void toSerializableMap_omits_null_typed_fields() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").build();
    Map<String, Object> map = cfg.toSerializableMap();
    assertTrue(map.containsKey("issuer"));
    assertFalse(map.containsKey("token_endpoint"));
    assertFalse(map.containsKey("jwks_uri"));
  }

  @Test
  public void toString_equals_toJSON() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").build();
    assertEquals(cfg.toString(), cfg.toJSON());
  }

  @Test
  public void typed_accessors_round_trip_through_builder() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .acrValuesSupported(List.of("0"))
        .authorizationEndpoint("https://example.com/auth")
        .claimsSupported(List.of("sub"))
        .codeChallengeMethodsSupported(List.of("S256"))
        .endSessionEndpoint("https://example.com/logout")
        .grantTypesSupported(List.of("authorization_code"))
        .idTokenSigningAlgValuesSupported(List.of("RS256"))
        .introspectionEndpoint("https://example.com/introspect")
        .issuer("https://example.com")
        .jwksURI("https://example.com/jwks")
        .registrationEndpoint("https://example.com/register")
        .requestParameterSupported(false)
        .requestURIParameterSupported(true)
        .requireRequestURIRegistration(false)
        .responseModesSupported(List.of("query"))
        .responseTypesSupported(List.of("code"))
        .revocationEndpoint("https://example.com/revoke")
        .scopesSupported(List.of("openid"))
        .subjectTypesSupported(List.of("public"))
        .tokenEndpoint("https://example.com/token")
        .tokenEndpointAuthMethodsSupported(List.of("client_secret_basic"))
        .tokenEndpointAuthSigningAlgValuesSupported(List.of("RS256"))
        .userinfoEndpoint("https://example.com/userinfo")
        .build();
    assertEquals(cfg.acrValuesSupported(), List.of("0"));
    assertEquals(cfg.authorizationEndpoint(), "https://example.com/auth");
    assertEquals(cfg.claimsSupported(), List.of("sub"));
    assertEquals(cfg.codeChallengeMethodsSupported(), List.of("S256"));
    assertEquals(cfg.endSessionEndpoint(), "https://example.com/logout");
    assertEquals(cfg.grantTypesSupported(), List.of("authorization_code"));
    assertEquals(cfg.idTokenSigningAlgValuesSupported(), List.of("RS256"));
    assertEquals(cfg.introspectionEndpoint(), "https://example.com/introspect");
    assertEquals(cfg.issuer(), "https://example.com");
    assertEquals(cfg.jwksURI(), "https://example.com/jwks");
    assertEquals(cfg.registrationEndpoint(), "https://example.com/register");
    assertEquals(cfg.requestParameterSupported(), Boolean.FALSE);
    assertEquals(cfg.requestURIParameterSupported(), Boolean.TRUE);
    assertEquals(cfg.requireRequestURIRegistration(), Boolean.FALSE);
    assertEquals(cfg.responseModesSupported(), List.of("query"));
    assertEquals(cfg.responseTypesSupported(), List.of("code"));
    assertEquals(cfg.revocationEndpoint(), "https://example.com/revoke");
    assertEquals(cfg.scopesSupported(), List.of("openid"));
    assertEquals(cfg.subjectTypesSupported(), List.of("public"));
    assertEquals(cfg.tokenEndpoint(), "https://example.com/token");
    assertEquals(cfg.tokenEndpointAuthMethodsSupported(), List.of("client_secret_basic"));
    assertEquals(cfg.tokenEndpointAuthSigningAlgValuesSupported(), List.of("RS256"));
    assertEquals(cfg.userinfoEndpoint(), "https://example.com/userinfo");
  }

  @Test
  public void unset_typed_accessors_return_null() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().build();
    assertNull(cfg.issuer());
    assertNull(cfg.jwksURI());
    assertNull(cfg.scopesSupported());
    assertNull(cfg.requestParameterSupported());
    assertNotNull(cfg.otherClaims());
    assertTrue(cfg.otherClaims().isEmpty());
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=OpenIDConnectConfigurationTest`
Expected: compilation failure — `OpenIDConnectConfiguration` does not exist.

- [ ] **Step 3: Implement `OpenIDConnectConfiguration`**

Create `src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java`:

Structure (full file, alphabetized fields and accessors):

```java
/* MIT header */
package org.lattejava.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Models the commonly-deployed subset of OpenID Connect Discovery 1.0 Provider
 * Metadata and RFC 8414 Authorization Server Metadata. Every typed field is
 * nullable — a pure-OAuth response will have null OIDC-specific fields, and
 * an OIDC response without RFC 8414 extras will have null introspection /
 * revocation fields.
 *
 * <p>The typed surface is deliberately a subset, not a superset, of the full
 * metadata. Promoting an {@link #otherClaims()} key to a typed accessor in a
 * future 7.x release is a non-breaking addition. Construct via
 * {@link #builder()}; the only network entry point is
 * {@link OpenIDConnect#discover(String)} /
 * {@link OpenIDConnect#discoverFromWellKnown(String)}.</p>
 *
 * <p>Instances are immutable. List-typed accessors and {@link #otherClaims()}
 * return unmodifiable views.</p>
 */
public final class OpenIDConnectConfiguration {
  private static final Set<String> REGISTERED = new HashSet<>(Arrays.asList(
      "acr_values_supported",
      "authorization_endpoint",
      "claims_supported",
      "code_challenge_methods_supported",
      "end_session_endpoint",
      "grant_types_supported",
      "id_token_signing_alg_values_supported",
      "introspection_endpoint",
      "issuer",
      "jwks_uri",
      "registration_endpoint",
      "request_parameter_supported",
      "request_uri_parameter_supported",
      "require_request_uri_registration",
      "response_modes_supported",
      "response_types_supported",
      "revocation_endpoint",
      "scopes_supported",
      "subject_types_supported",
      "token_endpoint",
      "token_endpoint_auth_methods_supported",
      "token_endpoint_auth_signing_alg_values_supported",
      "userinfo_endpoint"
  ));
  private final List<String> acrValuesSupported;
  private final String authorizationEndpoint;
  private final List<String> claimsSupported;
  private final List<String> codeChallengeMethodsSupported;
  private final String endSessionEndpoint;
  private final List<String> grantTypesSupported;
  private final List<String> idTokenSigningAlgValuesSupported;
  private final String introspectionEndpoint;
  private final String issuer;
  private final String jwksURI;
  private final Map<String, Object> otherClaims;
  private final String registrationEndpoint;
  private final Boolean requestParameterSupported;
  private final Boolean requestURIParameterSupported;
  private final Boolean requireRequestURIRegistration;
  private final List<String> responseModesSupported;
  private final List<String> responseTypesSupported;
  private final String revocationEndpoint;
  private final List<String> scopesSupported;
  private final List<String> subjectTypesSupported;
  private final String tokenEndpoint;
  private final List<String> tokenEndpointAuthMethodsSupported;
  private final List<String> tokenEndpointAuthSigningAlgValuesSupported;
  private final String userinfoEndpoint;

  private OpenIDConnectConfiguration(Builder b) {
    this.acrValuesSupported = immutableCopy(b.acrValuesSupported);
    this.authorizationEndpoint = b.authorizationEndpoint;
    this.claimsSupported = immutableCopy(b.claimsSupported);
    this.codeChallengeMethodsSupported = immutableCopy(b.codeChallengeMethodsSupported);
    this.endSessionEndpoint = b.endSessionEndpoint;
    this.grantTypesSupported = immutableCopy(b.grantTypesSupported);
    this.idTokenSigningAlgValuesSupported = immutableCopy(b.idTokenSigningAlgValuesSupported);
    this.introspectionEndpoint = b.introspectionEndpoint;
    this.issuer = b.issuer;
    this.jwksURI = b.jwksURI;
    this.otherClaims = Collections.unmodifiableMap(new LinkedHashMap<>(b.otherClaims));
    this.registrationEndpoint = b.registrationEndpoint;
    this.requestParameterSupported = b.requestParameterSupported;
    this.requestURIParameterSupported = b.requestURIParameterSupported;
    this.requireRequestURIRegistration = b.requireRequestURIRegistration;
    this.responseModesSupported = immutableCopy(b.responseModesSupported);
    this.responseTypesSupported = immutableCopy(b.responseTypesSupported);
    this.revocationEndpoint = b.revocationEndpoint;
    this.scopesSupported = immutableCopy(b.scopesSupported);
    this.subjectTypesSupported = immutableCopy(b.subjectTypesSupported);
    this.tokenEndpoint = b.tokenEndpoint;
    this.tokenEndpointAuthMethodsSupported = immutableCopy(b.tokenEndpointAuthMethodsSupported);
    this.tokenEndpointAuthSigningAlgValuesSupported = immutableCopy(b.tokenEndpointAuthSigningAlgValuesSupported);
    this.userinfoEndpoint = b.userinfoEndpoint;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Package-private routing helper used by {@link OpenIDConnect#discover(String)}.
   * Walks {@code map} dispatching recognized snake_case keys to typed setters
   * and unrecognized keys to {@link Builder#claim(String, Object)}. Rejects a
   * non-string element in any string-array typed field with
   * {@link IllegalArgumentException}.
   */
  static OpenIDConnectConfiguration fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) continue;
      switch (name) {
        case "acr_values_supported": b.acrValuesSupported = stringList(value, name); break;
        case "authorization_endpoint": b.authorizationEndpoint = value.toString(); break;
        case "claims_supported": b.claimsSupported = stringList(value, name); break;
        case "code_challenge_methods_supported": b.codeChallengeMethodsSupported = stringList(value, name); break;
        case "end_session_endpoint": b.endSessionEndpoint = value.toString(); break;
        case "grant_types_supported": b.grantTypesSupported = stringList(value, name); break;
        case "id_token_signing_alg_values_supported": b.idTokenSigningAlgValuesSupported = stringList(value, name); break;
        case "introspection_endpoint": b.introspectionEndpoint = value.toString(); break;
        case "issuer": b.issuer = value.toString(); break;
        case "jwks_uri": b.jwksURI = value.toString(); break;
        case "registration_endpoint": b.registrationEndpoint = value.toString(); break;
        case "request_parameter_supported": b.requestParameterSupported = bool(value, name); break;
        case "request_uri_parameter_supported": b.requestURIParameterSupported = bool(value, name); break;
        case "require_request_uri_registration": b.requireRequestURIRegistration = bool(value, name); break;
        case "response_modes_supported": b.responseModesSupported = stringList(value, name); break;
        case "response_types_supported": b.responseTypesSupported = stringList(value, name); break;
        case "revocation_endpoint": b.revocationEndpoint = value.toString(); break;
        case "scopes_supported": b.scopesSupported = stringList(value, name); break;
        case "subject_types_supported": b.subjectTypesSupported = stringList(value, name); break;
        case "token_endpoint": b.tokenEndpoint = value.toString(); break;
        case "token_endpoint_auth_methods_supported": b.tokenEndpointAuthMethodsSupported = stringList(value, name); break;
        case "token_endpoint_auth_signing_alg_values_supported": b.tokenEndpointAuthSigningAlgValuesSupported = stringList(value, name); break;
        case "userinfo_endpoint": b.userinfoEndpoint = value.toString(); break;
        default: b.otherClaims.put(name, value); break;
      }
    }
    return b.build();
  }

  private static Boolean bool(Object value, String name) {
    if (value instanceof Boolean bv) return bv;
    throw new IllegalArgumentException("Discovery field [" + name + "] must be a boolean");
  }

  private static List<String> immutableCopy(List<String> list) {
    return list == null ? null : List.copyOf(list);
  }

  private static List<String> stringList(Object value, String name) {
    if (!(value instanceof List<?> list)) {
      throw new IllegalArgumentException("Discovery field [" + name + "] must be an array of strings");
    }
    List<String> result = new ArrayList<>();
    for (Object element : list) {
      if (!(element instanceof String s)) {
        throw new IllegalArgumentException("Discovery field [" + name + "] must be an array of strings");
      }
      result.add(s);
    }
    return result;
  }

  private static void putIfPresent(Map<String, Object> out, String key, Object value) {
    if (value != null) out.put(key, value);
  }

  public List<String> acrValuesSupported() { return acrValuesSupported; }
  public String authorizationEndpoint() { return authorizationEndpoint; }
  public List<String> claimsSupported() { return claimsSupported; }
  public List<String> codeChallengeMethodsSupported() { return codeChallengeMethodsSupported; }
  public String endSessionEndpoint() { return endSessionEndpoint; }
  public List<String> grantTypesSupported() { return grantTypesSupported; }
  public List<String> idTokenSigningAlgValuesSupported() { return idTokenSigningAlgValuesSupported; }
  public String introspectionEndpoint() { return introspectionEndpoint; }
  public String issuer() { return issuer; }
  public String jwksURI() { return jwksURI; }
  public Map<String, Object> otherClaims() { return otherClaims; }
  public String registrationEndpoint() { return registrationEndpoint; }
  public Boolean requestParameterSupported() { return requestParameterSupported; }
  public Boolean requestURIParameterSupported() { return requestURIParameterSupported; }
  public Boolean requireRequestURIRegistration() { return requireRequestURIRegistration; }
  public List<String> responseModesSupported() { return responseModesSupported; }
  public List<String> responseTypesSupported() { return responseTypesSupported; }
  public String revocationEndpoint() { return revocationEndpoint; }
  public List<String> scopesSupported() { return scopesSupported; }
  public List<String> subjectTypesSupported() { return subjectTypesSupported; }
  public String tokenEndpoint() { return tokenEndpoint; }
  public List<String> tokenEndpointAuthMethodsSupported() { return tokenEndpointAuthMethodsSupported; }
  public List<String> tokenEndpointAuthSigningAlgValuesSupported() { return tokenEndpointAuthSigningAlgValuesSupported; }
  public String userinfoEndpoint() { return userinfoEndpoint; }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof OpenIDConnectConfiguration that)) return false;
    return Objects.equals(acrValuesSupported, that.acrValuesSupported)
        && Objects.equals(authorizationEndpoint, that.authorizationEndpoint)
        && Objects.equals(claimsSupported, that.claimsSupported)
        && Objects.equals(codeChallengeMethodsSupported, that.codeChallengeMethodsSupported)
        && Objects.equals(endSessionEndpoint, that.endSessionEndpoint)
        && Objects.equals(grantTypesSupported, that.grantTypesSupported)
        && Objects.equals(idTokenSigningAlgValuesSupported, that.idTokenSigningAlgValuesSupported)
        && Objects.equals(introspectionEndpoint, that.introspectionEndpoint)
        && Objects.equals(issuer, that.issuer)
        && Objects.equals(jwksURI, that.jwksURI)
        && Objects.equals(otherClaims, that.otherClaims)
        && Objects.equals(registrationEndpoint, that.registrationEndpoint)
        && Objects.equals(requestParameterSupported, that.requestParameterSupported)
        && Objects.equals(requestURIParameterSupported, that.requestURIParameterSupported)
        && Objects.equals(requireRequestURIRegistration, that.requireRequestURIRegistration)
        && Objects.equals(responseModesSupported, that.responseModesSupported)
        && Objects.equals(responseTypesSupported, that.responseTypesSupported)
        && Objects.equals(revocationEndpoint, that.revocationEndpoint)
        && Objects.equals(scopesSupported, that.scopesSupported)
        && Objects.equals(subjectTypesSupported, that.subjectTypesSupported)
        && Objects.equals(tokenEndpoint, that.tokenEndpoint)
        && Objects.equals(tokenEndpointAuthMethodsSupported, that.tokenEndpointAuthMethodsSupported)
        && Objects.equals(tokenEndpointAuthSigningAlgValuesSupported, that.tokenEndpointAuthSigningAlgValuesSupported)
        && Objects.equals(userinfoEndpoint, that.userinfoEndpoint);
  }

  @Override
  public int hashCode() {
    return Objects.hash(acrValuesSupported, authorizationEndpoint, claimsSupported,
        codeChallengeMethodsSupported, endSessionEndpoint, grantTypesSupported,
        idTokenSigningAlgValuesSupported, introspectionEndpoint, issuer, jwksURI,
        otherClaims, registrationEndpoint, requestParameterSupported,
        requestURIParameterSupported, requireRequestURIRegistration,
        responseModesSupported, responseTypesSupported, revocationEndpoint,
        scopesSupported, subjectTypesSupported, tokenEndpoint,
        tokenEndpointAuthMethodsSupported, tokenEndpointAuthSigningAlgValuesSupported,
        userinfoEndpoint);
  }

  public String toJSON() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  /**
   * Map suitable for JSON serialization. Typed fields with non-null values
   * appear under their snake_case names; entries from {@link #otherClaims()}
   * are flattened to top-level alongside the typed fields.
   */
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    putIfPresent(out, "acr_values_supported", acrValuesSupported);
    putIfPresent(out, "authorization_endpoint", authorizationEndpoint);
    putIfPresent(out, "claims_supported", claimsSupported);
    putIfPresent(out, "code_challenge_methods_supported", codeChallengeMethodsSupported);
    putIfPresent(out, "end_session_endpoint", endSessionEndpoint);
    putIfPresent(out, "grant_types_supported", grantTypesSupported);
    putIfPresent(out, "id_token_signing_alg_values_supported", idTokenSigningAlgValuesSupported);
    putIfPresent(out, "introspection_endpoint", introspectionEndpoint);
    putIfPresent(out, "issuer", issuer);
    putIfPresent(out, "jwks_uri", jwksURI);
    putIfPresent(out, "registration_endpoint", registrationEndpoint);
    putIfPresent(out, "request_parameter_supported", requestParameterSupported);
    putIfPresent(out, "request_uri_parameter_supported", requestURIParameterSupported);
    putIfPresent(out, "require_request_uri_registration", requireRequestURIRegistration);
    putIfPresent(out, "response_modes_supported", responseModesSupported);
    putIfPresent(out, "response_types_supported", responseTypesSupported);
    putIfPresent(out, "revocation_endpoint", revocationEndpoint);
    putIfPresent(out, "scopes_supported", scopesSupported);
    putIfPresent(out, "subject_types_supported", subjectTypesSupported);
    putIfPresent(out, "token_endpoint", tokenEndpoint);
    putIfPresent(out, "token_endpoint_auth_methods_supported", tokenEndpointAuthMethodsSupported);
    putIfPresent(out, "token_endpoint_auth_signing_alg_values_supported", tokenEndpointAuthSigningAlgValuesSupported);
    putIfPresent(out, "userinfo_endpoint", userinfoEndpoint);
    for (Map.Entry<String, Object> e : otherClaims.entrySet()) {
      if (e.getValue() != null) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  @Override
  public String toString() {
    return toJSON();
  }

  /**
   * Reusable, mutable builder. Each {@link #build()} returns a fresh
   * immutable {@link OpenIDConnectConfiguration} with independent collection
   * copies.
   */
  public static final class Builder {
    List<String> acrValuesSupported;
    String authorizationEndpoint;
    List<String> claimsSupported;
    List<String> codeChallengeMethodsSupported;
    String endSessionEndpoint;
    List<String> grantTypesSupported;
    List<String> idTokenSigningAlgValuesSupported;
    String introspectionEndpoint;
    String issuer;
    String jwksURI;
    final Map<String, Object> otherClaims = new LinkedHashMap<>();
    String registrationEndpoint;
    Boolean requestParameterSupported;
    Boolean requestURIParameterSupported;
    Boolean requireRequestURIRegistration;
    List<String> responseModesSupported;
    List<String> responseTypesSupported;
    String revocationEndpoint;
    List<String> scopesSupported;
    List<String> subjectTypesSupported;
    String tokenEndpoint;
    List<String> tokenEndpointAuthMethodsSupported;
    List<String> tokenEndpointAuthSigningAlgValuesSupported;
    String userinfoEndpoint;

    private Builder() {}

    public Builder acrValuesSupported(List<String> v) { this.acrValuesSupported = v; return this; }
    public Builder authorizationEndpoint(String v) { this.authorizationEndpoint = v; return this; }
    public OpenIDConnectConfiguration build() { return new OpenIDConnectConfiguration(this); }
    public Builder claim(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (REGISTERED.contains(name)) {
        throw new IllegalArgumentException("Cannot add a typed discovery field [" + name + "] via claim(); use the typed setter");
      }
      otherClaims.put(name, value);
      return this;
    }
    public Builder claimsSupported(List<String> v) { this.claimsSupported = v; return this; }
    public Builder codeChallengeMethodsSupported(List<String> v) { this.codeChallengeMethodsSupported = v; return this; }
    public Builder endSessionEndpoint(String v) { this.endSessionEndpoint = v; return this; }
    public Builder grantTypesSupported(List<String> v) { this.grantTypesSupported = v; return this; }
    public Builder idTokenSigningAlgValuesSupported(List<String> v) { this.idTokenSigningAlgValuesSupported = v; return this; }
    public Builder introspectionEndpoint(String v) { this.introspectionEndpoint = v; return this; }
    public Builder issuer(String v) { this.issuer = v; return this; }
    public Builder jwksURI(String v) { this.jwksURI = v; return this; }
    public Builder registrationEndpoint(String v) { this.registrationEndpoint = v; return this; }
    public Builder requestParameterSupported(Boolean v) { this.requestParameterSupported = v; return this; }
    public Builder requestURIParameterSupported(Boolean v) { this.requestURIParameterSupported = v; return this; }
    public Builder requireRequestURIRegistration(Boolean v) { this.requireRequestURIRegistration = v; return this; }
    public Builder responseModesSupported(List<String> v) { this.responseModesSupported = v; return this; }
    public Builder responseTypesSupported(List<String> v) { this.responseTypesSupported = v; return this; }
    public Builder revocationEndpoint(String v) { this.revocationEndpoint = v; return this; }
    public Builder scopesSupported(List<String> v) { this.scopesSupported = v; return this; }
    public Builder subjectTypesSupported(List<String> v) { this.subjectTypesSupported = v; return this; }
    public Builder tokenEndpoint(String v) { this.tokenEndpoint = v; return this; }
    public Builder tokenEndpointAuthMethodsSupported(List<String> v) { this.tokenEndpointAuthMethodsSupported = v; return this; }
    public Builder tokenEndpointAuthSigningAlgValuesSupported(List<String> v) { this.tokenEndpointAuthSigningAlgValuesSupported = v; return this; }
    public Builder userinfoEndpoint(String v) { this.userinfoEndpoint = v; return this; }
  }
}
```

Builder field package-private (drop `private`) so the `fromMap` static factory in the same outer class can write directly to them.

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=OpenIDConnectConfigurationTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java src/test/java/org/lattejava/jwt/OpenIDConnectConfigurationTest.java
git commit -m "feat: add OpenIDConnectConfiguration POJO (spec §1, rev 3 typed surface)"
```

---

## Task 6: `OpenIDConnect.discover` / `discoverFromWellKnown`

**Spec reference:** §2 (entry points + issuer-equality validation + trailing-slash normalization).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/OpenIDConnect.java`
- Test: `src/test/java/org/lattejava/jwt/OpenIDConnectDiscoverTest.java` (create)

Add the eight discover overloads to the existing `OpenIDConnect` class (alongside `at_hash` / `c_hash`). All paths funnel through one private `doDiscover(String url, String expectedIssuer, FetchLimits limits, Consumer<HttpURLConnection> customizer)` method.

**Issuer-equality validation (§2):** when `expectedIssuer != null`, compare `cfg.issuer()` to `expectedIssuer` after stripping a single trailing slash from each side. Mismatch → `OpenIDConnectException`. The `discover(issuer)` overloads pass the original (untrimmed) issuer string as `expectedIssuer`. The `discoverFromWellKnown(url)` overloads pass `null` (no issuer to compare against; documented security downgrade).

**Failure modes:** all of these throw `OpenIDConnectException` (and *only* that — never wrap into `JWKSFetchException` and never let `JSONProcessingException` escape):
- network failure / connect timeout / read timeout
- non-2xx HTTP status
- redirect overflow / cross-origin redirect rejection / oversize response
- JSON parse failure
- response missing `issuer` (the spec is implicit — `OpenIDConnect.discover(issuer)` cannot validate `expectedIssuer` if the response has no `issuer` field; treat absent `issuer` as a §4.3 violation)
- response missing `jwks_uri` (Discovery 1.0 REQUIRED field)
- issuer-equality mismatch

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/OpenIDConnectDiscoverTest.java`. Use `com.sun.net.httpserver.HttpServer` for fixtures (see `JWKSourceTest` for the existing pattern). Cover:

```java
/* MIT header */
package org.lattejava.jwt;

import com.sun.net.httpserver.HttpServer;
import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class OpenIDConnectDiscoverTest extends BaseTest {
  private HttpServer server;
  private String baseURL;

  @BeforeMethod
  public void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.start();
    baseURL = "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @AfterMethod
  public void stop() {
    if (server != null) server.stop(0);
  }

  @Test
  public void discover_appends_well_known_path_and_strips_trailing_slash_from_issuer() {
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    OpenIDConnectConfiguration cfg = OpenIDConnect.discover(baseURL + "/");
    assertEquals(cfg.issuer(), baseURL);
    assertEquals(cfg.jwksURI(), baseURL + "/jwks");
  }

  @Test
  public void discover_passes_response_through_typed_routing() {
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\","
        + "\"response_types_supported\":[\"code\",\"id_token\"],"
        + "\"mfa_challenge_endpoint\":\"" + baseURL + "/mfa\"}");
    OpenIDConnectConfiguration cfg = OpenIDConnect.discover(baseURL);
    assertEquals(cfg.responseTypesSupported(), java.util.List.of("code", "id_token"));
    assertEquals(cfg.otherClaims().get("mfa_challenge_endpoint"), baseURL + "/mfa");
  }

  @Test
  public void discover_rejects_issuer_equality_mismatch() {
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"https://attacker.example\",\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    OpenIDConnectException ex = assertThrows(OpenIDConnectException.class,
        () -> OpenIDConnect.discover(baseURL));
    assertTrue(ex.getMessage().contains("issuer"));
    assertTrue(ex.getMessage().contains("attacker.example"));
  }

  @Test
  public void discover_normalizes_trailing_slash_on_both_sides_of_issuer_check() {
    // Input issuer has trailing slash; response issuer has no trailing slash.
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    OpenIDConnect.discover(baseURL + "/");

    // Input issuer has no slash; response issuer has trailing slash.
    serveDiscovery("/x/.well-known/openid-configuration",
        "{\"issuer\":\"" + baseURL + "/x/\",\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    OpenIDConnect.discover(baseURL + "/x");
  }

  @Test
  public void discover_throws_when_issuer_field_is_missing() {
    serveDiscovery("/.well-known/openid-configuration",
        "{\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    assertThrows(OpenIDConnectException.class, () -> OpenIDConnect.discover(baseURL));
  }

  @Test
  public void discoverFromWellKnown_does_not_validate_issuer_equality() {
    // Response issuer differs from URL host — discoverFromWellKnown is a documented downgrade.
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"https://elsewhere.example\",\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    OpenIDConnectConfiguration cfg = OpenIDConnect.discoverFromWellKnown(baseURL + "/.well-known/openid-configuration");
    assertEquals(cfg.issuer(), "https://elsewhere.example");
  }

  @Test
  public void discoverFromWellKnown_throws_on_missing_jwks_uri() {
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"" + baseURL + "\"}");
    OpenIDConnectException ex = assertThrows(OpenIDConnectException.class,
        () -> OpenIDConnect.discoverFromWellKnown(baseURL + "/.well-known/openid-configuration"));
    assertTrue(ex.getMessage().contains("jwks_uri"));
  }

  @Test
  public void discover_throws_OpenIDConnectException_on_non_2xx() {
    server.createContext("/.well-known/openid-configuration", ex -> {
      ex.sendResponseHeaders(500, -1);
      ex.close();
    });
    assertThrows(OpenIDConnectException.class, () -> OpenIDConnect.discover(baseURL));
  }

  @Test
  public void discover_throws_OpenIDConnectException_on_unparseable_body() {
    serveDiscovery("/.well-known/openid-configuration", "not-json");
    assertThrows(OpenIDConnectException.class, () -> OpenIDConnect.discover(baseURL));
  }

  @Test
  public void discover_enforces_response_byte_cap_via_FetchLimits() {
    StringBuilder big = new StringBuilder("{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/j\",\"x\":\"");
    for (int i = 0; i < 4096; i++) big.append('a');
    big.append("\"}");
    serveDiscovery("/.well-known/openid-configuration", big.toString());
    FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
    assertThrows(OpenIDConnectException.class, () -> OpenIDConnect.discover(baseURL, tight));
  }

  @Test
  public void discover_rejects_cross_origin_redirect_by_default() throws IOException {
    server.createContext("/.well-known/openid-configuration", ex -> {
      ex.getResponseHeaders().add("Location", "http://localhost:1/elsewhere");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    OpenIDConnectException ex = assertThrows(OpenIDConnectException.class,
        () -> OpenIDConnect.discover(baseURL));
    assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"),
        "Unexpected: " + ex.getMessage());
  }

  @Test
  public void discover_with_customizer_invokes_customizer_on_connection() {
    AtomicReference<HttpURLConnection> seen = new AtomicReference<>();
    serveDiscovery("/.well-known/openid-configuration",
        "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\"}");
    OpenIDConnect.discover(baseURL, conn -> {
      seen.set(conn);
      conn.setRequestProperty("X-Test", "yes");
    });
    assertNotNull(seen.get());
  }

  private void serveDiscovery(String path, String body) {
    server.removeContext(path); // safe even if absent (try/catch optional)
    // ...actually removeContext throws if absent; instead, only call createContext once per test.
  }
}
```

(Note: the `serveDiscovery` helper above needs care — `HttpServer.removeContext` throws if the context is absent. Adapt to either a Map of registered paths or `try { removeContext } catch { }` before `createContext`. Existing `JWKSourceTest` may already have a helper to reuse.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=OpenIDConnectDiscoverTest`
Expected: compilation failure — `OpenIDConnect.discover` does not exist.

- [ ] **Step 3: Implement the discover entry points**

In `src/main/java/org/lattejava/jwt/OpenIDConnect.java`, add the new imports and methods. Keep `at_hash` / `c_hash` and the existing private helpers untouched.

```java
// New imports:
import org.lattejava.jwt.internal.HardenedJSON;
import org.lattejava.jwt.internal.MessageSanitizer;
import org.lattejava.jwt.internal.http.AbstractHTTPHelper;

import java.net.HttpURLConnection;
import java.util.Map;
import java.util.function.Consumer;

// Add to the class body, after the existing static helpers:

public static OpenIDConnectConfiguration discover(String issuer) {
  return discover(issuer, FetchLimits.defaults(), null);
}

public static OpenIDConnectConfiguration discover(String issuer, Consumer<HttpURLConnection> customizer) {
  return discover(issuer, FetchLimits.defaults(), customizer);
}

public static OpenIDConnectConfiguration discover(String issuer, FetchLimits limits) {
  return discover(issuer, limits, null);
}

public static OpenIDConnectConfiguration discover(String issuer, FetchLimits limits, Consumer<HttpURLConnection> customizer) {
  Objects.requireNonNull(issuer, "issuer");
  Objects.requireNonNull(limits, "limits");
  String trimmed = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
  String url = trimmed + "/.well-known/openid-configuration";
  return doDiscover(url, issuer, limits, customizer);
}

public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL) {
  return discoverFromWellKnown(wellKnownURL, FetchLimits.defaults(), null);
}

public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL, Consumer<HttpURLConnection> customizer) {
  return discoverFromWellKnown(wellKnownURL, FetchLimits.defaults(), customizer);
}

public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL, FetchLimits limits) {
  return discoverFromWellKnown(wellKnownURL, limits, null);
}

public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL, FetchLimits limits, Consumer<HttpURLConnection> customizer) {
  Objects.requireNonNull(wellKnownURL, "wellKnownURL");
  Objects.requireNonNull(limits, "limits");
  return doDiscover(wellKnownURL, null, limits, customizer);
}

private static OpenIDConnectConfiguration doDiscover(String url, String expectedIssuer,
    FetchLimits limits, Consumer<HttpURLConnection> customizer) {
  HttpURLConnection connection = AbstractHTTPHelper.buildURLConnection(url,
      OpenIDConnectException::new);
  if (customizer != null) customizer.accept(connection);

  Map<String, Object> raw;
  try {
    raw = AbstractHTTPHelper.get(connection,
        limits.maxResponseBytes(),
        limits.maxRedirects(),
        !limits.allowCrossOriginRedirects(),
        (conn, is) -> HardenedJSON.parse(is, limits),
        OpenIDConnectException::new);
  } catch (OpenIDConnectException e) {
    throw e;
  } catch (RuntimeException e) {
    throw new OpenIDConnectException("Failed to fetch OIDC discovery document from [" + MessageSanitizer.forMessage(url) + "]", e);
  }

  OpenIDConnectConfiguration cfg;
  try {
    cfg = OpenIDConnectConfiguration.fromMap(raw);
  } catch (IllegalArgumentException e) {
    throw new OpenIDConnectException("Discovery document at [" + MessageSanitizer.forMessage(url) + "] is malformed: " + e.getMessage(), e);
  }

  if (cfg.jwksURI() == null || cfg.jwksURI().isEmpty()) {
    throw new OpenIDConnectException("Discovery document at [" + MessageSanitizer.forMessage(url) + "] is missing the [jwks_uri] field");
  }

  if (expectedIssuer != null) {
    if (cfg.issuer() == null || cfg.issuer().isEmpty()) {
      throw new OpenIDConnectException("Discovery document at [" + MessageSanitizer.forMessage(url) + "] is missing the [issuer] field");
    }
    String expectedTrim = expectedIssuer.endsWith("/") ? expectedIssuer.substring(0, expectedIssuer.length() - 1) : expectedIssuer;
    String actualTrim = cfg.issuer().endsWith("/") ? cfg.issuer().substring(0, cfg.issuer().length() - 1) : cfg.issuer();
    if (!expectedTrim.equals(actualTrim)) {
      throw new OpenIDConnectException("Discovery document issuer [" + MessageSanitizer.forMessage(cfg.issuer()) + "] does not match the expected issuer [" + MessageSanitizer.forMessage(expectedIssuer) + "]");
    }
  }

  return cfg;
}
```

Important Javadoc to add (sentence-case, keep concise):
- On `discover(String issuer, ...)`: note that the issuer-equality check (OIDC Discovery 1.0 §4.3) is enforced after a single-trailing-slash normalization on both sides.
- On `discoverFromWellKnown(String wellKnownURL, ...)`: note that no issuer-equality validation is performed — the caller has not supplied an expected issuer. Recommend `discover(issuer)` for OIDC. Mention this is the right entry point for an RFC 8414 server's `/.well-known/oauth-authorization-server` URL.
- On `FetchLimits.allowCrossOriginRedirects(true)`: this entry point also honors the flag. Cross-origin redirect → `OpenIDConnectException` by default.

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=OpenIDConnectDiscoverTest`
Expected: PASS. Also run `latte test --jca --test=OpenIDConnectTest` if it exists, to confirm `at_hash` / `c_hash` still pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/OpenIDConnect.java src/test/java/org/lattejava/jwt/OpenIDConnectDiscoverTest.java
git commit -m "feat: add OpenIDConnect.discover and discoverFromWellKnown (spec §2)"
```

---

## Task 7: Rename `JWKSRefreshException` → `JWKSFetchException`

**Spec reference:** §3.6 (rename only — same `Reason` enum, same hierarchy).

**Files:**
- Rename: `src/main/java/org/lattejava/jwt/jwks/JWKSRefreshException.java` → `JWKSFetchException.java`
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKSource.java` (replace all references)
- Rename test: `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java` references `JWKSRefreshException`; rename them.

Pure rename. The class continues to extend `JWTException`. The `Reason` enum keeps the same five constants in the same order. Update Javadoc to remove "Refresh"-only language (now also surfaces from `fetchOnce` and the `failFast` path).

- [ ] **Step 1: Inventory call sites**

Run: `grep -rn "JWKSRefreshException" src/ --include="*.java"`
Expected: hits in `JWKSRefreshException.java`, `JWKSource.java`, and tests under `src/test/java/org/lattejava/jwt/jwks/`. Note the count.

- [ ] **Step 2: Rename the file**

```bash
git mv src/main/java/org/lattejava/jwt/jwks/JWKSRefreshException.java src/main/java/org/lattejava/jwt/jwks/JWKSFetchException.java
```

- [ ] **Step 3: Update class name and Javadoc inside the renamed file**

Edit `src/main/java/org/lattejava/jwt/jwks/JWKSFetchException.java`:
- Change `public final class JWKSRefreshException extends JWTException` to `public final class JWKSFetchException extends JWTException`.
- Update both constructor names.
- Replace the class-level Javadoc with: `Thrown by JWKS-endpoint fetches: {@link JWKSource#refresh()} on a remote-backed JWKS, {@code JWKS.fetchOnce(...)} (one-shot), and the initial fetch performed inside {@code Builder.build()} when {@code failFast == true} and the JWKS hop fails. {@link #reason()} carries the categorical reason so callers can dispatch programmatically without inspecting the cause chain.`

The `Reason` enum stays unchanged. (Note: `JWKSource` is renamed to `JWKS` in Task 9 — for now the Javadoc references `JWKSource` and is updated in Task 9.)

- [ ] **Step 4: Replace all references**

In `src/main/java/org/lattejava/jwt/jwks/JWKSource.java`:
- Replace every `JWKSRefreshException` with `JWKSFetchException` (12 occurrences in code + Javadoc).

In `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java`:
- Replace every `JWKSRefreshException` with `JWKSFetchException`.

Use Edit with `replace_all: true`.

- [ ] **Step 5: Compile and test**

Run: `latte test --jca`
Expected: PASS. No behavior changes; pure rename.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(jwks): rename JWKSRefreshException to JWKSFetchException (spec §3.6)"
```

---

## Task 8: Add `Snapshot.jwkByKid` and `Snapshot.allKeys` (preparation for raw JWK lookup)

**Spec reference:** §3.3 (snapshot shape).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKSource.java`

Today the `Snapshot` record carries `Map<String, Verifier> byKid` only. To support `JWKS.get(kid)`, `keys()`, and `keyIds()` (Task 10), the snapshot must also carry the raw `JSONWebKey`s. Add two fields:

- `Map<String, JSONWebKey> jwkByKid` — kid → JWK, populated for every JWK that has a non-null `kid` (first-write-wins on duplicates).
- `List<JSONWebKey> allKeys` — full JWK list in JWKS-endpoint insertion order, including kidless JWKs.

The snapshot at this point is *constructed* with the new fields but not yet *exposed* via instance methods. That is Task 10. This task ensures the snapshot rotation plumbing carries the new fields atomically with `byKid`.

- [ ] **Step 1: Update the `Snapshot` record**

In `src/main/java/org/lattejava/jwt/jwks/JWKSource.java`, change the `Snapshot` record (currently lines 649-654):

```java
record Snapshot(
    List<JSONWebKey> allKeys,
    Map<String, Verifier> byKid,
    Map<String, JSONWebKey> jwkByKid,
    Instant fetchedAt,
    Instant nextDueAt,
    int consecutiveFailures,
    Instant lastFailedRefresh) {}
```

Imports: add `java.util.List` if not already present.

- [ ] **Step 2: Update every `new Snapshot(...)` call site**

There are several:
- Constructor (~line 92): `this.ref.set(new Snapshot(List.of(), Map.of(), Map.of(), Instant.EPOCH, Instant.EPOCH, 0, null));`
- `doRefreshOrThrow` (~line 430): build `allKeys` (ordered list of JWKs that survived `Verifiers.fromJWK`, including kidless ones) and `jwkByKid` (LinkedHashMap, kid → JWK, only for JWKs with non-null kid).
- `failureSnapshot` (~line 442-465): carry forward the previous `allKeys` and `jwkByKid` alongside `byKid`.

Inside `doRefreshOrThrow`, after the `for (JSONWebKey jwk : resp.keys())` loop:

```java
private Snapshot doRefreshOrThrow(Snapshot prev) {
  Instant now = Instant.now(clock);
  JWKSResponse resp = fetch();
  List<JSONWebKey> allKeys = new ArrayList<>();
  Map<String, Verifier> byKid = new LinkedHashMap<>();
  Map<String, JSONWebKey> jwkByKid = new LinkedHashMap<>();
  for (JSONWebKey jwk : resp.keys()) {
    Verifier v;
    try {
      v = Verifiers.fromJWK(jwk);
    } catch (InvalidJWKException reject) {
      if (reject.reason() == InvalidJWKException.Reason.ALG_CRV_MISMATCH) {
        if (logger.isWarnEnabled()) {
          logger.warn("JWK rejected [" + reject.reason() + "]: " + reject.getMessage());
        }
      } else if (logger.isDebugEnabled()) {
        logger.debug("JWK rejected [" + reject.reason() + "]: " + reject.getMessage());
      }
      continue;
    }
    String kid = jwk.kid();
    if (kid != null && byKid.containsKey(kid)) {
      if (logger.isWarnEnabled()) {
        logger.warn("JWKS contains duplicate kid [" + kid + "]; first-write-wins");
      }
      continue;
    }
    allKeys.add(jwk);
    if (kid != null) {
      byKid.put(kid, v);
      jwkByKid.put(kid, jwk);
    }
  }
  if (allKeys.isEmpty()) {
    throw new JWKSFetchException(JWKSFetchException.Reason.EMPTY_RESULT,
        "JWKS refresh produced no usable keys after JWK conversion");
  }
  Duration chosen = chosenInterval(resp);
  Instant nextDue = now.plus(maxOf(minRefreshInterval, chosen));
  if (logger.isInfoEnabled()) {
    logger.info("JWKS refresh succeeded; kids=[" + byKid.keySet() + "]");
  }
  List<JSONWebKey> allKeysSnapshot = Collections.unmodifiableList(new ArrayList<>(allKeys));
  Map<String, Verifier> byKidSnapshot = Collections.unmodifiableMap(new LinkedHashMap<>(byKid));
  Map<String, JSONWebKey> jwkByKidSnapshot = Collections.unmodifiableMap(new LinkedHashMap<>(jwkByKid));
  return new Snapshot(allKeysSnapshot, byKidSnapshot, jwkByKidSnapshot, now, nextDue, 0, null);
}
```

Note the rev-3 rule: **kidless JWKs land in `allKeys` (visible via `keys()`) but NOT in `byKid` / `jwkByKid` (not resolvable by kid)**. The empty-result check operates on `allKeys.isEmpty()` (an all-kidless JWKS is still a "successful" snapshot).

In `failureSnapshot`:

```java
private Snapshot failureSnapshot(Snapshot prev, Instant now, Throwable cause) {
  int prior = (prev == null) ? 0 : prev.consecutiveFailures();
  int next = prior + 1;
  List<JSONWebKey> allKeys = (prev == null) ? List.of() : prev.allKeys();
  Map<String, Verifier> byKid = (prev == null) ? Map.of() : prev.byKid();
  Map<String, JSONWebKey> jwkByKid = (prev == null) ? Map.of() : prev.jwkByKid();
  Instant fetchedAt = (prev == null) ? Instant.EPOCH : prev.fetchedAt();
  Duration off = backoff(next, minRefreshInterval, refreshInterval);
  Instant nextDue = now.plus(off);

  HTTPResponseException httpEx = unwrapHTTP(cause);
  if (httpEx != null) {
    String ra = httpEx.headerValue("Retry-After");
    if (ra != null) {
      Duration raDur = parseRetryAfter(ra, now);
      if (raDur != null) {
        Instant raNext = now.plus(raDur);
        if (raNext.isAfter(nextDue)) {
          nextDue = raNext;
          if (logger.isInfoEnabled()) {
            logger.info("Retry-After honored; nextDueAt extended by [" + raDur + "]");
          }
        }
      } else if (logger.isDebugEnabled()) {
        logger.debug("Retry-After header [" + ra + "] could not be parsed; falling back to backoff");
      }
    }
  }
  return new Snapshot(allKeys, byKid, jwkByKid, fetchedAt, nextDue, next, now);
}
```

- [ ] **Step 3: Update `currentKids()`** (still named `currentKids` here; rename is Task 10):

```java
public Set<String> currentKids() {
  return Collections.unmodifiableSet(new LinkedHashSet<>(ref.get().byKid().keySet()));
}
```

(No change needed; it already reads from `byKid().keySet()`. Confirm.)

- [ ] **Step 4: Run the existing `JWKSourceTest`**

Run: `latte test --jca --test=JWKSourceTest`
Expected: PASS. The new fields are populated and rotated correctly; nothing in the test surface changed.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKSource.java
git commit -m "refactor(jwks): add Snapshot.jwkByKid and allKeys (prep for raw lookup)"
```

---

## Task 9: Rename `JWKSource` → `JWKS`

**Spec reference:** §3 (rename), §5.4 (renames table).

**Files:**
- Rename: `src/main/java/org/lattejava/jwt/jwks/JWKSource.java` → `JWKS.java`
- Modify: `src/main/java/org/lattejava/jwt/jwks/package-info.java`
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKSFetchException.java` (Javadoc still says `JWKSource`)
- Modify: `src/main/java/org/lattejava/jwt/VerifierResolver.java` (if it references `JWKSource`)
- Rename test: `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java` → `JWKSTest.java`
- Modify: any test that references `JWKSource`

- [ ] **Step 1: Inventory call sites**

```bash
grep -rln "JWKSource" src/ --include="*.java"
grep -rln "jwks-source" src/ --include="*.java"
```

Note all matches.

- [ ] **Step 2: Rename the source file**

```bash
git mv src/main/java/org/lattejava/jwt/jwks/JWKSource.java src/main/java/org/lattejava/jwt/jwks/JWKS.java
git mv src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
```

- [ ] **Step 3: Replace `JWKSource` with `JWKS` everywhere it appears**

In `JWKS.java` (the renamed file):
- `public final class JWKSource` → `public final class JWKS`
- Constructor name: `JWKSource(Builder b)` → `JWKS(Builder b)`
- `public JWKSource build()` → `public JWKS build()`
- `return new JWKSource(this);` → `return new JWKS(this);`
- All Javadoc references and log messages: `"JWKSource closed"` → `"JWKS closed"`, etc.
- The thread name `"jwks-source-scheduler"` → `"jwks-scheduler"` (less misleading after the rename).

In `package-info.java`, `JWKSFetchException.java`, `VerifierResolver.java`, and any test files: replace `JWKSource` with `JWKS` (use Edit with `replace_all: true`).

In `JWKSTest.java`: rename the class from `JWKSourceTest` to `JWKSTest`. Rename any local variables called `source` to `jwks` for readability — optional but helps reviewers.

- [ ] **Step 3b: Rename `fromWellKnownConfiguration` → `fromWellKnown`** (spec §5.4)

In `JWKS.java`, rename the static factory method `fromWellKnownConfiguration(String wellKnownURL)` to `fromWellKnown(String wellKnownURL)`. Update every test reference (`grep -rn "fromWellKnownConfiguration" src/`) and any Javadoc that names the old method.

- [ ] **Step 4: Compile and test**

Run: `latte test --jca`
Expected: PASS. No behavior change.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(jwks): rename JWKSource to JWKS, fromWellKnownConfiguration to fromWellKnown"
```

---

## Task 10: `JWKS.get(kid)`, `keys()`, `keyIds()` (raw JWK access)

**Spec reference:** §3.2.

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

Add three new instance methods. Rename `currentKids()` → `keyIds()` (per §5.4). The methods read from the `Snapshot` fields populated in Task 8.

**Rev-3 rules:**
- `keys()` — full insertion order, includes kidless JWKs.
- `keyIds()` — insertion order, **excludes** the null entry (kidless JWKs do not appear).
- `get(String kid)` — returns null for unknown kid AND for `kid == null`.
- All three return unmodifiable views.

- [ ] **Step 1: Write the failing tests**

Add to `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java` (use existing test fixtures):

```java
@Test
public void get_returns_jwk_for_known_kid() throws Exception {
  String url = startJWKSServer("kid-A", "kid-B");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertNotNull(jwks.get("kid-A"));
    assertEquals(jwks.get("kid-A").kid(), "kid-A");
  }
}

@Test
public void get_returns_null_for_unknown_kid() throws Exception {
  String url = startJWKSServer("kid-A");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertNull(jwks.get("not-present"));
  }
}

@Test
public void get_returns_null_for_null_kid() throws Exception {
  String url = startJWKSServer("kid-A");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertNull(jwks.get(null));
  }
}

@Test
public void keys_preserves_insertion_order_and_includes_kidless() throws Exception {
  // JWKS endpoint returns three keys: kid-A, no-kid, kid-B
  String url = startJWKSServerWithKidlessSecond("kid-A", "kid-B");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    java.util.List<String> kids = jwks.keys().stream()
        .map(JSONWebKey::kid)
        .toList();
    assertEquals(kids, java.util.List.of("kid-A", null, "kid-B"));
  }
}

@Test
public void keyIds_excludes_null_kids() throws Exception {
  String url = startJWKSServerWithKidlessSecond("kid-A", "kid-B");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertEquals(jwks.keyIds(), new java.util.LinkedHashSet<>(java.util.List.of("kid-A", "kid-B")));
  }
}

@Test
public void keys_returns_unmodifiable_view() throws Exception {
  String url = startJWKSServer("kid-A");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertThrows(UnsupportedOperationException.class, () -> jwks.keys().clear());
  }
}

@Test
public void keyIds_returns_unmodifiable_view() throws Exception {
  String url = startJWKSServer("kid-A");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertThrows(UnsupportedOperationException.class, () -> jwks.keyIds().clear());
  }
}

@Test
public void duplicate_kid_first_write_wins() throws Exception {
  String url = startJWKSServerWithDuplicateKid("dup");
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    waitForFirstSuccess(jwks);
    assertEquals(jwks.keys().size(), 1);
    assertNotNull(jwks.get("dup"));
  }
}
```

(Adapt `startJWKSServerWithKidlessSecond` and `startJWKSServerWithDuplicateKid` to existing fixture style. The latter exists today via `src/test/resources/jwks/rsa_duplicate_kid.json`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: compilation failure (`JWKS.get`, `JWKS.keys`, `JWKS.keyIds` do not exist).

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

Replace `currentKids()` with `keyIds()`, and add `get(String)` and `keys()`:

```java
public JSONWebKey get(String kid) {
  if (kid == null) return null;
  return ref.get().jwkByKid().get(kid);
}

public Set<String> keyIds() {
  return Collections.unmodifiableSet(new LinkedHashSet<>(ref.get().jwkByKid().keySet()));
}

public Collection<JSONWebKey> keys() {
  return Collections.unmodifiableCollection(new ArrayList<>(ref.get().allKeys()));
}
```

Imports: ensure `java.util.ArrayList`, `java.util.Collection`, `java.util.LinkedHashSet`, `java.util.Set`, `java.util.Collections`.

Method ordering inside the class: alphabetical within visibility/kind group. `consecutiveFailures, get, keyIds, keys, lastFailedRefresh, lastSuccessfulRefresh, nextDueAt, refresh, resolve` (then `close` is `@Override` but conventionally listed alphabetically too — keep current ordering pattern in the file).

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): add JWKS.get(kid), keys(), keyIds() (rename currentKids)"
```

---

## Task 11: `JWKS.fromConfiguration(...)`, `JWKS.of(...)` static factories

**Spec reference:** §3.1 (factories).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

Add three new factories:

```java
public static JWKS of(JSONWebKey... keys);                       // varargs
public static JWKS of(List<JSONWebKey> keys);                    // collection
public static Builder fromConfiguration(OpenIDConnectConfiguration cfg);
```

`fromConfiguration` is a remote-backed factory like `fromJWKS` — it returns a `Builder`. Internally it builds a JWKS-only `Builder` (no discovery hop) using `cfg.jwksURI()` as the URL. **Validation:** `Builder.build()` will throw `IllegalArgumentException` if `cfg.jwksURI()` is null/empty (per §3.5). The validation happens at `build()` time, not at `fromConfiguration` time, to keep the factory cheap and let the builder collect more knobs first. Actually re-read the spec: "`Builder.build()` throws `IllegalArgumentException` if `cfg.jwksURI()` is null or empty, before any fetch is dispatched." So `build()` is the validator.

`of(...)` returns a `JWKS` directly (not a Builder) because there is nothing to configure for a static set: no refresh, no clock, no scheduler, no HTTP customizer. The asymmetry is intentional and reflects the underlying truth.

**Static-mode JWKS** (`JWKS.of`) requires a different construction path than the remote-backed Builder path. Add a private constructor `JWKS(List<JSONWebKey> staticKeys)` that:
- Builds an immediate Snapshot from the keys (apply same kidless-OK + duplicate-kid-first-write-wins logic as `doRefreshOrThrow`).
- Sets `scheduler = null`, `source = null`, `url = null`, `clock = Clock.systemUTC()`, `logger = NoOpLogger.INSTANCE`, `cacheControlPolicy = CacheControlPolicy.IGNORE`, `refreshInterval = Duration.ofMinutes(1)`, `minRefreshInterval = Duration.ofMillis(1)`, `refreshTimeout = Duration.ofSeconds(1)`, `refreshOnMiss = false`, `scheduledRefresh = false`, `httpConnectionCustomizer = null`, `fetchLimits = FetchLimits.defaults()` (added in Task 12), `failFast = false`.
- Sets a `staticMode` boolean field that gates `refresh()` (no-op), `consecutiveFailures()` (0), `lastFailedRefresh()` (null), `lastSuccessfulRefresh()` (null), `nextDueAt()` (null), `close()` (no-op).

**`JWKS.of()` with no keys is permitted** (rev 3 §3.2): returns a non-null instance with empty `keys()`/`keyIds()` and `get(any) == null`. `resolve(any)` returns null (which downstream becomes `MissingVerifierException` in `JWTDecoder`).

- [ ] **Step 1: Write the failing tests**

Add to `JWKSTest.java`:

```java
@Test
public void of_with_keys_returns_resolvable_static_set() {
  JSONWebKey k1 = loadJWK("kid-A");  // existing test helper
  JSONWebKey k2 = loadJWK("kid-B");
  JWKS jwks = JWKS.of(k1, k2);
  assertEquals(jwks.keys().size(), 2);
  assertEquals(jwks.keyIds(), new java.util.LinkedHashSet<>(java.util.List.of("kid-A", "kid-B")));
  assertNotNull(jwks.get("kid-A"));
  assertNull(jwks.get("nope"));
}

@Test
public void of_with_empty_list_is_permitted_and_returns_null_from_resolve() {
  JWKS jwks = JWKS.of(java.util.List.of());
  assertNotNull(jwks);
  assertTrue(jwks.keys().isEmpty());
  assertTrue(jwks.keyIds().isEmpty());
  assertNull(jwks.get("anything"));
  Header h = Header.builder().alg(StandardAlgorithm.HS256).kid("anything").build();
  assertNull(jwks.resolve(h));
}

@Test
public void of_no_args_is_permitted() {
  JWKS jwks = JWKS.of();
  assertNotNull(jwks);
  assertTrue(jwks.keys().isEmpty());
}

@Test
public void of_static_refresh_is_noop() {
  JWKS jwks = JWKS.of(loadJWK("kid-A"));
  jwks.refresh();  // must not throw, must not block
  assertEquals(jwks.consecutiveFailures(), 0);
  assertNull(jwks.lastFailedRefresh());
  assertNull(jwks.lastSuccessfulRefresh());
  assertNull(jwks.nextDueAt());
  jwks.close();  // no-op, must not throw
}

@Test
public void of_first_write_wins_on_duplicate_kid() {
  JSONWebKey first = loadJWK("dup");
  JSONWebKey second = loadJWK("dup");  // same kid, different key material
  JWKS jwks = JWKS.of(first, second);
  assertEquals(jwks.keys().size(), 1);
  assertSame(jwks.get("dup"), first);
}

@Test
public void fromConfiguration_with_jwks_uri_builds_remote_backed_jwks() throws Exception {
  String jwksURL = startJWKSServer("kid-A");
  OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
      .issuer("ignored")
      .jwksURI(jwksURL)
      .build();
  try (JWKS jwks = JWKS.fromConfiguration(cfg).build()) {
    waitForFirstSuccess(jwks);
    assertNotNull(jwks.get("kid-A"));
  }
}

@Test
public void fromConfiguration_throws_IllegalArgumentException_when_jwks_uri_is_null() {
  OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").build();
  assertThrows(IllegalArgumentException.class, () -> JWKS.fromConfiguration(cfg).build());
}

@Test
public void fromConfiguration_throws_IllegalArgumentException_when_jwks_uri_is_empty() {
  OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").jwksURI("").build();
  assertThrows(IllegalArgumentException.class, () -> JWKS.fromConfiguration(cfg).build());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: compilation failure (factories don't exist).

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

Add a `boolean staticMode` field (final). Add a new private constructor for the static-mode path:

```java
private JWKS(List<JSONWebKey> staticKeys) {
  this.cacheControlPolicy = CacheControlPolicy.IGNORE;
  this.clock = Clock.systemUTC();
  this.fetchLimits = FetchLimits.defaults();
  this.failFast = false;
  this.httpConnectionCustomizer = null;
  this.logger = NoOpLogger.INSTANCE;
  this.minRefreshInterval = Duration.ofMillis(1);
  this.refreshInterval = Duration.ofMinutes(1);
  this.refreshOnMiss = false;
  this.refreshTimeout = Duration.ofSeconds(1);
  this.scheduledRefresh = false;
  this.scheduler = null;
  this.source = null;
  this.staticMode = true;
  this.url = null;
  // Build the snapshot now.
  List<JSONWebKey> all = new ArrayList<>();
  Map<String, Verifier> byKid = new LinkedHashMap<>();
  Map<String, JSONWebKey> jwkByKid = new LinkedHashMap<>();
  for (JSONWebKey jwk : staticKeys) {
    Verifier v;
    try {
      v = Verifiers.fromJWK(jwk);
    } catch (InvalidJWKException reject) {
      // Same logging as remote path: WARN on ALG_CRV_MISMATCH, DEBUG otherwise. Skip the JWK.
      continue;
    }
    String kid = jwk.kid();
    if (kid != null && byKid.containsKey(kid)) {
      // First-write-wins; skip dup
      continue;
    }
    all.add(jwk);
    if (kid != null) {
      byKid.put(kid, v);
      jwkByKid.put(kid, jwk);
    }
  }
  this.ref.set(new Snapshot(
      Collections.unmodifiableList(new ArrayList<>(all)),
      Collections.unmodifiableMap(new LinkedHashMap<>(byKid)),
      Collections.unmodifiableMap(new LinkedHashMap<>(jwkByKid)),
      Instant.EPOCH, Instant.EPOCH, 0, null));
}
```

Add the `staticMode` short-circuit to existing methods. Pattern:

```java
public int consecutiveFailures() {
  if (staticMode) return 0;
  return ref.get().consecutiveFailures();
}

public Instant lastFailedRefresh() {
  if (staticMode) return null;
  return ref.get().lastFailedRefresh();
}

public Instant lastSuccessfulRefresh() {
  if (staticMode) return null;
  Snapshot s = ref.get();
  return s.fetchedAt().equals(Instant.EPOCH) ? null : s.fetchedAt();
}

public Instant nextDueAt() {
  if (staticMode) return null;
  return ref.get().nextDueAt();
}

public void refresh() {
  if (staticMode) return;
  // existing body
}

@Override public void close() {
  if (staticMode) return;
  // existing body
}
```

`resolve(Header)` works without modification — for the static case, the snapshot is set at construction, and `resolve` reads it the same way. (The only difference is that `refreshOnMiss` is false for static mode, so on a miss it returns null without scheduling.)

Add the factory methods:

```java
public static Builder fromConfiguration(OpenIDConnectConfiguration cfg) {
  Objects.requireNonNull(cfg, "cfg");
  return new Builder(FetchSource.JWKS, cfg.jwksURI(), cfg);
}

public static JWKS of(JSONWebKey... keys) {
  return new JWKS(keys == null ? List.of() : Arrays.asList(keys));
}

public static JWKS of(List<JSONWebKey> keys) {
  Objects.requireNonNull(keys, "keys");
  return new JWKS(keys);
}
```

The `Builder(FetchSource, String, OpenIDConnectConfiguration)` constructor stores `cfg` so that `Builder.build()` can validate `cfg.jwksURI()` early. `null` is allowed for `cfg` in the existing 2-arg constructor (used by `fromIssuer`/`fromWellKnown`/`fromJWKS`).

Add to `Builder`:
```java
private final OpenIDConnectConfiguration cfg;

Builder(FetchSource source, String url) {
  this(source, url, null);
}

Builder(FetchSource source, String url, OpenIDConnectConfiguration cfg) {
  this.source = source;
  this.url = url;
  this.cfg = cfg;
}
```

In `Builder.build()`, before any other validation:

```java
public JWKS build() {
  if (cfg != null) {
    if (cfg.jwksURI() == null || cfg.jwksURI().isEmpty()) {
      throw new IllegalArgumentException("Cannot build a JWKS from a configuration with a null or empty jwksURI");
    }
  }
  Objects.requireNonNull(url, "url");
  // ... existing validations
}
```

(`cfg` only matters for early rejection; the runtime fetch path uses `url` and `source`, both already wired in the `Builder` constructor.)

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): add JWKS.of, fromConfiguration, static-mode constructor"
```

---

## Task 12: `JWKS.fetchOnce(...)`, `Builder.fetchLimits(...)`, `Builder.failFast(...)`; wire fetches via `FetchLimits` + `HardenedJSON`

**Spec reference:** §3.1 (`fetchOnce`), §3.5 (Builder.fetchLimits, failFast, build-time fetch semantics), §3.7 (redirect policy applied), §4.

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

Three intertwined changes:
1. Add `Builder.fetchLimits(FetchLimits)` (default `FetchLimits.defaults()`).
2. Add `Builder.failFast(boolean)` (default `false`).
3. Add four `fetchOnce(...)` static methods.
4. Inline the JWKS-direct fetch path so it uses `FetchLimits` (instead of `JSONWebKeySetHelper.maxResponseSize` etc.) and the same-origin guard. The issuer/well-known paths continue to call `JSONWebKeySetHelper` until Task 13 swaps them to `OpenIDConnect.discover`.
5. Implement `failFast` semantics in `Builder.build()`: re-raise the underlying exception synchronously if the initial fetch fails.

- [ ] **Step 1: Write the failing tests**

Add to `JWKSTest.java`:

```java
@Test
public void builder_fetchLimits_applies_to_jwks_response_size_cap() throws Exception {
  String url = startJWKSServerReturningLargeBody();
  FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
  try (JWKS jwks = JWKS.fromJWKS(url).fetchLimits(tight).build()) {
    waitForFirstFailure(jwks);
    assertTrue(jwks.consecutiveFailures() >= 1);
  }
}

@Test
public void builder_failFast_throws_on_initial_failure() throws Exception {
  String url = "http://127.0.0.1:1/no-such-server";
  assertThrows(JWKSFetchException.class,
      () -> JWKS.fromJWKS(url).failFast(true).build());
}

@Test
public void builder_failFast_does_not_leak_threads_on_failure() throws Exception {
  // Best-effort thread-leak check: count "jwks-*" threads before and after.
  long before = countJWKSThreads();
  String url = "http://127.0.0.1:1/no-such-server";
  assertThrows(JWKSFetchException.class,
      () -> JWKS.fromJWKS(url).failFast(true).scheduledRefresh(true).build());
  // Allow a brief moment for the worker to die after the build() throw.
  Thread.sleep(200);
  long after = countJWKSThreads();
  assertTrue(after <= before, "expected no new jwks-* threads but went from " + before + " to " + after);
}

@Test
public void builder_failFast_default_false_does_not_throw_on_initial_failure() throws Exception {
  String url = "http://127.0.0.1:1/no-such-server";
  try (JWKS jwks = JWKS.fromJWKS(url).build()) {
    assertNotNull(jwks);
    assertNull(jwks.lastSuccessfulRefresh());
  }
}

@Test
public void fetchOnce_returns_keys_from_jwks_endpoint() throws Exception {
  String url = startJWKSServer("kid-1", "kid-2");
  java.util.List<JSONWebKey> keys = JWKS.fetchOnce(url);
  assertEquals(keys.stream().map(JSONWebKey::kid).toList(), java.util.List.of("kid-1", "kid-2"));
}

@Test
public void fetchOnce_with_customizer_applies_to_connection() throws Exception {
  java.util.concurrent.atomic.AtomicBoolean called = new java.util.concurrent.atomic.AtomicBoolean();
  String url = startJWKSServer("kid-1");
  JWKS.fetchOnce(url, conn -> { called.set(true); conn.setRequestProperty("X-Test", "y"); });
  assertTrue(called.get());
}

@Test
public void fetchOnce_with_FetchLimits_enforces_response_cap() throws Exception {
  String url = startJWKSServerReturningLargeBody();
  FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
  assertThrows(JWKSFetchException.class, () -> JWKS.fetchOnce(url, tight));
}

@Test
public void fetchOnce_rejects_cross_origin_redirect_by_default() throws Exception {
  String url = startServerThatRedirectsToDifferentHost();
  JWKSFetchException ex = assertThrows(JWKSFetchException.class, () -> JWKS.fetchOnce(url));
  assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"));
}

private static long countJWKSThreads() {
  return Thread.getAllStackTraces().keySet().stream()
      .filter(t -> t.getName().startsWith("jwks-"))
      .count();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: compilation failure (`Builder.fetchLimits`, `Builder.failFast`, `JWKS.fetchOnce` do not exist).

- [ ] **Step 3: Implement**

Add to `JWKS`:

```java
// New instance fields:
private final boolean failFast;
private final FetchLimits fetchLimits;

// In the Builder-constructor JWKS(Builder b):
this.failFast = b.failFast;
this.fetchLimits = b.fetchLimits;

// Implementation of Builder.build() initial-fetch with failFast semantics:
public JWKS build() {
  // ... existing validations (cfg.jwksURI null check, refresh-interval checks, etc.)
  JWKS jwks = new JWKS(this);
  // The constructor dispatched the initial fetch via singleflightRefresh(). If failFast,
  // re-raise the failure synchronously (the constructor swallowed it).
  if (failFast) {
    Snapshot s = jwks.ref.get();
    if (s.consecutiveFailures() > 0) {
      // Best-effort: the constructor's CompletableFuture is gone; we have to rebuild
      // the failure cause. The simplest correct approach: dispatch a sync refresh()
      // and surface the typed exception it throws.
      try {
        jwks.refresh();
      } catch (RuntimeException re) {
        // Stop the scheduler and the worker before throwing.
        if (jwks.scheduler != null) jwks.scheduler.shutdownNow();
        throw re;
      }
      // If refresh() somehow succeeded after the constructor failed, return the JWKS.
    }
  }
  return jwks;
}
```

Note: this implementation is *almost* right but the "rebuild the failure" path adds a second HTTP request. A cleaner approach: have the constructor remember the initial-fetch exception in a transient field that `Builder.build()` then reads. For example:

```java
// On JWKS:
volatile Throwable initialFetchFailure;  // package-private; cleared on first successful refresh

// Inside the constructor's existing initial-fetch block:
} catch (ExecutionException ee) {
  Throwable c = ee.getCause();
  this.initialFetchFailure = (c != null) ? c : ee;
}
```

Then `Builder.build()`:

```java
public JWKS build() {
  // ... existing validations
  JWKS jwks = new JWKS(this);
  if (failFast && jwks.initialFetchFailure != null) {
    Throwable f = jwks.initialFetchFailure;
    if (jwks.scheduler != null) jwks.scheduler.shutdownNow();
    if (f instanceof JWKSFetchException jfe) throw jfe;
    if (f instanceof OpenIDConnectException oce) throw oce;
    // Defense-in-depth: classify
    throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
        "Initial JWKS fetch failed", f);
  }
  return jwks;
}
```

Add `Builder` field/setters:

```java
private boolean failFast = false;
private FetchLimits fetchLimits = FetchLimits.defaults();

public Builder failFast(boolean failFast) {
  this.failFast = failFast;
  return this;
}

public Builder fetchLimits(FetchLimits limits) {
  this.fetchLimits = Objects.requireNonNull(limits, "fetchLimits");
  return this;
}
```

Add the four `fetchOnce` static methods:

```java
public static List<JSONWebKey> fetchOnce(String jwksURL) {
  return fetchOnce(jwksURL, FetchLimits.defaults(), null);
}

public static List<JSONWebKey> fetchOnce(String jwksURL, Consumer<HttpURLConnection> customizer) {
  return fetchOnce(jwksURL, FetchLimits.defaults(), customizer);
}

public static List<JSONWebKey> fetchOnce(String jwksURL, FetchLimits limits) {
  return fetchOnce(jwksURL, limits, null);
}

public static List<JSONWebKey> fetchOnce(String jwksURL, FetchLimits limits, Consumer<HttpURLConnection> customizer) {
  Objects.requireNonNull(jwksURL, "jwksURL");
  Objects.requireNonNull(limits, "limits");
  HttpURLConnection connection = AbstractHTTPHelper.buildURLConnection(jwksURL,
      (msg, cause) -> new JWKSFetchException(JWKSFetchException.Reason.NETWORK, msg, cause));
  if (customizer != null) customizer.accept(connection);
  try {
    return AbstractHTTPHelper.get(connection,
        limits.maxResponseBytes(),
        limits.maxRedirects(),
        !limits.allowCrossOriginRedirects(),
        (conn, is) -> parseJWKSResponseKeys(conn, is, limits),
        (msg, cause) -> classifyFetchFailure(msg, cause));
  } catch (JWKSFetchException e) {
    throw e;
  } catch (RuntimeException e) {
    throw classifyFetchFailure("JWKS fetch failed", e);
  }
}

// Private helper used by both fetchOnce and the inlined fetchJWKSDirect path:
private static List<JSONWebKey> parseJWKSResponseKeys(HttpURLConnection conn, InputStream is, FetchLimits limits) {
  Map<String, Object> map = HardenedJSON.parse(is, limits);
  Object keys = map.get("keys");
  if (!(keys instanceof List<?> keyList)) {
    throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
        "JWKS endpoint [" + conn.getURL() + "] response is missing the [keys] array");
  }
  List<JSONWebKey> result = new ArrayList<>();
  for (Object element : keyList) {
    if (!(element instanceof Map<?, ?> elementMap)) {
      throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
          "JWKS endpoint [" + conn.getURL() + "] response contains a non-object element in [keys]");
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> typed = (Map<String, Object>) elementMap;
    result.add(JSONWebKey.fromMap(typed));
  }
  return result;
}

private static JWKSFetchException classifyFetchFailure(String msg, Throwable cause) {
  if (cause instanceof HTTPResponseException) {
    return new JWKSFetchException(JWKSFetchException.Reason.NON_2XX, msg, cause);
  }
  Throwable t = cause;
  while (t != null) {
    if (t instanceof IOException) {
      return new JWKSFetchException(JWKSFetchException.Reason.NETWORK, msg, cause);
    }
    t = t.getCause();
  }
  return new JWKSFetchException(JWKSFetchException.Reason.PARSE, msg, cause);
}
```

Inline the JWKS-direct fetch path. Replace the existing `private JWKSResponse fetch()` (lines ~468-474):

```java
private JWKSResponse fetch() {
  return switch (source) {
    case ISSUER     -> JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer(url, httpConnectionCustomizer);   // Task 13 inlines
    case WELL_KNOWN -> JSONWebKeySetHelper.retrieveJWKSResponseFromWellKnownConfiguration(url, httpConnectionCustomizer);   // Task 13 inlines
    case JWKS       -> fetchJWKSDirect(url);
  };
}

private JWKSResponse fetchJWKSDirect(String jwksURL) {
  HttpURLConnection connection = AbstractHTTPHelper.buildURLConnection(jwksURL,
      (msg, cause) -> new JWKSFetchException(JWKSFetchException.Reason.NETWORK, msg, cause));
  if (httpConnectionCustomizer != null) httpConnectionCustomizer.accept(connection);
  return AbstractHTTPHelper.get(connection,
      fetchLimits.maxResponseBytes(),
      fetchLimits.maxRedirects(),
      !fetchLimits.allowCrossOriginRedirects(),
      (conn, is) -> {
        List<JSONWebKey> keys = parseJWKSResponseKeys(conn, is, fetchLimits);
        int status = -1;
        try { status = conn.getResponseCode(); } catch (IOException ignored) {}
        Map<String, String> sel = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String name : new String[]{"Cache-Control", "Retry-After"}) {
          String v = conn.getHeaderField(name);
          if (v != null) sel.put(name, v);
        }
        return new JWKSResponse(keys, status, sel);
      },
      JWKS::classifyFetchFailure);
}
```

Imports: add `java.util.TreeMap`, `java.util.ArrayList`, `org.lattejava.jwt.FetchLimits`, `org.lattejava.jwt.HTTPResponseException` (already there?), `org.lattejava.jwt.internal.HardenedJSON`, `org.lattejava.jwt.internal.http.AbstractHTTPHelper`.

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS for new tests; existing remote-backed tests still pass (the JWKS-direct path is wired correctly; issuer/well-known still go through the legacy helper, migrated in Task 13).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): add fetchOnce, Builder.fetchLimits, Builder.failFast"
```

---

## Task 13: Wire `fromIssuer` / `fromWellKnown` through `OpenIDConnect.discover`; lock `jwks_uri` after first successful discovery

**Spec reference:** §3.4 (refresh behavior), §3.5 (Builder-scope semantics, build-time fetch).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

This task implements the rev-3 refresh-behavior change (the most subtle change in the whole spec):

> Discovery happens **at most once successfully** over the lifetime of a `JWKS`, then never again.
>
> - The first refresh runs discovery, extracts and caches `jwks_uri`, and runs the JWKS hop.
> - If discovery succeeds, `jwks_uri` is locked for the lifetime of the `JWKS` and every subsequent refresh hits it directly.
> - If discovery has not yet succeeded (construction-time discovery hop failed, or every refresh since has failed before reaching the JWKS hop), every refresh re-attempts discovery. Once one succeeds, the rule above kicks in.

Concretely: `JWKS` gains a `volatile String lockedJWKSURI` field, initially null. When `fetchJWKSDirect` succeeds via the discovery path, set `lockedJWKSURI` to the discovered URL.

**Exception type discipline (§3.6):** while discovery has not succeeded, `refresh()` re-attempts discovery and surfaces `OpenIDConnectException`. After the lock, `refresh()` only runs the JWKS hop and surfaces `JWKSFetchException`. Both extend `RuntimeException`, so callers catching the parent are unaffected; callers wanting phase-level dispatch catch each.

**Timeout scope:** `refreshTimeout` bounds **only** the JWKS-endpoint hop. The discovery hop is bounded by `HttpURLConnection` connect/read timeouts (10s/10s default in `AbstractHTTPHelper.buildURLConnection`). This was already true prior to this task (the JWKS hop is what `singleflightRefresh` waits on); calling it out for clarity.

- [ ] **Step 1: Write the failing tests**

Add to `JWKSTest.java`:

```java
@Test
public void fromIssuer_first_refresh_hits_discovery_then_jwks() throws Exception {
  // Stand up an OIDC server: discovery doc + JWKS endpoint.
  AtomicInteger discoveryHits = new AtomicInteger();
  AtomicInteger jwksHits = new AtomicInteger();
  String issuer = startOIDCServer(discoveryHits, jwksHits, "kid-A");
  try (JWKS jwks = JWKS.fromIssuer(issuer).build()) {
    waitForFirstSuccess(jwks);
    assertEquals(discoveryHits.get(), 1);
    assertEquals(jwksHits.get(), 1);
  }
}

@Test
public void fromIssuer_subsequent_refresh_skips_discovery() throws Exception {
  AtomicInteger discoveryHits = new AtomicInteger();
  AtomicInteger jwksHits = new AtomicInteger();
  String issuer = startOIDCServer(discoveryHits, jwksHits, "kid-A");
  try (JWKS jwks = JWKS.fromIssuer(issuer).build()) {
    waitForFirstSuccess(jwks);
    int discoveryAfterFirst = discoveryHits.get();
    int jwksAfterFirst = jwksHits.get();
    jwks.refresh();
    assertEquals(discoveryHits.get(), discoveryAfterFirst, "discovery hit a second time");
    assertEquals(jwksHits.get(), jwksAfterFirst + 1, "JWKS hop not re-run on refresh");
  }
}

@Test
public void fromIssuer_refresh_reattempts_discovery_until_first_success() throws Exception {
  // First discovery attempt: 500. Second: 200 with a normal doc.
  AtomicInteger discoveryHits = new AtomicInteger();
  String issuer = startOIDCServerWithDiscoveryFailingThenSucceeding(discoveryHits, "kid-A");
  try (JWKS jwks = JWKS.fromIssuer(issuer).build()) {
    // Build does not throw; first discovery attempt failed inside the worker.
    assertNull(jwks.lastSuccessfulRefresh());
    assertTrue(jwks.consecutiveFailures() >= 1);
    // refresh() re-attempts discovery (because discovery has not yet succeeded).
    jwks.refresh();
    assertNotNull(jwks.lastSuccessfulRefresh());
    int hitsAfterSuccess = discoveryHits.get();
    // After the first success, refresh() does NOT re-attempt discovery.
    jwks.refresh();
    assertEquals(discoveryHits.get(), hitsAfterSuccess);
  }
}

@Test
public void fromIssuer_refresh_throws_OpenIDConnectException_while_discovery_not_yet_succeeded() throws Exception {
  // Stand up a server where discovery always returns 500.
  String issuer = startOIDCServerWithDiscovery500();
  try (JWKS jwks = JWKS.fromIssuer(issuer).build()) {
    assertThrows(OpenIDConnectException.class, jwks::refresh);
  }
}

@Test
public void fromIssuer_refresh_throws_JWKSFetchException_after_discovery_locked() throws Exception {
  // Discovery succeeds, then JWKS endpoint is replaced with a 500-returning handler.
  String issuer = startOIDCServerJWKSWillFailLater("kid-A");
  try (JWKS jwks = JWKS.fromIssuer(issuer).build()) {
    waitForFirstSuccess(jwks);
    breakJWKSEndpoint(); // rewires the JWKS path on the test server to return 500
    assertThrows(JWKSFetchException.class, jwks::refresh);
  }
}

@Test
public void fromConfiguration_does_not_perform_discovery_at_build() throws Exception {
  // Provide an OpenIDConnectConfiguration directly — no discovery hop.
  String jwksURL = startJWKSServer("kid-A");
  OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
      .issuer("ignored")
      .jwksURI(jwksURL)
      .build();
  try (JWKS jwks = JWKS.fromConfiguration(cfg).build()) {
    waitForFirstSuccess(jwks);
    // Nothing to assert about discovery hits; just verify the JWKS works.
    assertNotNull(jwks.get("kid-A"));
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: failures (the issuer/well-known paths still call `JSONWebKeySetHelper`, which re-fetches discovery on every refresh; some assertions about discovery hits will be wrong).

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

Add a `volatile String lockedJWKSURI = null;` field. In the `fetch()` switch, replace the issuer/well-known cases:

```java
private JWKSResponse fetch() {
  String effectiveURL;
  if (lockedJWKSURI != null) {
    effectiveURL = lockedJWKSURI;
  } else {
    effectiveURL = switch (source) {
      case ISSUER     -> resolveJWKSURIFromIssuer(url);
      case WELL_KNOWN -> resolveJWKSURIFromWellKnown(url);
      case JWKS       -> url;
    };
  }
  JWKSResponse response = fetchJWKSDirect(effectiveURL);
  // First successful JWKS fetch on a discovery-derived path -> lock the URL.
  if (lockedJWKSURI == null && source != FetchSource.JWKS) {
    lockedJWKSURI = effectiveURL;
  }
  return response;
}

private String resolveJWKSURIFromIssuer(String issuer) {
  OpenIDConnectConfiguration cfg = OpenIDConnect.discover(
      issuer, fetchLimits, httpConnectionCustomizer);
  return cfg.jwksURI();
}

private String resolveJWKSURIFromWellKnown(String wellKnownURL) {
  OpenIDConnectConfiguration cfg = OpenIDConnect.discoverFromWellKnown(
      wellKnownURL, fetchLimits, httpConnectionCustomizer);
  return cfg.jwksURI();
}
```

Imports: add `org.lattejava.jwt.OpenIDConnect`, `org.lattejava.jwt.OpenIDConnectConfiguration`, `org.lattejava.jwt.OpenIDConnectException`.

Note that `OpenIDConnect.discover` throws `OpenIDConnectException` on any discovery failure (including parse, non-2xx, cross-origin, missing fields, issuer mismatch). The `singleflightRefresh` worker's existing catch handlers will catch this as a generic `Exception`; route it directly through to the awaiter rather than reclassifying. Update the worker's exception handling:

```java
Thread.ofVirtual().start(() -> {
  refreshThread = Thread.currentThread();
  try {
    Snapshot prev = ref.get();
    Snapshot fresh;
    Throwable failureCause = null;
    try {
      fresh = doRefreshOrThrow(prev);
    } catch (JWKSFetchException re) {
      failureCause = re;
      if (logger.isErrorEnabled()) {
        logger.error("JWKS refresh failed [" + re.reason() + "]", re);
      }
      fresh = failureSnapshot(prev, Instant.now(clock), re);
    } catch (OpenIDConnectException oe) {
      failureCause = oe;
      if (logger.isErrorEnabled()) {
        logger.error("Discovery failed: " + oe.getMessage(), oe);
      }
      fresh = failureSnapshot(prev, Instant.now(clock), oe);
    } catch (Exception e) {
      JWKSFetchException wrapped = classifyFailure(e);
      failureCause = wrapped;
      if (logger.isErrorEnabled()) {
        logger.error("JWKS refresh failed [" + wrapped.reason() + "]", e);
      }
      fresh = failureSnapshot(prev, Instant.now(clock), wrapped);
    }
    if (!closed) {
      ref.set(fresh);
    }
    if (failureCause != null) {
      mine.completeExceptionally(failureCause);
    } else {
      mine.complete(fresh);
    }
  } finally {
    refreshThread = null;
    inflight.set(null);
  }
});
```

Update `refresh()` to surface `OpenIDConnectException` directly (do not re-wrap into `JWKSFetchException`):

```java
public void refresh() {
  if (staticMode) return;
  if (closed) {
    if (logger.isDebugEnabled()) logger.debug("refresh() called on closed JWKS");
    return;
  }
  CompletableFuture<Snapshot> fut = singleflightRefresh();
  try {
    fut.get(refreshTimeout.toMillis(), TimeUnit.MILLISECONDS);
  } catch (TimeoutException te) {
    throw new JWKSFetchException(JWKSFetchException.Reason.TIMEOUT,
        "Timed out after [" + refreshTimeout + "] waiting for JWKS refresh", te);
  } catch (InterruptedException ie) {
    Thread.currentThread().interrupt();
    throw new JWKSFetchException(JWKSFetchException.Reason.TIMEOUT,
        "Interrupted while waiting for JWKS refresh", ie);
  } catch (ExecutionException ee) {
    Throwable c = ee.getCause();
    if (c instanceof JWKSFetchException re) throw re;
    if (c instanceof OpenIDConnectException oe) throw oe;
    throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
        "JWKS refresh failed", c != null ? c : ee);
  }
}
```

Add Javadoc on `refresh()`: "While discovery has not yet succeeded, this method re-attempts discovery and may throw `OpenIDConnectException`. After the JWKS URL has been locked from the first successful discovery, only `JWKSFetchException` is thrown. Both extend `RuntimeException`, so callers catching the parent are unaffected."

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS. Existing tests still pass; new tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): wire fromIssuer/fromWellKnown via OpenIDConnect.discover; lock jwks_uri"
```

---

## Task 14: Delete `oauth2/` package; remove `module-info.java` export

**Spec reference:** §5.1 (deletions), §5.3 (deleted package).

**Files:**
- Delete: `src/main/java/org/lattejava/jwt/oauth2/AuthorizationServerMetaData.java`
- Delete: `src/main/java/org/lattejava/jwt/oauth2/ServerMetaDataHelper.java`
- Delete: `src/test/java/org/lattejava/jwt/oauth2/ServerMetaDataTest.java` (and `src/test/resources/oauth2/` if unused after this)
- Modify: `src/main/java/module-info.java` (remove `exports org.lattejava.jwt.oauth2;`)

The `oauth2/` package is now empty. The migration path for callers (per spec §5.1 and §5.2) is documented in the changelog; no library code depends on these classes after Task 13.

- [ ] **Step 1: Verify no production code references the oauth2 package**

```bash
grep -rln "org.lattejava.jwt.oauth2\|AuthorizationServerMetaData\|ServerMetaDataHelper" src/main --include="*.java"
```

Expected: zero hits. (If anything remains, fix it before proceeding — it's a missed migration.)

- [ ] **Step 2: Delete the source files and tests**

```bash
git rm src/main/java/org/lattejava/jwt/oauth2/AuthorizationServerMetaData.java
git rm src/main/java/org/lattejava/jwt/oauth2/ServerMetaDataHelper.java
git rm src/test/java/org/lattejava/jwt/oauth2/ServerMetaDataTest.java
git rm src/test/resources/oauth2/example_server_metadata.json   # if unused
rmdir src/main/java/org/lattejava/jwt/oauth2 2>/dev/null || true
rmdir src/test/java/org/lattejava/jwt/oauth2 2>/dev/null || true
rmdir src/test/resources/oauth2 2>/dev/null || true
```

- [ ] **Step 3: Update `module-info.java`**

Edit `src/main/java/module-info.java`. Remove the line `exports org.lattejava.jwt.oauth2;`. Keep all other exports alphabetized.

- [ ] **Step 4: Build and test**

Run: `latte test --jca`
Expected: PASS. Compilation succeeds without the oauth2 package and module-info export.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: delete org.lattejava.jwt.oauth2 package (spec §5.3)"
```

---

## Task 15: Delete `JSONWebKeySetHelper`; migrate test callers

**Spec reference:** §5.1, §5.2 (redistribution table).

**Files:**
- Delete: `src/main/java/org/lattejava/jwt/jwks/JSONWebKeySetHelper.java`
- Delete or migrate: `src/test/java/org/lattejava/jwt/jwks/JSONWebKeySetHelperTest.java`
- Modify: `src/main/java/org/lattejava/jwt/internal/http/AbstractHTTPHelper.java` (remove the legacy 4-arg `get` overload if no longer called)

After Task 13 the production code no longer references `JSONWebKeySetHelper`. The test class `JSONWebKeySetHelperTest` is the last caller. Its coverage migrates to `JWKSTest` (most cases already covered there) and `OpenIDConnectDiscoverTest`. Anything that does not have a clear new home is deleted (the migration table in §5.2 explicitly removes `retrieveKeysFromJWKS(HttpURLConnection)` — there is no replacement).

- [ ] **Step 1: Migrate or delete `JSONWebKeySetHelperTest`**

Read `src/test/java/org/lattejava/jwt/jwks/JSONWebKeySetHelperTest.java`. For each test:
- If the behavior is already covered in `JWKSTest` (response-cap, redirect-cap, JSON-parse caps, network failures, well-known/issuer happy path, JWK conversion errors): delete the test.
- If the behavior is not yet covered (e.g. a specific failure-message format): port it to `JWKSTest` (using `JWKS.fetchOnce(...)` or `JWKS.fromIssuer(...)`) or to `OpenIDConnectDiscoverTest`.

After the migration, delete `JSONWebKeySetHelperTest.java`.

- [ ] **Step 2: Delete `JSONWebKeySetHelper`**

```bash
git rm src/main/java/org/lattejava/jwt/jwks/JSONWebKeySetHelper.java
git rm src/test/java/org/lattejava/jwt/jwks/JSONWebKeySetHelperTest.java
```

- [ ] **Step 3: Verify `AbstractHTTPHelper` legacy overload is unused**

```bash
grep -rn "AbstractHTTPHelper.get(" src --include="*.java"
```

If only the 6-arg overload (with `sameOriginRedirectsOnly`) is referenced, delete the 4-arg overload from `AbstractHTTPHelper.java`. Update its Javadoc.

- [ ] **Step 4: Build and test**

Run: `latte test --jca`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(jwks): delete JSONWebKeySetHelper (spec §5.2)"
```

---

## Task 16: README review + happy-path examples for the new surface

**Files:**
- Modify: `README.md`

The 7.0 surface is meaningfully different. The README must show the new happy paths so that a reader landing on the repo immediately sees how to use the library. Specifically: examples for OIDC discovery, the new `JWKS` factories (`fromIssuer`, `fromConfiguration`, `of`, `fetchOnce`), per-instance `FetchLimits`, and the `failFast` option.

This is a documentation task, not TDD. Read the current README, identify outdated snippets (anything referencing `JWKSource`, `JSONWebKeySetHelper`, `AuthorizationServerMetaData`, `ServerMetaDataHelper`, the global static config setters, or the old `currentKids()`), replace them with rev-3 equivalents, and add new sections where the surface is now richer.

- [ ] **Step 1: Inventory outdated content**

Read `README.md`. Search for outdated symbols:

```bash
grep -n "JWKSource\|JSONWebKeySetHelper\|AuthorizationServerMetaData\|ServerMetaDataHelper\|setMaxResponseSize\|setMaxRedirects\|setMaxNestingDepth\|setMaxObjectMembers\|setMaxArrayElements\|setAllowDuplicateJSONKeys\|currentKids\|JWKSRefreshException\|fromWellKnownConfiguration" README.md
```

For each hit, decide: replace with the new symbol, delete (if no longer relevant), or rewrite the surrounding section.

- [ ] **Step 2: Update or add the following README sections**

If the README does not already have these, add them. If it does, update them:

1. **OpenID Connect discovery** — show `OpenIDConnect.discover(issuer)` returning an `OpenIDConnectConfiguration`, point at `cfg.jwksURI()`, mention typed accessors, and call out the `discoverFromWellKnown(url)` overload as the right entry point for RFC 8414 servers.

2. **JWKS — the simple case** — show `JWKS.fromIssuer(issuer).build()` producing a self-refreshing `VerifierResolver`. Point at `JWTDecoder.builder().build().decode(token, jwks)`.

3. **JWKS — static keys** — show `JWKS.of(jwk1, jwk2)` for callers who already have `JSONWebKey` instances in hand (e.g. embedded in code or loaded from a file).

4. **JWKS — one-shot fetch** — show `JWKS.fetchOnce(url)` returning a `List<JSONWebKey>`.

5. **`fromConfiguration`** — show the discovery-then-construct two-step pattern when the caller wants the configuration in hand for non-JWT reasons (e.g. inspecting `tokenEndpoint` for a separate OAuth flow).

6. **`FetchLimits`** — explain the per-instance hardening config, defaults, and the `allowCrossOriginRedirects` opt-in (with the security warning).

7. **`failFast`** — show the build-time fail-fast pattern for callers that prefer "crash at boot" over "self-heal in the background."

8. **Migration callouts** — if the README has a "What's new in 7.0" or migration section, add the `JWKSource → JWKS`, `currentKids() → keyIds()`, `fromWellKnownConfiguration → fromWellKnown`, `JWKSRefreshException → JWKSFetchException`, oauth2-package-removal entries.

Suggested code snippets (these are illustrative — adapt to the README's existing voice):

````markdown
### OIDC Discovery

```java
OpenIDConnectConfiguration cfg = OpenIDConnect.discover("https://issuer.example.com");
String tokenEndpoint = cfg.tokenEndpoint();
String jwksURI       = cfg.jwksURI();
List<String> sigAlgs = cfg.idTokenSigningAlgValuesSupported();
```

`discover(issuer)` enforces OIDC Discovery 1.0 §4.3 issuer-equality validation:
the response's `issuer` field must match the input issuer. For RFC 8414 OAuth
servers without an OIDC issuer to validate against, use
`OpenIDConnect.discoverFromWellKnown(url)`.

### JWKS — self-refreshing verifier resolver

```java
try (JWKS jwks = JWKS.fromIssuer("https://issuer.example.com").build()) {
  JWT jwt = JWTDecoder.builder().build().decode(token, jwks);
}
```

Other entry points:
- `JWKS.fromWellKnown(url)` — same as `fromIssuer` but with a fully-qualified discovery URL.
- `JWKS.fromJWKS(url)` — skip discovery entirely, fetch the JWKS directly.
- `JWKS.fromConfiguration(cfg)` — use a pre-fetched `OpenIDConnectConfiguration`.
- `JWKS.of(jwk1, jwk2, ...)` — static, in-memory keys (no HTTP, no scheduler).
- `JWKS.fetchOnce(url)` — one-shot fetch returning `List<JSONWebKey>`.

### Per-instance hardening

```java
FetchLimits tight = FetchLimits.builder()
    .maxResponseBytes(64 * 1024)
    .maxRedirects(1)
    .build();

JWKS jwks = JWKS.fromIssuer(issuer).fetchLimits(tight).build();
OpenIDConnectConfiguration cfg = OpenIDConnect.discover(issuer, tight);
```

### Fail-fast at boot

```java
JWKS jwks = JWKS.fromIssuer(issuer).failFast(true).build();
// Throws OpenIDConnectException or JWKSFetchException if the initial fetch fails.
```
````

- [ ] **Step 3: Verify with a careful read-through**

Read the updated README end-to-end. Make sure:
- All code snippets compile (mentally trace them against the new API surface).
- Acronym casing matches: `JSON`, `URI`, `JWKS`, `JWT`, `OIDC`.
- No references to deleted classes remain.
- Examples use `JWKS` (not `JWKSource`), `keyIds()` (not `currentKids()`), `fromWellKnown` (not `fromWellKnownConfiguration`), `JWKSFetchException` (not `JWKSRefreshException`).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): update for 7.0 discovery + JWKS surface"
```

---

## Task 17: Final verification + spec status update

**Files:**
- Modify: `specs/7.0-discovery-and-jwks-simplification.md` (status field)

- [ ] **Step 1: Run the full test suite (both provider modes)**

Run: `latte test`
Expected: PASS for both `-Dtest.fips=false` and `-Dtest.fips=true` runs. If a FIPS-only failure surfaces (BouncyCastle FIPS provider quirks around RSA-OAEP, MGF, etc.), investigate before declaring done — most of this work is fetch/parse and provider-agnostic, but any test that exercises a `Verifiers.fromJWK(...)` round-trip on a non-RSA key may differ between providers.

- [ ] **Step 2: Generate Javadoc to catch broken `{@link}` references**

Run: `latte doc`
Expected: BUILD SUCCESS (no missing references). The renames in Tasks 7 and 9 may leave dangling `{@link JWKSource}` or `{@link JWKSRefreshException}` references in unrelated files — fix them now.

```bash
grep -rn "JWKSource\|JWKSRefreshException" src/main --include="*.java"
```

Expected: zero hits.

- [ ] **Step 3: Confirm zero compile-scope dependencies**

Read `project.latte`. The `group(name: "compile")` block must remain empty. Scan the new `OpenIDConnectConfiguration`, `OpenIDConnect`, `JWKS`, `FetchLimits`, `HardenedJSON` files for any rogue `import` from outside the JDK (`java.*`) and the project (`org.lattejava.jwt.*`). Expected: nothing else.

- [ ] **Step 4: Update the spec's `Status` field**

Edit `specs/7.0-discovery-and-jwks-simplification.md`. Change the table at the top:

```
| Status | Implemented |
```

(Keep the rev number at 3.)

- [ ] **Step 5: Commit and push**

```bash
git add specs/7.0-discovery-and-jwks-simplification.md
git commit -m "spec(7.0): mark discovery + JWKS simplification as implemented"
```

Push only on user direction. Do not open a PR automatically.

- [ ] **Step 6: Hand back to the user**

Summarize what shipped and any caveats (FIPS-only test failures, deferred items from §7, etc.).

---

## Self-review notes

Before declaring this plan complete, the writer (you) should re-read the spec and confirm:

- [x] §1 OpenIDConnectConfiguration: 23 typed fields covered in Task 5; `otherClaims()` for everything else; no public `fromMap`; `toJSON`/`toString`/`equals`/`hashCode`/`toSerializableMap` semantics covered.
- [x] §1.3 OpenIDConnectException: Task 4. Does **not** extend JWTException.
- [x] §2 OpenIDConnect.discover entry points: Task 6. Eight overloads; issuer-equality validation with single-trailing-slash normalization; `discoverFromWellKnown` skips validation.
- [x] §3.1 JWKS factories: `fromIssuer`/`fromWellKnown`/`fromJWKS` (existing, renamed in Task 9), `fromConfiguration` (Task 11), `of(...)` (Task 11), `fetchOnce(...)` (Task 12).
- [x] §3.2 instance surface: `get(kid)`, `keys()`, `keyIds()` (Task 10), kidless rule, duplicate-kid first-write-wins, `JWKS.of()` empty permitted (Task 11).
- [x] §3.3 Snapshot: `jwkByKid` + `allKeys` added in Task 8, populated in Task 8, exposed in Task 10.
- [x] §3.4 refresh behavior: at-most-once-successfully discovery, `lockedJWKSURI` field (Task 13). Pre-lock refreshes re-attempt; post-lock refreshes hit JWKS only.
- [x] §3.5 Builder: `fetchLimits` (Task 12), `failFast` (Task 12), build-time fetch semantics (Task 12). `fromConfiguration` validation early-throw `IllegalArgumentException` (Task 11).
- [x] §3.6 JWKSFetchException: rename in Task 7. Discovery → OpenIDConnectException, JWKS-hop → JWKSFetchException, no wrapping. `refresh()` can throw either depending on phase (Task 13).
- [x] §3.7 redirect policy: same-origin guard in Task 3 (added to `AbstractHTTPHelper`), wired through discovery (Task 6) and JWKS (Tasks 12, 13). Opt-out via `FetchLimits.allowCrossOriginRedirects(true)` (Task 1).
- [x] §4 FetchLimits: Task 1. All defaults match historical values; `allowCrossOriginRedirects` defaults to false; reusable builder.
- [x] §5.1 deleted classes: `JSONWebKeySetHelper.JSONWebKeySetException` (Task 15), `AuthorizationServerMetaData` and `ServerMetaDataHelper` (Task 14), `JSONWebKeySetHelper` (Task 15).
- [x] §5.2 `JSONWebKeySetHelper` redistribution: `parseJSON` → `internal/HardenedJSON` (Task 2). Static config setters → `FetchLimits` (Task 1). Other entry points → `JWKS.fetchOnce` / `OpenIDConnect.discover` (Tasks 6, 12).
- [x] §5.3 deleted package: oauth2 package removed in Task 14, including `module-info.java` exports.
- [x] §5.4 renames: `JWKSource → JWKS` (Task 9), `currentKids → keyIds` (Task 10), `fromWellKnownConfiguration → fromWellKnown` (rename done as part of Task 9), `JWKSRefreshException → JWKSFetchException` (Task 7).
