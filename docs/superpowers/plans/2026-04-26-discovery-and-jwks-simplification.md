# Discovery + JWKS Simplification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement spec `specs/7.0-discovery-and-jwks-simplification.md` (rev 2): promote OIDC discovery to a first-class type, rename `JWKSource` → `JWKS` with raw-JWK lookup and new factories, replace process-global hardening config with per-instance `FetchLimits`, and delete the OAuth-only metadata classes.

**Architecture:** New top-level types `OpenIDConnectConfiguration`, `OpenIDConnectException`, `FetchLimits`. New static methods `OpenIDConnect.discover(...)` and `OpenIDConnect.discoverFromWellKnown(...)`. Class rename `JWKSource` → `JWKS` with new instance methods (`get`, `keys`, `keyIds`), new factories (`fromConfiguration`, `of`, `fetchOnce`), and the construction-time discovery hop replacing per-refresh discovery. Hardened JSON parsing extracted to `internal/HardenedJSON`. Same-origin redirect policy on every fetch. OAuth-only classes (`AuthorizationServerMetaData`, `ServerMetaDataHelper`, `JSONWebKeySetHelper`) deleted; `oauth2/` package removed.

**Tech Stack:** Java 21, TestNG, the Latte CLI build (`latte build`, `latte test`, `latte test --jca`, `latte test --fips`). Zero compile-scope dependencies — do not add any. Project-specific rules in `.claude/rules/code-conventions.md` (acronyms uppercase, alphabetized members, no blank lines between fields, sentence-style Javadoc, class-member ordering by visibility) and `.claude/rules/error-messages.md` (`[value]` brackets in exception/log messages) are non-negotiable.

**Spec sections referenced:** This plan implements §1–§5 of the spec. §6 (changelog) is project documentation produced at release time, not in this plan. §7 items are explicitly out of scope.

**Branch:** `robotdan/simpler` (worktree at `.worktrees/robotdan/simpler`).

**Baseline before starting:** `latte test --jca` reports 11149 pass, 0 fail, 3 skip. Any new failures introduced during a task must be fixed before that task's commit.

**Conventions for every task:**
- TDD discipline: write the failing test first, run it, watch it fail with the expected reason, then implement.
- One commit per task. Use Conventional Commits style (`feat:`, `refactor:`, `test:`, `chore:`); keep the subject ≤72 chars.
- Run `latte test --jca` at minimum before committing. Run the full `latte test` (both JCA and FIPS) before the verification task at the end.
- Acronyms upper-case throughout (`URI` not `Uri`, `JSON` not `Json`, `JWKS` not `Jwks`).
- All exception/log messages wrap runtime values in `[value]` (never `'value'` or `"value"`).
- License header: this work is brand-new code, use the MIT header `Copyright (c) 2026, The Latte Project, All Rights Reserved` (see `JWKSource.java` lines 1-22 for the exact text). Inherited files keep their existing Apache-2.0 headers.

---

## Task 1: `FetchLimits` (per-instance hardening config)

**Spec reference:** §4.

**Files:**
- Create: `src/main/java/org/lattejava/jwt/FetchLimits.java`
- Test: `src/test/java/org/lattejava/jwt/FetchLimitsTest.java`

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/FetchLimitsTest.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header — copy from JWKSource.java]
 */
package org.lattejava.jwt;

import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;

public class FetchLimitsTest extends BaseTest {
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
  }

  @Test
  public void defaults_returns_singleton() {
    assertSame(FetchLimits.defaults(), FetchLimits.defaults());
  }

  @Test
  public void builder_overrides_each_field() {
    FetchLimits limits = FetchLimits.builder()
        .maxResponseBytes(2048)
        .maxRedirects(7)
        .maxNestingDepth(8)
        .maxNumberLength(500)
        .maxObjectMembers(50)
        .maxArrayElements(100)
        .allowDuplicateJSONKeys(true)
        .build();
    assertEquals(limits.maxResponseBytes(), 2048);
    assertEquals(limits.maxRedirects(), 7);
    assertEquals(limits.maxNestingDepth(), 8);
    assertEquals(limits.maxNumberLength(), 500);
    assertEquals(limits.maxObjectMembers(), 50);
    assertEquals(limits.maxArrayElements(), 100);
    assertEquals(limits.allowDuplicateJSONKeys(), true);
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
  public void builder_allows_zero_redirects() {
    // Zero redirects disables redirect following — explicitly permitted, unlike the other limits.
    FetchLimits limits = FetchLimits.builder().maxRedirects(0).build();
    assertEquals(limits.maxRedirects(), 0);
  }

  @Test
  public void builder_rejects_negative_redirects() {
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxRedirects(-1));
  }

  @Test
  public void builder_is_reusable() {
    FetchLimits.Builder b = FetchLimits.builder().maxResponseBytes(1000);
    FetchLimits a = b.build();
    FetchLimits c = b.maxResponseBytes(2000).build();
    assertEquals(a.maxResponseBytes(), 1000);
    assertEquals(c.maxResponseBytes(), 2000);
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=FetchLimitsTest`
Expected: compilation failure — `FetchLimits` does not exist.

- [ ] **Step 3: Implement `FetchLimits`**

Create `src/main/java/org/lattejava/jwt/FetchLimits.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt;

/**
 * Per-instance hardening limits for HTTP fetches and JSON parsing performed by
 * {@link org.lattejava.jwt.jwks.JWKS} and {@link OpenIDConnect#discover(String)}.
 * Replaces the volatile static configuration that lived on the deleted
 * {@code JSONWebKeySetHelper} and {@code ServerMetaDataHelper}.
 *
 * <p>Instances are immutable. Defaults match historical behavior exactly. The
 * response cap and JSON parser caps cannot be disabled — the corresponding
 * setters reject zero or negative values. {@link #maxRedirects()} is the
 * exception: zero is permitted and disables redirect following.</p>
 */
public final class FetchLimits {
  private static final FetchLimits DEFAULTS = builder().build();

  private final boolean allowDuplicateJSONKeys;
  private final int maxArrayElements;
  private final int maxNestingDepth;
  private final int maxNumberLength;
  private final int maxObjectMembers;
  private final int maxRedirects;
  private final int maxResponseBytes;

  private FetchLimits(Builder b) {
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

  public boolean allowDuplicateJSONKeys() { return allowDuplicateJSONKeys; }
  public int maxArrayElements() { return maxArrayElements; }
  public int maxNestingDepth() { return maxNestingDepth; }
  public int maxNumberLength() { return maxNumberLength; }
  public int maxObjectMembers() { return maxObjectMembers; }
  public int maxRedirects() { return maxRedirects; }
  public int maxResponseBytes() { return maxResponseBytes; }

  public static final class Builder {
    private boolean allowDuplicateJSONKeys = false;
    private int maxArrayElements = 10_000;
    private int maxNestingDepth = 16;
    private int maxNumberLength = 1_000;
    private int maxObjectMembers = 1_000;
    private int maxRedirects = 3;
    private int maxResponseBytes = 1024 * 1024;

    private Builder() {}

    public Builder allowDuplicateJSONKeys(boolean allow) {
      this.allowDuplicateJSONKeys = allow;
      return this;
    }

    public Builder maxArrayElements(int n) {
      requirePositive(n, "maxArrayElements");
      this.maxArrayElements = n;
      return this;
    }

    public Builder maxNestingDepth(int n) {
      requirePositive(n, "maxNestingDepth");
      this.maxNestingDepth = n;
      return this;
    }

    public Builder maxNumberLength(int n) {
      requirePositive(n, "maxNumberLength");
      this.maxNumberLength = n;
      return this;
    }

    public Builder maxObjectMembers(int n) {
      requirePositive(n, "maxObjectMembers");
      this.maxObjectMembers = n;
      return this;
    }

    public Builder maxRedirects(int n) {
      if (n < 0) {
        throw new IllegalArgumentException("maxRedirects must be >= 0 but found [" + n + "]");
      }
      this.maxRedirects = n;
      return this;
    }

    public Builder maxResponseBytes(int n) {
      requirePositive(n, "maxResponseBytes");
      this.maxResponseBytes = n;
      return this;
    }

    public FetchLimits build() {
      return new FetchLimits(this);
    }

    private static void requirePositive(int n, String field) {
      if (n <= 0) {
        throw new IllegalArgumentException(field + " must be > 0 but found [" + n + "]");
      }
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `latte test --jca --test=FetchLimitsTest`
Expected: PASS — 7 tests passing.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/FetchLimits.java src/test/java/org/lattejava/jwt/FetchLimitsTest.java
git commit -m "feat(fetch): add FetchLimits for per-instance fetch/parse hardening"
```

---

## Task 2: `HardenedJSON` (internal hardened-parse utility)

**Spec reference:** §5.2 row "`parseJSON(InputStream)`".

**Files:**
- Create: `src/main/java/org/lattejava/jwt/internal/HardenedJSON.java`
- Test: `src/test/java/org/lattejava/jwt/internal/HardenedJSONTest.java`

This step extracts the body of today's `JSONWebKeySetHelper.parseJSON(InputStream)` into an internal helper that takes its limits via `FetchLimits` rather than reading from static fields. Today the helper still exists; we add the new utility now and migrate callers in later tasks. The helper class is package-private to `internal/` (do not export from `jwt/`).

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/internal/HardenedJSONTest.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
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
  public void parses_minimal_object() {
    Map<String, Object> result = parse("{\"a\":1}", FetchLimits.defaults());
    assertEquals(result, Map.of("a", 1L));
  }

  @Test
  public void rejects_object_exceeding_member_cap() {
    StringBuilder sb = new StringBuilder("{");
    for (int i = 0; i < 5; i++) {
      if (i > 0) sb.append(",");
      sb.append("\"k").append(i).append("\":").append(i);
    }
    sb.append("}");
    FetchLimits tight = FetchLimits.builder().maxObjectMembers(3).build();
    assertThrows(JSONProcessingException.class, () -> parse(sb.toString(), tight));
  }

  @Test
  public void rejects_duplicate_keys_when_disallowed() {
    String json = "{\"k\":1,\"k\":2}";
    assertThrows(JSONProcessingException.class, () -> parse(json, FetchLimits.defaults()));
  }

  @Test
  public void permits_duplicate_keys_when_allowed() {
    String json = "{\"k\":1,\"k\":2}";
    FetchLimits perm = FetchLimits.builder().allowDuplicateJSONKeys(true).build();
    Map<String, Object> result = parse(json, perm);
    assertEquals(result.get("k"), 2L);
  }

  private static Map<String, Object> parse(String json, FetchLimits limits) {
    return HardenedJSON.parse(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)), limits);
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=HardenedJSONTest`
Expected: compilation failure — `HardenedJSON` does not exist.

- [ ] **Step 3: Implement `HardenedJSON`**

Create `src/main/java/org/lattejava/jwt/internal/HardenedJSON.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt.internal;

import org.lattejava.jwt.FetchLimits;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.JSONProcessor;
import org.lattejava.jwt.LatteJSONProcessor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * Reads an input stream fully and parses the bytes as a top-level JSON object,
 * applying the parse-time hardening limits in the supplied {@link FetchLimits}.
 * The caller is responsible for any per-hop response-size cap on the
 * {@code InputStream} itself; this helper only enforces the JSON-structure caps
 * documented on {@link FetchLimits}.
 */
public final class HardenedJSON {
  private HardenedJSON() {}

  public static Map<String, Object> parse(InputStream is, FetchLimits limits) {
    JSONProcessor processor = new LatteJSONProcessor(
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
      throw new JSONProcessingException("Failed to read input stream", e);
    }
  }
}
```

Note: `JSONProcessingException` already exists at `org.lattejava.jwt.JSONProcessingException`. Verify by reading that file before this step.

- [ ] **Step 4: Run tests to verify they pass**

Run: `latte test --jca --test=HardenedJSONTest`
Expected: PASS — 4 tests passing.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/internal/HardenedJSON.java src/test/java/org/lattejava/jwt/internal/HardenedJSONTest.java
git commit -m "feat(internal): add HardenedJSON parse utility taking FetchLimits"
```

---

## Task 3: `OpenIDConnectException`

**Spec reference:** §1.3.

**Files:**
- Create: `src/main/java/org/lattejava/jwt/OpenIDConnectException.java`
- Test: `src/test/java/org/lattejava/jwt/OpenIDConnectExceptionTest.java`

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/OpenIDConnectExceptionTest.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt;

import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

public class OpenIDConnectExceptionTest extends BaseTest {
  @Test
  public void extends_runtime_exception_not_jwt_exception() {
    OpenIDConnectException e = new OpenIDConnectException("boom");
    assertTrue(e instanceof RuntimeException);
    assertFalse(e instanceof JWTException);
  }

  @Test
  public void carries_message_and_cause() {
    Throwable cause = new RuntimeException("inner");
    OpenIDConnectException e = new OpenIDConnectException("boom", cause);
    assertEquals(e.getMessage(), "boom");
    assertSame(e.getCause(), cause);
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=OpenIDConnectExceptionTest`
Expected: compilation failure — `OpenIDConnectException` does not exist.

- [ ] **Step 3: Implement `OpenIDConnectException`**

Create `src/main/java/org/lattejava/jwt/OpenIDConnectException.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt;

/**
 * Thrown by {@link OpenIDConnect#discover(String)} and
 * {@link OpenIDConnect#discoverFromWellKnown(String)} for any failure of the
 * discovery fetch: network error, non-2xx HTTP status, response too large,
 * cross-origin redirect rejection, JSON parse failure, or a discovery document
 * that does not honor OIDC Discovery 1.0 (missing {@code jwks_uri}, missing
 * {@code issuer}, or an {@code issuer} value that does not match the request).
 *
 * <p>Extends {@link RuntimeException} rather than {@link JWTException}:
 * discovery is not a JWT operation, and putting it under {@code JWTException}
 * would mislead {@code catch} blocks targeting JWT-specific failures.</p>
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `latte test --jca --test=OpenIDConnectExceptionTest`
Expected: PASS — 2 tests passing.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/OpenIDConnectException.java src/test/java/org/lattejava/jwt/OpenIDConnectExceptionTest.java
git commit -m "feat(oidc): add OpenIDConnectException (extends RuntimeException)"
```

---

## Task 4: `OpenIDConnectConfiguration` POJO

**Spec reference:** §1.1, §1.2.

**Files:**
- Create: `src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java`
- Test: `src/test/java/org/lattejava/jwt/OpenIDConnectConfigurationTest.java`

This is a large but mechanical class: ~45 typed accessors, a `Builder`, `equals`/`hashCode`, `toJSON`, `toSerializableMap`. The full field list is in spec §1.1 Table — every row's fields must have a private final field, a builder setter, and a typed accessor.

**Reference for pattern:** `src/main/java/org/lattejava/jwt/oauth2/AuthorizationServerMetaData.java` (existing class) demonstrates the exact shape this new class adopts. Read it before starting. Differences:
- Field set is the spec §1.1 superset (~45 fields vs 23).
- Acronym casing is corrected: `jwksURI()` not `jwksUri()`, `opPolicyURI()` not `opPolicyUri()`, `opTosURI()` not `opTosUri()`.
- No public `fromMap(Map)` factory (spec §1.2 explicitly removes it). Internal parsing happens in Task 5 inside the discovery code path.
- `toSerializableMap()` is preserved (round-trip serialization).
- `claim(String, Object)` on Builder for unknown / extension claims (matches `AuthorizationServerMetaData.Builder.claim(...)`).

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/org/lattejava/jwt/OpenIDConnectConfigurationTest.java`:

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt;

import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class OpenIDConnectConfigurationTest extends BaseTest {
  @Test
  public void builder_constructs_minimal_instance_with_all_other_fields_null() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("https://example.com")
        .build();
    assertEquals(cfg.issuer(), "https://example.com");
    assertNull(cfg.jwksURI());
    assertNull(cfg.userinfoEndpoint());
    assertNull(cfg.endSessionEndpoint());
    assertEquals(cfg.otherClaims(), Map.of());
  }

  @Test
  public void builder_returns_independent_instances_per_build() {
    OpenIDConnectConfiguration.Builder b = OpenIDConnectConfiguration.builder().issuer("a");
    OpenIDConnectConfiguration first = b.build();
    OpenIDConnectConfiguration second = b.issuer("b").build();
    assertEquals(first.issuer(), "a");
    assertEquals(second.issuer(), "b");
  }

  @Test
  public void list_accessors_return_unmodifiable_views() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .scopesSupported(List.of("openid", "email"))
        .build();
    assertThrows(UnsupportedOperationException.class, () -> cfg.scopesSupported().add("profile"));
  }

  @Test
  public void otherClaims_round_trip_through_toSerializableMap() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("https://example.com")
        .claim("mfa_challenge_endpoint", "https://example.com/mfa")
        .build();
    Map<String, Object> map = cfg.toSerializableMap();
    assertEquals(map.get("issuer"), "https://example.com");
    assertEquals(map.get("mfa_challenge_endpoint"), "https://example.com/mfa");
  }

  @Test
  public void claim_rejects_recognized_keys() {
    OpenIDConnectConfiguration.Builder b = OpenIDConnectConfiguration.builder();
    assertThrows(IllegalArgumentException.class, () -> b.claim("issuer", "x"));
    assertThrows(IllegalArgumentException.class, () -> b.claim("jwks_uri", "x"));
  }

  @Test
  public void equals_and_hashCode_value_based() {
    OpenIDConnectConfiguration a = OpenIDConnectConfiguration.builder().issuer("x").build();
    OpenIDConnectConfiguration b = OpenIDConnectConfiguration.builder().issuer("x").build();
    OpenIDConnectConfiguration c = OpenIDConnectConfiguration.builder().issuer("y").build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertNotEquals(a, c);
  }

  @Test
  public void toJSON_produces_valid_json() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("https://example.com")
        .jwksURI("https://example.com/jwks.json")
        .build();
    String json = cfg.toJSON();
    assertTrue(json.contains("\"issuer\":\"https://example.com\""));
    assertTrue(json.contains("\"jwks_uri\":\"https://example.com/jwks.json\""));
  }

  @Test
  public void acronym_accessors_present() {
    // Existence test: methods that the acronym rule moved from Uri → URI must compile.
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .jwksURI("https://example.com/jwks.json")
        .opPolicyURI("https://example.com/policy")
        .opTosURI("https://example.com/tos")
        .build();
    assertNotNull(cfg.jwksURI());
    assertNotNull(cfg.opPolicyURI());
    assertNotNull(cfg.opTosURI());
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `latte test --jca --test=OpenIDConnectConfigurationTest`
Expected: compilation failure — `OpenIDConnectConfiguration` does not exist.

- [ ] **Step 3: Implement `OpenIDConnectConfiguration`**

Create `src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java`. Use `oauth2/AuthorizationServerMetaData.java` as the structural template — fields → constructor → static `immutableCopy` → public accessors → `toSerializableMap` → `equals`/`hashCode`/`toJSON`/`toString` → `builder()` → `Builder` class with one setter per field, plus `claim(String, Object)` that rejects registered names.

Field set (each is `private final`, has a builder setter, has a typed accessor — alphabetized within visibility per `code-conventions.md`):

| JSON name | Java identifier | Type |
|---|---|---|
| `acr_values_supported` | `acrValuesSupported` | `List<String>` |
| `authorization_endpoint` | `authorizationEndpoint` | `String` |
| `backchannel_logout_session_supported` | `backchannelLogoutSessionSupported` | `Boolean` |
| `backchannel_logout_supported` | `backchannelLogoutSupported` | `Boolean` |
| `check_session_iframe` | `checkSessionIframe` | `String` |
| `claim_types_supported` | `claimTypesSupported` | `List<String>` |
| `claims_locales_supported` | `claimsLocalesSupported` | `List<String>` |
| `claims_parameter_supported` | `claimsParameterSupported` | `Boolean` |
| `claims_supported` | `claimsSupported` | `List<String>` |
| `code_challenge_methods_supported` | `codeChallengeMethodsSupported` | `List<String>` |
| `display_values_supported` | `displayValuesSupported` | `List<String>` |
| `end_session_endpoint` | `endSessionEndpoint` | `String` |
| `frontchannel_logout_session_supported` | `frontchannelLogoutSessionSupported` | `Boolean` |
| `frontchannel_logout_supported` | `frontchannelLogoutSupported` | `Boolean` |
| `grant_types_supported` | `grantTypesSupported` | `List<String>` |
| `id_token_encryption_alg_values_supported` | `idTokenEncryptionAlgValuesSupported` | `List<String>` |
| `id_token_encryption_enc_values_supported` | `idTokenEncryptionEncValuesSupported` | `List<String>` |
| `id_token_signing_alg_values_supported` | `idTokenSigningAlgValuesSupported` | `List<String>` |
| `introspection_endpoint` | `introspectionEndpoint` | `String` |
| `introspection_endpoint_auth_methods_supported` | `introspectionEndpointAuthMethodsSupported` | `List<String>` |
| `introspection_endpoint_auth_signing_alg_values_supported` | `introspectionEndpointAuthSigningAlgValuesSupported` | `List<String>` |
| `issuer` | `issuer` | `String` |
| `jwks_uri` | `jwksURI` | `String` |
| `op_policy_uri` | `opPolicyURI` | `String` |
| `op_tos_uri` | `opTosURI` | `String` |
| `registration_endpoint` | `registrationEndpoint` | `String` |
| `request_object_encryption_alg_values_supported` | `requestObjectEncryptionAlgValuesSupported` | `List<String>` |
| `request_object_encryption_enc_values_supported` | `requestObjectEncryptionEncValuesSupported` | `List<String>` |
| `request_object_signing_alg_values_supported` | `requestObjectSigningAlgValuesSupported` | `List<String>` |
| `request_parameter_supported` | `requestParameterSupported` | `Boolean` |
| `request_uri_parameter_supported` | `requestURIParameterSupported` | `Boolean` |
| `require_request_uri_registration` | `requireRequestURIRegistration` | `Boolean` |
| `response_modes_supported` | `responseModesSupported` | `List<String>` |
| `response_types_supported` | `responseTypesSupported` | `List<String>` |
| `revocation_endpoint` | `revocationEndpoint` | `String` |
| `revocation_endpoint_auth_methods_supported` | `revocationEndpointAuthMethodsSupported` | `List<String>` |
| `revocation_endpoint_auth_signing_alg_values_supported` | `revocationEndpointAuthSigningAlgValuesSupported` | `List<String>` |
| `scopes_supported` | `scopesSupported` | `List<String>` |
| `service_documentation` | `serviceDocumentation` | `String` |
| `subject_types_supported` | `subjectTypesSupported` | `List<String>` |
| `token_endpoint` | `tokenEndpoint` | `String` |
| `token_endpoint_auth_methods_supported` | `tokenEndpointAuthMethodsSupported` | `List<String>` |
| `token_endpoint_auth_signing_alg_values_supported` | `tokenEndpointAuthSigningAlgValuesSupported` | `List<String>` |
| `ui_locales_supported` | `uiLocalesSupported` | `List<String>` |
| `userinfo_encryption_alg_values_supported` | `userinfoEncryptionAlgValuesSupported` | `List<String>` |
| `userinfo_encryption_enc_values_supported` | `userinfoEncryptionEncValuesSupported` | `List<String>` |
| `userinfo_endpoint` | `userinfoEndpoint` | `String` |
| `userinfo_signing_alg_values_supported` | `userinfoSigningAlgValuesSupported` | `List<String>` |

Plus an `otherClaims : Map<String, Object>` field (unmodifiable copy in constructor; mutable `LinkedHashMap` in builder).

The `REGISTERED` `Set<String>` (used by `Builder#claim(name, value)` to reject recognized keys) is the JSON-name column. Initialize as a `Set.of(...)` of all 48 names.

`toSerializableMap()` follows `AuthorizationServerMetaData.toSerializableMap()`: alphabetize the `putIfPresent` calls by JSON name, then append non-registered `otherClaims` entries.

Skeleton (showing the structural pattern; you must add every field from the table above):

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * OpenID Connect Discovery 1.0 Provider Metadata, plus RFC 8414 OAuth 2.0
 * Authorization Server Metadata fields and the routinely-deployed OIDC
 * extensions (RP-Initiated Logout, Session Management, Front-/Back-Channel
 * Logout). Every field is nullable: a pure-OAuth response will have null
 * OIDC-specific fields, and an OIDC response without RFC 8414 extras will
 * have null introspection / revocation fields.
 *
 * <p>Immutable. Construct via {@link #builder()}. Round-trip via
 * {@link #toSerializableMap()} through a {@link JSONProcessor}.</p>
 */
public final class OpenIDConnectConfiguration {
  private static final Set<String> REGISTERED = Set.of(
      "acr_values_supported",
      "authorization_endpoint",
      // ... every JSON name from the table above, alphabetized
      "userinfo_signing_alg_values_supported"
  );

  private final List<String> acrValuesSupported;
  private final String authorizationEndpoint;
  // ... every field from the table above, alphabetized
  private final List<String> userinfoSigningAlgValuesSupported;
  private final Map<String, Object> otherClaims;

  private OpenIDConnectConfiguration(Builder b) {
    this.acrValuesSupported = immutableCopy(b.acrValuesSupported);
    this.authorizationEndpoint = b.authorizationEndpoint;
    // ... assign every field, with immutableCopy(...) for List-typed fields
    this.otherClaims = Collections.unmodifiableMap(new LinkedHashMap<>(b.otherClaims));
  }

  public static Builder builder() {
    return new Builder();
  }

  // Accessors — alphabetized
  public List<String> acrValuesSupported() { return acrValuesSupported; }
  public String authorizationEndpoint() { return authorizationEndpoint; }
  // ... every accessor, alphabetized
  public Map<String, Object> otherClaims() { return otherClaims; }

  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    putIfPresent(out, "acr_values_supported", acrValuesSupported);
    putIfPresent(out, "authorization_endpoint", authorizationEndpoint);
    // ... every JSON name from the table above, alphabetized
    putIfPresent(out, "userinfo_signing_alg_values_supported", userinfoSigningAlgValuesSupported);
    for (Map.Entry<String, Object> e : otherClaims.entrySet()) {
      if (e.getValue() != null && !REGISTERED.contains(e.getKey())) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  public String toJSON() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  @Override public String toString() { return toJSON(); }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof OpenIDConnectConfiguration that)) return false;
    return Objects.equals(acrValuesSupported, that.acrValuesSupported)
        && Objects.equals(authorizationEndpoint, that.authorizationEndpoint)
        // ... every field
        && Objects.equals(userinfoSigningAlgValuesSupported, that.userinfoSigningAlgValuesSupported)
        && Objects.equals(otherClaims, that.otherClaims);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        acrValuesSupported,
        authorizationEndpoint,
        // ... every field
        userinfoSigningAlgValuesSupported,
        otherClaims);
  }

  private static List<String> immutableCopy(List<String> list) {
    return list == null ? null : List.copyOf(list);
  }

  private static void putIfPresent(Map<String, Object> out, String key, Object value) {
    if (value != null) {
      out.put(key, value);
    }
  }

  public static final class Builder {
    private List<String> acrValuesSupported;
    private String authorizationEndpoint;
    // ... every field, alphabetized; defaults: null for scalars and Lists, empty LinkedHashMap for otherClaims
    private List<String> userinfoSigningAlgValuesSupported;
    private final Map<String, Object> otherClaims = new LinkedHashMap<>();

    private Builder() {}

    public Builder acrValuesSupported(List<String> v) { this.acrValuesSupported = v; return this; }
    public Builder authorizationEndpoint(String v) { this.authorizationEndpoint = v; return this; }
    // ... every setter, alphabetized
    public Builder userinfoSigningAlgValuesSupported(List<String> v) { this.userinfoSigningAlgValuesSupported = v; return this; }

    public Builder claim(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (REGISTERED.contains(name)) {
        throw new IllegalArgumentException("Cannot add a registered configuration claim [" + name + "]; use the typed setter");
      }
      otherClaims.put(name, value);
      return this;
    }

    public OpenIDConnectConfiguration build() {
      return new OpenIDConnectConfiguration(this);
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `latte test --jca --test=OpenIDConnectConfigurationTest`
Expected: PASS — 8 tests passing.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java src/test/java/org/lattejava/jwt/OpenIDConnectConfigurationTest.java
git commit -m "feat(oidc): add OpenIDConnectConfiguration POJO"
```

---

## Task 5: `OpenIDConnect.discover` / `discoverFromWellKnown`

**Spec reference:** §2.

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/OpenIDConnect.java` (add 8 static methods + private fetch path)
- Test: `src/test/java/org/lattejava/jwt/OpenIDConnectDiscoverTest.java`

This task adds the discovery entry points. The implementation reuses `internal/http/AbstractHTTPHelper` for the actual HTTP fetch (same hardening primitives `JSONWebKeySetHelper` uses today: per-hop body cap, manual redirect counting). New behavior: same-origin redirect rejection (spec §3.7) and OIDC §4.3 issuer-equality validation in `discover(issuer)`.

**Note on `AbstractHTTPHelper`:** The existing helper takes `maxResponseBytes` and `maxRedirects` as method parameters (not from static config). Reuse `get(connection, maxResponseBytes, maxRedirects, parser, exceptionMapper)`. The same-origin check is a NEW capability — it requires extending the helper or adding the check in the discovery code path. Read `AbstractHTTPHelper.java` first to decide. Recommended: add a same-origin redirect predicate parameter to a new overload of `get(...)`. This new overload will also be used by `JWKS` in Task 11/13 — design it accordingly.

- [ ] **Step 1: Extend `AbstractHTTPHelper` with same-origin redirect support**

Read `src/main/java/org/lattejava/jwt/internal/http/AbstractHTTPHelper.java` first. Then add a new protected overload `get(...)` that takes a `boolean sameOriginRedirectsOnly` flag, and inside the redirect-following loop, when `sameOriginRedirectsOnly` is true, compare the (scheme, host, port) of the redirect target against the original request and throw the supplied exception (with message: `"Refusing cross-origin redirect from [<originalScheme>://<originalHost>:<originalPort>] to [<targetScheme>://<targetHost>:<targetPort>]"`) when they differ. Do not change the existing overloads' behavior.

Update existing callers (`JSONWebKeySetHelper.retrieveKeysFromJWKS`, `retrieveJWKSURI`, `retrieveJWKSResponseFromJWKS`, etc., and `ServerMetaDataHelper.retrieveFromWellKnownConfiguration`) to pass `sameOriginRedirectsOnly=false` for now — the current behavior is preserved for these legacy callers (they will be removed in Tasks 14-15). New `JWKS` and `OpenIDConnect.discover` paths will pass `true`.

Add tests for the same-origin behavior in a new `src/test/java/org/lattejava/jwt/internal/http/AbstractHTTPHelperSameOriginTest.java` using `com.sun.net.httpserver.HttpServer` (see how `JWKSourceTest` sets up a local server) covering:
- Same-host redirect followed (success)
- Different-host redirect rejected (exception)
- Different-port redirect rejected
- Different-scheme redirect rejected
- `maxRedirects=0` rejects any redirect regardless of origin

- [ ] **Step 2: Run AbstractHTTPHelper tests**

Run: `latte test --jca --test=AbstractHTTPHelperSameOriginTest`
Expected: PASS.

- [ ] **Step 3: Commit the helper extension**

```bash
git add src/main/java/org/lattejava/jwt/internal/http/AbstractHTTPHelper.java src/test/java/org/lattejava/jwt/internal/http/AbstractHTTPHelperSameOriginTest.java
git commit -m "feat(http): add same-origin redirect predicate to AbstractHTTPHelper.get"
```

- [ ] **Step 4: Write the failing tests for `OpenIDConnect.discover`**

Create `src/test/java/org/lattejava/jwt/OpenIDConnectDiscoverTest.java`. Use the same `HttpServer`-based test pattern `JWKSourceTest` uses (read it first). The fixture is a per-test `HttpServer` bound to `localhost:0` (free port), with one or two contexts that return a JSON body the test controls.

One complete reference test (use this as the pattern for the rest):

```java
/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * [full MIT header]
 */
package org.lattejava.jwt;

import com.sun.net.httpserver.HttpServer;
import org.lattejava.jwt.testing.BaseTest;
import org.testng.annotations.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class OpenIDConnectDiscoverTest extends BaseTest {
  @Test
  public void discover_fetches_wellknown_and_returns_populated_configuration() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int port = server.getAddress().getPort();
    String issuer = "http://127.0.0.1:" + port;
    String body = "{\"issuer\":\"" + issuer + "\","
        + "\"jwks_uri\":\"" + issuer + "/jwks.json\","
        + "\"authorization_endpoint\":\"" + issuer + "/auth\","
        + "\"token_endpoint\":\"" + issuer + "/token\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    server.createContext("/.well-known/openid-configuration", exchange -> {
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, bodyBytes.length);
      exchange.getResponseBody().write(bodyBytes);
      exchange.close();
    });
    server.start();
    try {
      OpenIDConnectConfiguration cfg = OpenIDConnect.discover(issuer);
      assertEquals(cfg.issuer(), issuer);
      assertEquals(cfg.jwksURI(), issuer + "/jwks.json");
      assertEquals(cfg.authorizationEndpoint(), issuer + "/auth");
      assertEquals(cfg.responseTypesSupported(), java.util.List.of("code"));
      assertEquals(cfg.subjectTypesSupported(), java.util.List.of("public"));
      assertEquals(cfg.idTokenSigningAlgValuesSupported(), java.util.List.of("RS256"));
    } finally {
      server.stop(0);
    }
  }
}
```

Then add the following further tests, each following the same fixture pattern (one `HttpServer`, one or two contexts, request, assert, stop). Wrap any per-test response shaping into a small private helper (`startServer(String wellKnownBody)` returning the issuer URL plus the server) if it cuts repetition:

| Test method | Fixture | Assertion |
|---|---|---|
| `discover_trims_trailing_slash_on_issuer` | well-known returns `issuer` matching the URL **without** trailing slash | passing `"http://...:port/"` (with slash) succeeds, returned `cfg.issuer()` equals the no-slash form |
| `discover_rejects_issuer_mismatch` | well-known returns `"issuer":"https://attacker.example.com"` | `OpenIDConnectException` thrown; message contains `[https://attacker.example.com]` and the expected issuer in `[value]` brackets |
| `discoverFromWellKnown_does_not_validate_issuer` | well-known returns any `issuer` value | call succeeds; `cfg.issuer()` equals what the server returned |
| `discover_rejects_cross_origin_redirect` | well-known returns `302` to a URL on a different host | `OpenIDConnectException` thrown; message contains `"Refusing cross-origin redirect"` |
| `discover_rejects_oversize_response` | well-known returns a body larger than 64 bytes | `OpenIDConnect.discover(issuer, FetchLimits.builder().maxResponseBytes(64).build(), null)` throws `OpenIDConnectException` |
| `discover_rejects_non_2xx_response` | well-known returns `500` | `OpenIDConnectException` thrown; cause is `HTTPResponseException` |
| `discover_applies_customizer_to_connection` | well-known echoes back a custom request header into the response body | passing `conn -> conn.setRequestProperty("X-Probe", "1")` causes the body's echo field to read `"1"` |
| `discover_routes_unknown_fields_to_otherClaims` | well-known body includes `"vendor_extension": {"x": 1}` | `cfg.otherClaims().get("vendor_extension")` is the parsed map |

(8 additional tests + the reference test = 9 total. Each ~30-50 lines.)

- [ ] **Step 5: Run tests to verify they fail**

Run: `latte test --jca --test=OpenIDConnectDiscoverTest`
Expected: compilation failure — `OpenIDConnect.discover` does not exist.

- [ ] **Step 6: Implement `OpenIDConnect.discover` / `discoverFromWellKnown` and the typed-field router**

Modify `src/main/java/org/lattejava/jwt/OpenIDConnect.java`. Add:

- Eight new static methods (4 × `discover`, 4 × `discoverFromWellKnown` — see spec §2 for exact signatures).
- A private `static OpenIDConnectConfiguration fetch(String url, String expectedIssuer, FetchLimits limits, Consumer<HttpURLConnection> customizer)` that:
  - Builds the `HttpURLConnection` via `AbstractHTTPHelper.buildURLConnection(url, OpenIDConnectException::new)`.
  - Applies the customizer if non-null.
  - Calls `AbstractHTTPHelper.get(connection, limits.maxResponseBytes(), limits.maxRedirects(), sameOriginRedirectsOnly=true, parser, OpenIDConnectException::new)`.
  - Inside the parser, calls `HardenedJSON.parse(inputStream, limits)` to get the `Map<String, Object>`.
  - Calls a new private `static OpenIDConnectConfiguration fromMap(Map<String, Object> map)` that walks the map and routes recognized keys to typed builder setters and unrecognized keys to `Builder.claim(...)`. Use `AuthorizationServerMetaData.fromMap(...)` (lines 284–318 of the existing file) as the structural template — replicate its switch with all OIDC fields and acronym corrections (`jwksURI` not `jwksUri`, etc.). Apply the same string-or-list type validation it does (`stringList(value, name)` helper with `IllegalArgumentException` on non-string elements).
  - If `expectedIssuer != null`, compares `cfg.issuer()` to `expectedIssuer` byte-for-byte and throws `OpenIDConnectException` on mismatch with message: `"Issuer mismatch: discovery document at [" + url + "] returned issuer [" + cfg.issuer() + "], expected [" + expectedIssuer + "]"`.
  - If `cfg.jwksURI() == null || cfg.jwksURI().isEmpty()`, throws `OpenIDConnectException` with message: `"Discovery document at [" + url + "] is missing the [jwks_uri] property"`.
  - Returns `cfg`.
- The eight public entry points are thin wrappers that compute the URL (issuer trim + path append for `discover`; verbatim for `discoverFromWellKnown`), default `FetchLimits` and `customizer` to defaults / null when omitted, and call `fetch(...)`. `discover(issuer, ...)` passes `expectedIssuer = issuer`; `discoverFromWellKnown(url, ...)` passes `null`.

Method ordering inside the class must match `code-conventions.md` (visibility-then-alphabetical). The eight new public statics interleave with `at_hash` and `c_hash` alphabetically.

- [ ] **Step 7: Run tests to verify they pass**

Run: `latte test --jca --test=OpenIDConnectDiscoverTest`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/main/java/org/lattejava/jwt/OpenIDConnect.java src/test/java/org/lattejava/jwt/OpenIDConnectDiscoverTest.java
git commit -m "feat(oidc): add OpenIDConnect.discover/discoverFromWellKnown"
```

---

## Task 6: Rename `JWKSRefreshException` → `JWKSFetchException`

**Spec reference:** §3.6, §5.4.

**Files:**
- Rename: `src/main/java/org/lattejava/jwt/jwks/JWKSRefreshException.java` → `JWKSFetchException.java`
- Modify: every caller of `JWKSRefreshException` in production and test code

Use `git mv` to preserve history.

- [ ] **Step 1: Rename the file and class**

```bash
git mv src/main/java/org/lattejava/jwt/jwks/JWKSRefreshException.java src/main/java/org/lattejava/jwt/jwks/JWKSFetchException.java
```

Edit the new file:
- Rename the class declaration from `JWKSRefreshException` to `JWKSFetchException`.
- Update both constructor names.
- Update the Javadoc: "Thrown by {@link JWKSource#refresh()} when an operator-driven refresh fails." becomes "Thrown by JWKS refresh, JWKS one-shot fetch, and the initial fetch performed inside {@code JWKS.Builder.build()}."
- Keep the `Reason` enum unchanged.

- [ ] **Step 2: Find all callers**

Run: `grep -rn "JWKSRefreshException" src/ --include='*.java'`
Replace every occurrence with `JWKSFetchException` in:
- `src/main/java/org/lattejava/jwt/jwks/JWKSource.java` (multiple call sites)
- `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java` (test assertions)
- Any other matches

- [ ] **Step 3: Build + test to verify the rename is clean**

Run: `latte test --jca`
Expected: 11149 pass, 0 fail, 3 skip (same as baseline).

- [ ] **Step 4: Commit**

```bash
git add -A src/
git commit -m "refactor(jwks): rename JWKSRefreshException to JWKSFetchException"
```

---

## Task 7: Add `Snapshot.jwkByKid` to `JWKSource` and populate it on every fetch

**Spec reference:** §3.3.

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKSource.java` (Snapshot record + `doRefreshOrThrow`)
- Test: `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java` (add assertions)

This task is preparatory: it threads the source `JSONWebKey` objects through the snapshot before the rename in Task 8. After this task, `JWKSource` retains JWKs alongside Verifiers but does not yet expose a `get(kid)` accessor (added in Task 9).

- [ ] **Step 1: Write the failing test** (we'll assert the new field is populated by adding a package-private accessor temporarily; remove or replace in Task 9)

Edit `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java` and add a new test method that uses an existing `HttpServer` fixture in the file (look for tests like `resolve_returns_verifier_for_known_kid` or similar — read 0-200 first to see the helper setup):

```java
@Test
public void snapshot_retains_source_jwk_alongside_verifier() throws Exception {
  // Use the same JWKS-server fixture pattern other tests use; serve a single key.
  // Then construct a JWKSource against it and assert that the package-private
  // snapshot exposes the JSONWebKey by kid.
  try (JWKSource source = newSourceServingOneKey("kid-1")) {
    Map<String, JSONWebKey> jwkByKid = source.snapshotForTest_jwkByKid();
    assertEquals(jwkByKid.size(), 1);
    assertNotNull(jwkByKid.get("kid-1"));
    assertEquals(jwkByKid.get("kid-1").kid(), "kid-1");
  }
}
```

(`newSourceServingOneKey` is a helper you write or adapt from existing test helpers. `snapshotForTest_jwkByKid` is a temporary package-private accessor we add; remove in Task 9.)

- [ ] **Step 2: Run to verify it fails**

Run: `latte test --jca --test=JWKSourceTest`
Expected: failure on the new test (`snapshotForTest_jwkByKid` does not exist).

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKSource.java`:

1. Modify the `Snapshot` record (currently at the bottom of the file, lines ~648-654):

```java
record Snapshot(
    Map<String, JSONWebKey> jwkByKid,
    Map<String, Verifier> byKid,
    Instant fetchedAt,
    Instant nextDueAt,
    int consecutiveFailures,
    Instant lastFailedRefresh) {}
```

2. Update the constructor's initial `Snapshot` and the `failureSnapshot` paths to provide `jwkByKid`:
   - In the constructor: `this.ref.set(new Snapshot(Map.of(), Map.of(), Instant.EPOCH, Instant.EPOCH, 0, null));`
   - In `failureSnapshot(Snapshot prev, ...)`: `Map<String, JSONWebKey> jwkByKid = (prev == null) ? Map.of() : prev.jwkByKid();` and pass it through.

3. In `doRefreshOrThrow(Snapshot prev)`, build a parallel `Map<String, JSONWebKey> jwkByKid = new LinkedHashMap<>();` and put `jwk` into it whenever `byKid.put(jwk.kid(), v)` succeeds. Wrap with `Collections.unmodifiableMap(new LinkedHashMap<>(jwkByKid))` and pass to the new Snapshot constructor.

4. Add a temporary package-private accessor on `JWKSource`:

```java
// Temporary package-private accessor used by tests during the JWKS rename
// migration. Removed when JWKS.get(String) is added in Task 9.
Map<String, JSONWebKey> snapshotForTest_jwkByKid() {
  return ref.get().jwkByKid();
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `latte test --jca --test=JWKSourceTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKSource.java src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java
git commit -m "refactor(jwks): retain source JWK in Snapshot alongside Verifier"
```

---

## Task 8: Rename `JWKSource` → `JWKS`

**Spec reference:** §3 header, §5.4.

**Files:**
- Rename: `src/main/java/org/lattejava/jwt/jwks/JWKSource.java` → `JWKS.java`
- Rename: `src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java` → `JWKSTest.java`
- Modify: every caller of `JWKSource` in production and test code

Mechanical rename; tests for the new instance methods come in Task 9. The `fromWellKnownConfiguration` factory rename to `fromWellKnown` happens in this same task (it's a public-name change on the renamed class).

- [ ] **Step 1: Rename the files**

```bash
git mv src/main/java/org/lattejava/jwt/jwks/JWKSource.java src/main/java/org/lattejava/jwt/jwks/JWKS.java
git mv src/test/java/org/lattejava/jwt/jwks/JWKSourceTest.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
```

- [ ] **Step 2: Edit `JWKS.java`**

In the new `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:
- Rename the class declaration: `public final class JWKSource` → `public final class JWKS`.
- Rename the private constructor: `JWKSource(Builder b)` → `JWKS(Builder b)`.
- Rename the factory `fromWellKnownConfiguration(String wellKnownURL)` → `fromWellKnown(String wellKnownURL)`.
- Rename the enum constant `WELL_KNOWN` (no rename needed — internal — but verify nothing referenced `fromWellKnownConfiguration` elsewhere).
- Update Javadoc references in this file from `JWKSource` to `JWKS`.
- The `Builder.build()` line `return new JWKSource(this);` becomes `return new JWKS(this);`.
- The `close()` log message `"JWKSource closed"` becomes `"JWKS closed"`.

- [ ] **Step 3: Edit `JWKSTest.java`**

In `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`:
- Rename class `JWKSourceTest` → `JWKSTest`.
- Replace every `JWKSource` reference with `JWKS`.
- Replace every `fromWellKnownConfiguration` reference with `fromWellKnown`.
- The temporary `snapshotForTest_jwkByKid()` accessor stays for now (removed in Task 9).

- [ ] **Step 4: Find and update all other callers**

Run: `grep -rn "JWKSource\|fromWellKnownConfiguration" src/ --include='*.java'`
Replace `JWKSource` with `JWKS` and `fromWellKnownConfiguration` with `fromWellKnown` in every match. Likely callers:
- `src/main/java/org/lattejava/jwt/jwks/JWKSFetchException.java` (Javadoc reference)
- Any other test files referencing `JWKSource` (e.g. integration / JWTDecoder tests)

- [ ] **Step 5: Build + test**

Run: `latte test --jca`
Expected: 11149 pass, 0 fail, 3 skip (the rename is mechanical and behavior-preserving).

- [ ] **Step 6: Commit**

```bash
git add -A src/
git commit -m "refactor(jwks): rename JWKSource to JWKS; fromWellKnownConfiguration to fromWellKnown"
```

---

## Task 9: New `JWKS` instance methods: `get(kid)`, `keys()`, `keyIds()`

**Spec reference:** §3.2.

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

This task adds three public accessors and renames `currentKids()` → `keyIds()`. It also removes the temporary `snapshotForTest_jwkByKid()` from Task 7.

- [ ] **Step 1: Write the failing tests**

In `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java` add tests:

```java
@Test
public void get_returns_jwk_for_known_kid() throws Exception {
  try (JWKS jwks = newSourceServingOneKey("kid-1")) {
    JSONWebKey jwk = jwks.get("kid-1");
    assertNotNull(jwk);
    assertEquals(jwk.kid(), "kid-1");
  }
}

@Test
public void get_returns_null_for_unknown_kid() throws Exception {
  try (JWKS jwks = newSourceServingOneKey("kid-1")) {
    assertNull(jwks.get("not-a-real-kid"));
  }
}

@Test
public void keys_returns_unmodifiable_view_in_endpoint_order() throws Exception {
  try (JWKS jwks = newSourceServingTwoKeys("kid-a", "kid-b")) {
    Collection<JSONWebKey> keys = jwks.keys();
    List<String> kids = keys.stream().map(JSONWebKey::kid).toList();
    assertEquals(kids, List.of("kid-a", "kid-b"));
    assertThrows(UnsupportedOperationException.class, () -> ((Collection<JSONWebKey>) keys).clear());
  }
}

@Test
public void keyIds_renames_currentKids_and_preserves_endpoint_order() throws Exception {
  try (JWKS jwks = newSourceServingTwoKeys("kid-a", "kid-b")) {
    assertEquals(new ArrayList<>(jwks.keyIds()), List.of("kid-a", "kid-b"));
  }
}
```

(Adapt the helper methods to whatever pattern your earlier tests adopted in Task 7. `newSourceServingTwoKeys` returns the keys in the endpoint order you control via the test fixture.)

Also: rename existing test method bodies that called `currentKids()` to call `keyIds()`. Find them with: `grep -n "currentKids" src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`.

Delete the test from Task 7 that called `snapshotForTest_jwkByKid()` — it is replaced by `get` / `keys` tests above.

- [ ] **Step 2: Run to verify the new tests fail**

Run: `latte test --jca --test=JWKSTest`
Expected: failures — `get`, `keys`, `keyIds` do not exist.

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

1. Rename the existing public method `currentKids()` to `keyIds()`. Body stays the same (returns `Collections.unmodifiableSet(new LinkedHashSet<>(ref.get().byKid().keySet()))`) — but switch the source to `jwkByKid` for clarity (functionally equivalent since both maps share keys).

2. Add the new accessors (alphabetized within public-instance ordering):

```java
public JSONWebKey get(String kid) {
  if (kid == null) return null;
  return ref.get().jwkByKid().get(kid);
}

public Collection<JSONWebKey> keys() {
  return Collections.unmodifiableCollection(ref.get().jwkByKid().values());
}
```

3. Remove the temporary `snapshotForTest_jwkByKid()` method added in Task 7.

4. Verify alphabetical ordering of all instance methods after this change (per `code-conventions.md`).

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): add JWKS.get/keys/keyIds; drop currentKids; remove test-only accessor"
```

---

## Task 10: `JWKS.fromConfiguration(...)` factory + `JWKS.of(...)` static factories

**Spec reference:** §3.1, §3.2 (last bullet — empty-set behavior), §3.5 (`fromConfiguration` validation).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

- [ ] **Step 1: Write the failing tests**

Add to `JWKSTest.java`:

```java
@Test
public void fromConfiguration_uses_jwks_uri_from_config() throws Exception {
  // Set up a JWKS endpoint at a known URL serving one key.
  String jwksURL = startJWKSServer("kid-1");
  OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
      .issuer("https://example.com")
      .jwksURI(jwksURL)
      .build();
  try (JWKS jwks = JWKS.fromConfiguration(cfg).build()) {
    waitForFirstSnapshot(jwks);
    assertEquals(jwks.keyIds(), Set.of("kid-1"));
  }
}

@Test
public void fromConfiguration_rejects_null_or_empty_jwks_uri() {
  OpenIDConnectConfiguration nullURI = OpenIDConnectConfiguration.builder().issuer("x").build();
  OpenIDConnectConfiguration emptyURI = OpenIDConnectConfiguration.builder().issuer("x").jwksURI("").build();
  assertThrows(IllegalArgumentException.class, () -> JWKS.fromConfiguration(nullURI).build());
  assertThrows(IllegalArgumentException.class, () -> JWKS.fromConfiguration(emptyURI).build());
}

@Test
public void of_with_list_creates_static_jwks() {
  JSONWebKey k1 = aTestKey("kid-1");
  JSONWebKey k2 = aTestKey("kid-2");
  try (JWKS jwks = JWKS.of(List.of(k1, k2))) {
    assertEquals(new ArrayList<>(jwks.keyIds()), List.of("kid-1", "kid-2"));
    assertSame(jwks.get("kid-1"), k1);
  }
}

@Test
public void of_with_varargs_creates_static_jwks() {
  JSONWebKey k = aTestKey("kid-1");
  try (JWKS jwks = JWKS.of(k)) {
    assertEquals(jwks.get("kid-1"), k);
  }
}

@Test
public void of_empty_list_returns_non_null_empty_jwks() {
  try (JWKS jwks = JWKS.of(List.of())) {
    assertNotNull(jwks);
    assertEquals(jwks.keys().size(), 0);
    assertEquals(jwks.keyIds().size(), 0);
    assertNull(jwks.get("anything"));
  }
}

@Test
public void of_static_jwks_operational_methods_are_no_ops() {
  try (JWKS jwks = JWKS.of(aTestKey("kid-1"))) {
    jwks.refresh();   // no-op, returns
    assertEquals(jwks.consecutiveFailures(), 0);
    assertNull(jwks.lastFailedRefresh());
    assertNull(jwks.lastSuccessfulRefresh());
    assertNull(jwks.nextDueAt());
    jwks.close();   // no-op, no thread to interrupt
  }
}
```

(`aTestKey(String kid)` is a helper that constructs a `JSONWebKey` with a Verifier-eligible material — copy from existing `JWKSTest` helpers. `startJWKSServer(String kid)` should already exist or be lifted from existing test code.)

- [ ] **Step 2: Run to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: compilation failure — new factories do not exist.

- [ ] **Step 3: Implement `fromConfiguration` and `of(...)` factories**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

1. Add a new `FetchSource` enum value `CONFIGURATION` (or, since `of(...)` doesn't go through Builder, just add a new factory branch for `fromConfiguration` that uses `FetchSource.JWKS` after extracting `jwks_uri` from the configuration):

```java
public static Builder fromConfiguration(OpenIDConnectConfiguration cfg) {
  Objects.requireNonNull(cfg, "cfg");
  if (cfg.jwksURI() == null || cfg.jwksURI().isEmpty()) {
    throw new IllegalArgumentException("OpenIDConnectConfiguration is missing [jwks_uri]");
  }
  return new Builder(FetchSource.JWKS, cfg.jwksURI());
}
```

2. Add the static `of(...)` factories. These do NOT go through Builder; they construct a `JWKS` instance directly, bypassing the scheduler / inflight worker setup. Add a new private constructor signature:

```java
private JWKS(List<JSONWebKey> keys) {
  // Static-mode constructor: no scheduler, no scheduled thread, no inflight worker.
  this.cacheControlPolicy = CacheControlPolicy.IGNORE;
  this.clock = Clock.systemUTC();
  this.closed = false;
  this.httpConnectionCustomizer = null;
  this.logger = NoOpLogger.INSTANCE;
  this.minRefreshInterval = Duration.ofSeconds(30);
  this.refreshInterval = Duration.ofMinutes(60);
  this.refreshOnMiss = false;
  this.refreshTimeout = Duration.ofSeconds(2);
  this.scheduledRefresh = false;
  this.scheduler = null;
  this.source = null;       // null indicates static mode
  this.url = null;
  this.fetchLimits = FetchLimits.defaults();   // added in Task 11

  Map<String, JSONWebKey> jwkByKid = new LinkedHashMap<>();
  Map<String, Verifier> byKid = new LinkedHashMap<>();
  for (JSONWebKey jwk : keys) {
    if (jwk == null) continue;
    Verifier v;
    try {
      v = Verifiers.fromJWK(jwk);
    } catch (InvalidJWKException reject) {
      continue;
    }
    if (jwkByKid.containsKey(jwk.kid())) continue;
    jwkByKid.put(jwk.kid(), jwk);
    byKid.put(jwk.kid(), v);
  }
  Snapshot snapshot = new Snapshot(
      Collections.unmodifiableMap(new LinkedHashMap<>(jwkByKid)),
      Collections.unmodifiableMap(new LinkedHashMap<>(byKid)),
      Instant.now(clock),
      Instant.MAX,
      0,
      null);
  this.ref.set(snapshot);
}

public static JWKS of(List<JSONWebKey> keys) {
  Objects.requireNonNull(keys, "keys");
  return new JWKS(keys);
}

public static JWKS of(JSONWebKey... keys) {
  Objects.requireNonNull(keys, "keys");
  return new JWKS(Arrays.asList(keys));
}
```

3. Update `refresh()`, `close()`, `lastSuccessfulRefresh()`, `lastFailedRefresh()`, `consecutiveFailures()`, `nextDueAt()` to short-circuit when `source == null` (static mode):

```java
public void refresh() {
  if (source == null) return;             // static mode: no-op
  if (closed) { ... }
  ...
}

public Instant lastSuccessfulRefresh() {
  if (source == null) return null;
  Snapshot s = ref.get();
  return s.fetchedAt().equals(Instant.EPOCH) ? null : s.fetchedAt();
}

public Instant nextDueAt() {
  if (source == null) return null;
  return ref.get().nextDueAt();
}

public Instant lastFailedRefresh() {
  if (source == null) return null;
  return ref.get().lastFailedRefresh();
}

public int consecutiveFailures() {
  if (source == null) return 0;
  return ref.get().consecutiveFailures();
}

@Override public void close() {
  if (closed) return;
  closed = true;
  if (source == null) return;             // static mode: no scheduler, no thread
  if (scheduler != null) { scheduler.shutdownNow(); }
  ...
}
```

4. The `resolve(Header)` method needs no changes — it reads from `ref.get().byKid()` and that map is populated identically by both the static-mode constructor and the Builder-mode constructor.

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): add JWKS.fromConfiguration and JWKS.of static factories"
```

---

## Task 11: `JWKS.fetchOnce(...)` static methods + `Builder.fetchLimits(...)` + wire `FetchLimits` through fetches

**Spec reference:** §3.1 (`fetchOnce`), §3.5 (Builder.fetchLimits and shared-knob semantics), §4.

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

This task does three intertwined things:
- Adds `JWKS.Builder.fetchLimits(FetchLimits)` (defaults to `FetchLimits.defaults()`).
- Adds the four `fetchOnce(...)` static methods.
- Wires the Builder's `fetchLimits` into the existing fetch path so it replaces the static config that today comes from `JSONWebKeySetHelper.maxResponseSize` etc.

The internal fetch path currently calls `JSONWebKeySetHelper.retrieveJWKSResponseFromJWKS(url, customizer)` (line 472 of `JWKS.java`). That method reads its limits from static config. We need to either (a) add a new overload taking `FetchLimits` and update `JWKS.fetch()` to call it, or (b) inline the JWKS-response fetch into `JWKS` itself. Option (b) is cleaner — the helper class is being deleted in Task 15 anyway. So this task inlines the fetch path. The `JSONWebKeySetHelper.retrieveJWKSResponseFrom*` triplet is no longer called from production code after this task (test callers are migrated in Task 14/15).

- [ ] **Step 1: Write the failing tests**

Add to `JWKSTest.java`:

```java
@Test
public void builder_fetchLimits_applies_to_jwks_response_size_cap() throws Exception {
  // Serve a JWKS body slightly larger than the configured cap.
  String jwksURL = startJWKSServerReturningLargeBody();
  FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
  // build() must not throw (initial fetch failures are async); the JWKS lands
  // with consecutiveFailures >= 1.
  try (JWKS jwks = JWKS.fromJWKS(jwksURL).fetchLimits(tight).build()) {
    waitForFirstFailure(jwks);
    assertTrue(jwks.consecutiveFailures() >= 1);
  }
}

@Test
public void fetchOnce_returns_keys_from_jwks_endpoint() throws Exception {
  String jwksURL = startJWKSServer("kid-1", "kid-2");
  List<JSONWebKey> keys = JWKS.fetchOnce(jwksURL);
  assertEquals(keys.stream().map(JSONWebKey::kid).toList(), List.of("kid-1", "kid-2"));
}

@Test
public void fetchOnce_with_customizer_applies_to_connection() throws Exception {
  AtomicBoolean customizerInvoked = new AtomicBoolean(false);
  String jwksURL = startJWKSServer("kid-1");
  List<JSONWebKey> keys = JWKS.fetchOnce(jwksURL, conn -> {
    customizerInvoked.set(true);
    conn.setRequestProperty("X-Test-Header", "yes");
  });
  assertEquals(keys.size(), 1);
  assertTrue(customizerInvoked.get());
}

@Test
public void fetchOnce_with_FetchLimits_enforces_response_cap() throws Exception {
  String jwksURL = startJWKSServerReturningLargeBody();
  FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
  assertThrows(JWKSFetchException.class, () -> JWKS.fetchOnce(jwksURL, tight));
}

@Test
public void fetchOnce_does_not_construct_a_JWKS_instance_or_thread() throws Exception {
  // No assertion specifics — this is a documentation test that exercises the
  // expected return type and verifies the call returns synchronously.
  String jwksURL = startJWKSServer("kid-1");
  List<JSONWebKey> keys = JWKS.fetchOnce(jwksURL);
  assertNotNull(keys);
}

@Test
public void fetchOnce_rejects_cross_origin_redirect() throws Exception {
  String jwksURL = startServerThatRedirectsToDifferentHost();
  assertThrows(JWKSFetchException.class, () -> JWKS.fetchOnce(jwksURL));
}
```

(Adapt `startJWKSServerReturningLargeBody`, `startServerThatRedirectsToDifferentHost`, `waitForFirstFailure` to existing test fixture style.)

- [ ] **Step 2: Run to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: compilation failure on `Builder.fetchLimits`, `JWKS.fetchOnce`.

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

1. Add a `FetchLimits fetchLimits` field on `JWKS` and `JWKS.Builder`. Default on Builder: `FetchLimits.defaults()`. Add `Builder.fetchLimits(FetchLimits)` setter (validates non-null with `Objects.requireNonNull`).

2. Add the four `fetchOnce` static methods. Each builds the connection, applies the customizer (if non-null), calls `AbstractHTTPHelper.get(...)` with `sameOriginRedirectsOnly=true`, parses via `HardenedJSON.parse(stream, limits)`, extracts the `keys` array, and converts each entry to a `JSONWebKey`. Failures map to `JWKSFetchException` via `classifyFailure(...)` (a new private static helper that mirrors the existing instance one).

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
        true,    // sameOriginRedirectsOnly
        (conn, is) -> {
          Map<String, Object> map = HardenedJSON.parse(is, limits);
          Object keys = map.get("keys");
          if (!(keys instanceof List<?> keyList)) {
            String url = conn.getURL().toString();
            throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
                "JWKS endpoint [" + url + "] response is missing the [keys] array");
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
        },
        (msg, cause) -> {
          // Reason classification: see classifyFailureFor(...).
          return classifyFailureFor(msg, cause);
        });
  } catch (JWKSFetchException e) {
    throw e;
  } catch (RuntimeException e) {
    throw classifyFailureFor("JWKS fetch failed", e);
  }
}

private static JWKSFetchException classifyFailureFor(String msg, Throwable cause) {
  // Mirror the instance classifyFailure logic.
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

3. Replace the body of the existing `private JWKSResponse fetch()` (lines ~468-474). Today it calls into `JSONWebKeySetHelper.retrieveJWKSResponseFrom*`. Inline the `JWKS` case (issuer/well-known cases are handled by Task 12 — for now, leave those calling the helper). Use `fetchLimits` (the new instance field) and `httpConnectionCustomizer` from `this`. The new fetch must also include `Cache-Control` and `Retry-After` headers in the returned `JWKSResponse` (today's helper does that; line 358-364 of `JSONWebKeySetHelper.java`).

```java
private JWKSResponse fetch() {
  return switch (source) {
    case ISSUER     -> JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer(url, httpConnectionCustomizer);   // Task 12 inlines this
    case WELL_KNOWN -> JSONWebKeySetHelper.retrieveJWKSResponseFromWellKnownConfiguration(url, httpConnectionCustomizer);   // Task 12 inlines this
    case JWKS       -> fetchJWKSDirect();
  };
}

private JWKSResponse fetchJWKSDirect() {
  HttpURLConnection connection = AbstractHTTPHelper.buildURLConnection(url,
      (msg, cause) -> new JWKSFetchException(JWKSFetchException.Reason.NETWORK, msg, cause));
  if (httpConnectionCustomizer != null) httpConnectionCustomizer.accept(connection);
  return AbstractHTTPHelper.get(connection,
      fetchLimits.maxResponseBytes(),
      fetchLimits.maxRedirects(),
      true,
      (conn, is) -> {
        Map<String, Object> map = HardenedJSON.parse(is, fetchLimits);
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
        int status = -1;
        try { status = conn.getResponseCode(); } catch (IOException ignored) {}
        Map<String, String> sel = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String name : new String[]{"Cache-Control", "Retry-After"}) {
          String v = conn.getHeaderField(name);
          if (v != null) sel.put(name, v);
        }
        return new JWKSResponse(result, status, sel);
      },
      (msg, cause) -> classifyFailureFor(msg, cause));
}
```

4. Update the static-mode constructor (added in Task 10) to accept `FetchLimits.defaults()` for the `fetchLimits` field — already shown in Task 10 step 3.

5. The `Builder` constructor needs a new field: `private FetchLimits fetchLimits = FetchLimits.defaults();` and a setter:

```java
public Builder fetchLimits(FetchLimits limits) {
  this.fetchLimits = Objects.requireNonNull(limits, "fetchLimits");
  return this;
}
```

The `JWKS(Builder b)` constructor reads `this.fetchLimits = b.fetchLimits;`.

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS for the new tests. The existing tests should continue to pass (the JWKS-direct path is wired up; the issuer/well-known paths still go through the legacy helper — they will be migrated in Task 12).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): add JWKS.fetchOnce, Builder.fetchLimits; inline JWKS-direct fetch"
```

---

## Task 12: Wire `fromIssuer` / `fromWellKnown` to use `OpenIDConnect.discover` (one-shot at build, cache `jwks_uri`)

**Spec reference:** §3.1 (factory delegation), §3.4 (refresh behavior change), §3.5 (Builder-scope semantics, build-time fetch semantics).

**Files:**
- Modify: `src/main/java/org/lattejava/jwt/jwks/JWKS.java`
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java`

After this task, `JWKS.fromIssuer(...)` and `JWKS.fromWellKnown(...)` no longer invoke `JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer/...WellKnownConfiguration`. Instead, the discovery hop runs once inside `Builder.build()` via `OpenIDConnect.discover` / `discoverFromWellKnown`, and the resulting `OpenIDConnectConfiguration` is captured. Subsequent refreshes dispatch only the JWKS hop. Also: when the discovery hop fails inside `Builder.build()`, the resulting initial-fetch failure carries the `OpenIDConnectException` as its cause.

- [ ] **Step 1: Write the failing tests**

Add to `JWKSTest.java`:

```java
@Test
public void fromIssuer_performs_discovery_only_at_build_not_per_refresh() throws Exception {
  // Set up a discovery server that counts hits to the well-known endpoint and
  // a JWKS server that counts hits to the JWKS endpoint.
  AtomicInteger discoveryHits = new AtomicInteger();
  AtomicInteger jwksHits = new AtomicInteger();
  String issuer = startInstrumentedIssuerServer(discoveryHits, jwksHits, "kid-1");
  try (JWKS jwks = JWKS.fromIssuer(issuer)
      .refreshInterval(Duration.ofMinutes(60))
      .minRefreshInterval(Duration.ofMillis(10))
      .build()) {
    waitForFirstSnapshot(jwks);
    int discoveryAfterBuild = discoveryHits.get();
    int jwksAfterBuild = jwksHits.get();
    jwks.refresh();
    jwks.refresh();
    // Discovery is one-shot at build:
    assertEquals(discoveryHits.get(), discoveryAfterBuild);
    // Each refresh hits the JWKS endpoint:
    assertTrue(jwksHits.get() > jwksAfterBuild);
  }
}

@Test
public void fromIssuer_build_failure_during_discovery_keeps_jwks_returning_empty() throws Exception {
  // Issuer well-known endpoint returns 500.
  String issuer = startIssuerServerReturning500();
  try (JWKS jwks = JWKS.fromIssuer(issuer)
      .refreshTimeout(Duration.ofMillis(500))
      .build()) {
    // build() does not throw; first snapshot is empty; consecutiveFailures >= 1.
    assertEquals(jwks.keys().size(), 0);
    assertTrue(jwks.consecutiveFailures() >= 1);
  }
}

@Test
public void fromIssuer_refresh_after_discovery_failure_surfaces_OpenIDConnectException_as_cause() throws Exception {
  // Same fixture as above; call refresh() and catch JWKSFetchException, assert cause type.
  String issuer = startIssuerServerReturning500();
  try (JWKS jwks = JWKS.fromIssuer(issuer).refreshTimeout(Duration.ofMillis(500)).build()) {
    // The first refresh attempt re-runs the build-time fetch path... but per
    // spec §3.4 refresh hits the JWKS endpoint directly. After a failed
    // discovery at build, jwks_uri is unknown — the refresh path must surface
    // a JWKSFetchException whose cause is the OpenIDConnectException from
    // the discovery hop. Decision: when discovery failed at build, refresh()
    // must re-attempt discovery (no jwks_uri yet); otherwise refresh hits
    // jwks_uri only.
    JWKSFetchException ex = assertThrows(JWKSFetchException.class, jwks::refresh);
    Throwable cause = ex.getCause();
    assertTrue(cause instanceof OpenIDConnectException, "expected OpenIDConnectException, got " + (cause == null ? "null" : cause.getClass()));
  }
}
```

The third test surfaces a design point not covered explicitly in the spec: when discovery fails at build, what does `refresh()` do? Spec §3.4 says discovery is one-shot — but the build-time discovery failed, so there's no `jwks_uri` to refresh against. The natural interpretation: the JWKS holds onto the "discovery pending" state and re-tries discovery on the next refresh attempt. Implement accordingly.

- [ ] **Step 2: Run to verify they fail**

Run: `latte test --jca --test=JWKSTest`
Expected: failures (the discovery-once-at-build behavior is not implemented).

- [ ] **Step 3: Implement**

In `src/main/java/org/lattejava/jwt/jwks/JWKS.java`:

1. Add a new private field `private volatile String resolvedJWKSURI;`. This holds `jwks_uri` after the first successful discovery (or, for `fromConfiguration`/`fromJWKS`, the URL straight away).

2. In the `JWKS(Builder b)` constructor (Builder-mode path), before dispatching the initial fetch:
   - If `b.source == FetchSource.JWKS` (set by `fromJWKS` and `fromConfiguration`): `this.resolvedJWKSURI = b.url;`
   - Else (`FetchSource.ISSUER` or `FetchSource.WELL_KNOWN`): `this.resolvedJWKSURI = null;` (will be populated on first successful discovery).

3. Modify `private JWKSResponse fetch()` so when `source` is `ISSUER` or `WELL_KNOWN`, it:
   - If `resolvedJWKSURI != null`: dispatch the JWKS hop via `fetchJWKSDirectAt(resolvedJWKSURI)` (a small refactor of `fetchJWKSDirect()` to take the URL as an argument).
   - Else: run discovery via `OpenIDConnect.discover(url, fetchLimits, httpConnectionCustomizer)` (or `discoverFromWellKnown`) — wrap the resulting `OpenIDConnectException` in `JWKSFetchException` with `Reason.PARSE` (for issuer-equality / missing-jwks_uri / parse failures) or `Reason.NETWORK` / `Reason.NON_2XX` for transport failures; classify by walking the cause chain. Capture `cfg.jwksURI()` into `resolvedJWKSURI`. Then dispatch the JWKS hop via `fetchJWKSDirectAt(resolvedJWKSURI)`.
   - The `JWKSFetchException` message names the failed hop: `"Discovery hop failed for issuer [" + url + "]"` or `"Discovery hop failed for well-known URL [" + url + "]"`. The cause is the original `OpenIDConnectException`.

4. Refactor `fetchJWKSDirect()` (Task 11) into `fetchJWKSDirectAt(String jwksURL)` — takes the URL explicitly, so both the `fromJWKS` path (passes `this.url`) and the post-discovery path (passes `resolvedJWKSURI`) can use it.

5. Delete the `JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer` / `...FromWellKnownConfiguration` calls from the `switch` in `fetch()`. The full switch becomes:

```java
private JWKSResponse fetch() {
  return switch (source) {
    case ISSUER, WELL_KNOWN -> fetchAfterMaybeDiscovery();
    case JWKS               -> fetchJWKSDirectAt(url);
  };
}

private JWKSResponse fetchAfterMaybeDiscovery() {
  if (resolvedJWKSURI == null) {
    OpenIDConnectConfiguration cfg;
    try {
      cfg = (source == FetchSource.ISSUER)
          ? OpenIDConnect.discover(url, fetchLimits, httpConnectionCustomizer)
          : OpenIDConnect.discoverFromWellKnown(url, fetchLimits, httpConnectionCustomizer);
    } catch (OpenIDConnectException oe) {
      JWKSFetchException.Reason reason = classifyDiscoveryFailureReason(oe);
      throw new JWKSFetchException(reason,
          (source == FetchSource.ISSUER ? "Discovery hop failed for issuer [" : "Discovery hop failed for well-known URL [") + url + "]",
          oe);
    }
    resolvedJWKSURI = cfg.jwksURI();
  }
  return fetchJWKSDirectAt(resolvedJWKSURI);
}

private static JWKSFetchException.Reason classifyDiscoveryFailureReason(OpenIDConnectException oe) {
  Throwable t = oe;
  while (t != null) {
    if (t instanceof HTTPResponseException) return JWKSFetchException.Reason.NON_2XX;
    if (t instanceof IOException) return JWKSFetchException.Reason.NETWORK;
    t = t.getCause();
  }
  return JWKSFetchException.Reason.PARSE;
}
```

- [ ] **Step 4: Run tests**

Run: `latte test --jca --test=JWKSTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/lattejava/jwt/jwks/JWKS.java src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "feat(jwks): one-shot discovery at build via OpenIDConnect.discover; cache jwks_uri"
```

---

## Task 13: Same-origin redirect policy is exercised on the JWKS hop

**Spec reference:** §3.7.

**Files:**
- Modify: `src/test/java/org/lattejava/jwt/jwks/JWKSTest.java` (add coverage)
- Modify (if needed): `src/main/java/org/lattejava/jwt/jwks/JWKS.java`

The same-origin redirect policy was implemented in Task 5 Step 1 (in `AbstractHTTPHelper`) and applied to discovery in Task 5 and to JWKS in Task 11/12 (`fetchJWKSDirectAt(...)` and `fetchOnce(...)` both pass `sameOriginRedirectsOnly=true`). This task verifies the JWKS hop end-to-end and adds explicit coverage.

- [ ] **Step 1: Write the failing test (or new coverage if already passing)**

Add to `JWKSTest.java`:

```java
@Test
public void refresh_rejects_jwks_endpoint_cross_origin_redirect() throws Exception {
  String jwksURL = startServerThatRedirectsToDifferentHost();
  try (JWKS jwks = JWKS.fromJWKS(jwksURL).build()) {
    JWKSFetchException ex = assertThrows(JWKSFetchException.class, jwks::refresh);
    assertEquals(ex.reason(), JWKSFetchException.Reason.NETWORK);
    assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"));
  }
}

@Test
public void same_host_redirect_followed_within_maxRedirects() throws Exception {
  String jwksURL = startServerThatRedirectsTwiceWithinSameOrigin("kid-1");
  try (JWKS jwks = JWKS.fromJWKS(jwksURL).build()) {
    waitForFirstSnapshot(jwks);
    assertEquals(jwks.keyIds(), Set.of("kid-1"));
  }
}
```

- [ ] **Step 2: Run**

Run: `latte test --jca --test=JWKSTest`
Expected: pass if Tasks 5/11/12 wired everything correctly. If the cross-origin test fails because the message text differs, adjust the assertion to match what `AbstractHTTPHelper` actually emits.

- [ ] **Step 3: Commit**

```bash
git add src/test/java/org/lattejava/jwt/jwks/JWKSTest.java
git commit -m "test(jwks): cover same-origin redirect policy on JWKS hop"
```

---

## Task 14: Delete `oauth2/` package (`AuthorizationServerMetaData` + `ServerMetaDataHelper` + tests)

**Spec reference:** §5.1, §5.3.

**Files:**
- Delete: `src/main/java/org/lattejava/jwt/oauth2/AuthorizationServerMetaData.java`
- Delete: `src/main/java/org/lattejava/jwt/oauth2/ServerMetaDataHelper.java`
- Delete: `src/test/java/org/lattejava/jwt/oauth2/ServerMetaDataTest.java`
- Delete: empty directories `src/main/java/org/lattejava/jwt/oauth2/` and `src/test/java/org/lattejava/jwt/oauth2/`

- [ ] **Step 1: Verify no callers remain in production code**

Run: `grep -rn "AuthorizationServerMetaData\|ServerMetaDataHelper" src/main/ --include='*.java'`
Expected: only references inside `oauth2/` itself.

If any other production file references these — do not delete; investigate why and migrate the caller first.

- [ ] **Step 2: Delete the files**

```bash
git rm src/main/java/org/lattejava/jwt/oauth2/AuthorizationServerMetaData.java
git rm src/main/java/org/lattejava/jwt/oauth2/ServerMetaDataHelper.java
git rm src/test/java/org/lattejava/jwt/oauth2/ServerMetaDataTest.java
rmdir src/main/java/org/lattejava/jwt/oauth2
rmdir src/test/java/org/lattejava/jwt/oauth2
```

- [ ] **Step 3: Build + test**

Run: `latte test --jca`
Expected: 11149 - (number of tests in ServerMetaDataTest) pass, 0 fail. If `ServerMetaDataTest` had N tests, the new total is `11149 - N` plus any new tests added in Tasks 1-13.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(oauth2): delete AuthorizationServerMetaData, ServerMetaDataHelper, oauth2 package"
```

---

## Task 15: Delete `JSONWebKeySetHelper`; migrate remaining test callers

**Spec reference:** §5.1, §5.2.

**Files:**
- Delete: `src/main/java/org/lattejava/jwt/jwks/JSONWebKeySetHelper.java`
- Delete: `src/test/java/org/lattejava/jwt/jwks/JSONWebKeySetHelperTest.java` (or migrate the still-relevant tests to `JWKSTest` and `OpenIDConnectDiscoverTest`)

After Tasks 11/12, no production code path calls into `JSONWebKeySetHelper`. The remaining callers are tests (`JSONWebKeySetHelperTest`).

- [ ] **Step 1: Audit `JSONWebKeySetHelperTest` and migrate worth-keeping coverage**

Read `src/test/java/org/lattejava/jwt/jwks/JSONWebKeySetHelperTest.java`. Each test there now has a successor in either `JWKSTest` (for `retrieveKeysFromJWKS` → `JWKS.fetchOnce`) or `OpenIDConnectDiscoverTest` (for `retrieveKeysFromIssuer` / `retrieveKeysFromWellKnownConfiguration`). For each test:
- If the behavior is already covered by a test in those files: skip it.
- If the behavior is NOT covered (response-cap edge cases, redirect counting, JSON parse hardening edge cases, header propagation through customizer): port the test to the appropriate new file using the new API, then delete the old one.

This audit may add ~5-15 ported tests. The audit IS the work — no shortcuts.

- [ ] **Step 2: Verify no production callers remain**

Run: `grep -rn "JSONWebKeySetHelper" src/main/ --include='*.java'`
Expected: empty.

- [ ] **Step 3: Delete the helper class and its test**

```bash
git rm src/main/java/org/lattejava/jwt/jwks/JSONWebKeySetHelper.java
git rm src/test/java/org/lattejava/jwt/jwks/JSONWebKeySetHelperTest.java
```

- [ ] **Step 4: Verify the `AbstractHTTPHelper` extension from Task 5 still compiles**

The Task 5 step 1 update modified `AbstractHTTPHelper` to add a same-origin overload while keeping the old overloads for `JSONWebKeySetHelper` / `ServerMetaDataHelper` compatibility. With both helpers now deleted, the old overloads may be unused — check with `grep -rn "AbstractHTTPHelper.get(" src/ --include='*.java'`. If the non-same-origin overload has zero callers, delete it to keep the helper's surface honest.

Run: `grep -rn "AbstractHTTPHelper" src/ --include='*.java'`
If the helper itself has only the same-origin-aware overload remaining, that's the desired end state.

- [ ] **Step 5: Build + test**

Run: `latte test --jca`
Expected: pass with the migrated tests.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(jwks): delete JSONWebKeySetHelper; migrate test coverage to JWKSTest and OpenIDConnectDiscoverTest"
```

---

## Task 16: Final verification + spec status update

**Spec reference:** all of it.

**Files:**
- Modify: `specs/7.0-discovery-and-jwks-simplification.md` (status row)
- Modify: `specs/README.md` (status column for the new spec row)

- [ ] **Step 1: Run the full test suite (both JCA and FIPS modes)**

Run: `latte test`
Expected: 0 failures in BOTH the JCA pass and the FIPS pass. Note the pass/fail/skip counts.

If any test fails in either mode, fix before proceeding. Do NOT advance the spec status while red.

- [ ] **Step 2: Verify the deletions actually removed everything**

Run:
```bash
ls src/main/java/org/lattejava/jwt/oauth2 2>&1   # expected: No such file or directory
find src -name "JWKSource.java" -o -name "JSONWebKeySetHelper.java" -o -name "AuthorizationServerMetaData.java" -o -name "ServerMetaDataHelper.java" -o -name "JWKSRefreshException.java" 2>&1   # expected: empty
grep -rn "JWKSource\|JSONWebKeySetHelper\|AuthorizationServerMetaData\|ServerMetaDataHelper\|JWKSRefreshException" src/ --include='*.java' 2>&1   # expected: empty
```

- [ ] **Step 3: Verify the new symbols compile and are reachable**

Run:
```bash
ls src/main/java/org/lattejava/jwt/FetchLimits.java src/main/java/org/lattejava/jwt/OpenIDConnectConfiguration.java src/main/java/org/lattejava/jwt/OpenIDConnectException.java src/main/java/org/lattejava/jwt/jwks/JWKS.java src/main/java/org/lattejava/jwt/jwks/JWKSFetchException.java src/main/java/org/lattejava/jwt/internal/HardenedJSON.java
```

All six paths must exist.

- [ ] **Step 4: Update the spec status to "In Progress"**

Edit `specs/7.0-discovery-and-jwks-simplification.md`:
- Status row: `In Progress (PR pending)` (or include the PR URL once opened).
- Bump revision to 3 if you made any clarifying edits during implementation; otherwise leave at 2.
- Add a dated note near the top: `> **2026-04-26** — implementation complete on branch \`robotdan/simpler\`. Spec advanced from Draft to In Progress.`

Edit `specs/README.md`:
- Update the index row's Status cell to match the spec file.
- Update the Last updated cell.

- [ ] **Step 5: Commit the status update**

```bash
git add specs/7.0-discovery-and-jwks-simplification.md specs/README.md
git commit -m "docs(spec): mark 7.0-discovery-and-jwks-simplification In Progress"
```

- [ ] **Step 6: Ready for PR**

The branch `robotdan/simpler` is ready to push and open a PR against `main`. Do NOT push without explicit user approval.
