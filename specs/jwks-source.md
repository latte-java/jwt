# JWKSource — self-refreshing JWK cache + VerifierResolver

| Field | Value |
|------|------|
| Status | Draft |
| Revision | 2 |
| Last updated | 2026-04-24 |
| Owner | Daniel DeGroff |
| Target version | 7.x (additive) |

## Problem statement

Today, integrators wiring `JWTDecoder` against a remote OIDC issuer must compose four things by hand:

1. Periodically fetch JWKS via `JSONWebKeySetHelper.retrieveKeysFromIssuer(...)`.
2. Build a `Map<String, Verifier>` keyed by `kid`.
3. Wrap that map in `VerifierResolver.byKid(...)`.
4. Decide what to do when an unknown `kid` arrives mid-rotation, when refreshes fail, when the process is shutting down, and when concurrent decoders all see the same cache miss simultaneously.

This is correct, but it is the same scaffolding everyone writes. The library should ship a high-level abstraction that performs the steps above safely for the common case (an OIDC IdP at a stable issuer URL), while preserving the low-level building blocks for callers who need them.

The new abstraction is `org.lattejava.jwt.jwks.JWKSource`. It implements `VerifierResolver` directly so it drops into `JWTDecoder.decode(token, source)`, and it implements `AutoCloseable` so it cleans up its scheduler on shutdown.

The name `JWKSource` is intentional: `KeyStore` would shadow `java.security.KeyStore` in callers' import lists, and `JWKCache` undersells the fact that this is the resolver, not just storage behind one.

## 1. Public API

### 1.1 Factory entry points

```java
package org.lattejava.jwt.jwks;

public final class JWKSource implements VerifierResolver, AutoCloseable {

  /**
   * Build a JWKSource that resolves keys via OIDC discovery
   * ({@code <issuer>/.well-known/openid-configuration} → {@code jwks_uri}).
   */
  public static Builder fromIssuer(String issuer);

  /**
   * Build a JWKSource that resolves keys via an explicit OIDC well-known
   * configuration URL. Use this when the discovery document does not live
   * at the conventional path beneath the issuer.
   */
  public static Builder fromWellKnownConfiguration(String wellKnownUrl);

  /**
   * Build a JWKSource that polls a JWKS endpoint directly. Use this for
   * non-OIDC issuers that publish a JWKS but no discovery document.
   */
  public static Builder fromJWKS(String jwksUrl);

  // VerifierResolver
  @Override public Verifier resolve(Header header);

  // Operational surface
  public void refresh();                           // synchronous, blocking, singleflight-coalesced
  @Override public void close();                   // idempotent, cancels scheduler, drains in-flight refresh
  public Instant lastSuccessfulRefresh();          // null if never succeeded
  public Set<String> currentKids();                // snapshot of kids in current cache
}
```

The three factories all return the same `Builder`; the only difference between them is which `JSONWebKeySetHelper.retrieveKeysFrom*` method is invoked when a refresh fires.

### 1.2 Builder

```java
public static final class Builder {

  // Refresh scheduling
  public Builder scheduledRefresh(boolean enabled);              // default: false
  public Builder refreshInterval(Duration d);                    // default: 60 minutes
  public Builder refreshOnMiss(boolean enabled);                 // default: true
  public Builder refreshTimeout(Duration d);                     // default: 2 seconds
  public Builder minRefreshInterval(Duration d);                 // default: 30 seconds; also the scheduler tick rate

  // HTTP behavior
  public Builder httpConnectionCustomizer(Consumer<HttpURLConnection> c); // default: null
  public Builder cacheControlPolicy(CacheControlPolicy p);       // default: CacheControlPolicy.CLAMP

  // Observability
  public Builder logger(Logger logger);                          // default: NoOpLogger

  // Per-call algorithm strategy used when constructing Verifiers from JWKs.
  public Builder verifierFactory(VerifierFactory factory);       // default: built-in JWK→Verifier mapping

  public JWKSource build();
}

public enum CacheControlPolicy {
  /** Clamp the server's max-age into [minRefreshInterval, refreshInterval]. */
  CLAMP,
  /** Ignore the server's max-age; always refresh on the configured interval. */
  IGNORE
}
```

`scheduledRefresh` and `refreshOnMiss` are independent toggles. The valid combinations are:

| `scheduledRefresh` | `refreshOnMiss` | Behavior |
|---|---|---|
| true | true (default) | Periodic refresh + on-miss refresh. Highest freshness, most network traffic. |
| true | false | Periodic refresh only. Misses fail immediately with `MissingVerifierException`. Useful when keys are known to be stable across the refresh interval. |
| false | true | On-demand only. First decode warms the cache; later decodes refresh only on unknown `kid`. |
| false | false | Manual `refresh()` only. Caller controls cadence entirely. |

### 1.3 Defaults

| Setting | Default | Rationale |
|---|---|---|
| `scheduledRefresh` | `false` | Most callers want lazy-warm + miss-driven refresh; opt in to a background thread. |
| `refreshInterval` | `60 minutes` | Matches the `max-age` most IdPs publish on JWKS responses; conservative wrt rotation. |
| `refreshOnMiss` | `true` | Unknown `kid` should trigger a fetch. The combination of singleflight + `nextDueAt` bounds amplification. |
| `refreshTimeout` | `2 seconds` | Bounds blocking on `resolve()` during a miss. Long enough for healthy networks, short enough to fail fast on a wedged IdP. |
| `minRefreshInterval` | `30 seconds` | Floor for both the scheduler tick rate and the on-miss debounce. Hard cap on amplification under attack. |
| `cacheControlPolicy` | `CLAMP` | Honor IdP-published `max-age` when sane, but never refresh more often than `minRefreshInterval` and never wait longer than `refreshInterval` between refreshes. |
| `logger` | `NoOpLogger` | Library is silent unless the integrator opts in. |
| `httpConnectionCustomizer` | `null` | No additional headers / TLS customization unless requested. |

### 1.4 Validation

`build()` is the only place that throws on configuration:

- `refreshInterval` must be positive.
- `minRefreshInterval` must be positive.
- `refreshInterval` must be `>= minRefreshInterval` (since `minRefreshInterval` is the tick rate, a `refreshInterval` smaller than one tick would be unreachable).
- `refreshTimeout` must be positive.
- The factory URL must be non-null and non-empty. **No scheme enforcement** — leaving this to the caller matches `JSONWebKeySetHelper`'s existing behavior and supports test fixtures that use plain HTTP.

Validation messages are stand-alone (no parameter echo unless the value is bounded — see `feedback_exception_message_style` memory).

## 2. Behavioral spec

### 2.1 Snapshot model

The cache state is a single immutable snapshot:

```java
record Snapshot(
    Map<String, Verifier> byKid,
    Instant fetchedAt,
    Instant nextDueAt,        // earliest time at which a refresh is allowed to start
    int consecutiveFailures   // 0 on the success path
) {}
```

It is held in `AtomicReference<Snapshot>`. Reads (`resolve()`, `currentKids()`, `lastSuccessfulRefresh()`) load the reference and read fields off the snapshot — there are no locks on the read path.

The very first snapshot is `Snapshot(emptyMap, Instant.EPOCH, Instant.EPOCH, 0)`. This means the first `resolve()` call will not find a `kid` and will fall through to the on-miss path (or fail, if `refreshOnMiss=false`).

### 2.2 `resolve(Header header)`

```
1. snapshot = ref.get()
2. v = snapshot.byKid.get(header.kid())
3. if v != null:
     if !v.canVerify(header.alg()): return null
     return v
4. if !refreshOnMiss: return null
5. if now < snapshot.nextDueAt: return null   // bounded by minRefreshInterval-derived window
6. fresh = singleflight.refresh()              // blocks up to refreshTimeout
7. v = fresh.byKid.get(header.kid())
8. apply step 3's canVerify check; return v or null
```

Step 5 is the DoS gate: even if 10,000 concurrent decoders all see the same unknown `kid`, only the first one past the `nextDueAt` window starts a fetch; the rest see `nextDueAt > now` and return `null` immediately.

Returning `null` triggers `MissingVerifierException` in `JWTDecoder` (per `VerifierResolver`'s contract). That is the correct behavior for "unknown `kid` and we already refreshed recently" — the token genuinely is unverifiable with this source.

### 2.3 `refresh()`

Synchronous, blocking, singleflight-coalesced. If a refresh is already in flight, the caller awaits its completion (bounded by `refreshTimeout`) and returns. If it succeeds, the new snapshot is installed before `refresh()` returns. If it fails, the snapshot is unchanged and the failure is logged at `error`. `refresh()` does not throw on a network failure — the source remains usable with its prior keys.

`refresh()` ignores `nextDueAt`. It is the explicit, caller-driven path; the gate exists to defend against amplification, not to throttle deliberate operator action.

### 2.4 The `nextDueAt` watermark

`nextDueAt` is the unified "when is the next refresh allowed to start" signal. It is consulted by both the scheduler tick (§2.5) and the on-miss path (§2.2), so the two paths cannot fight each other.

After a successful refresh:
- `nextDueAt = max(now + minRefreshInterval, now + chosenInterval)` where `chosenInterval` depends on `cacheControlPolicy` (see §2.6).

After a failed refresh:
- `nextDueAt = now + backoff(consecutiveFailures)` (see §2.7).

The on-miss path checks `now < nextDueAt` to decide whether to debounce. The scheduler tick checks the same condition before dispatching a refresh. There is no second cooldown variable.

### 2.5 Scheduler tick

When `scheduledRefresh=true`, a single virtual-thread scheduler wakes every `minRefreshInterval` ticks. On each tick:

1. `s = ref.get()`
2. If `now >= s.nextDueAt`, dispatch a refresh on a virtual thread. The dispatch goes through the same singleflight as the on-miss path.
3. Otherwise, return and wait for the next tick.

Tick rate is `minRefreshInterval` directly — there is no separate "tick interval" knob. This avoids the awkwardness of validating two intervals against each other and keeps the smallest schedulable window equal to the minimum refresh window.

### 2.6 Cache-Control honoring

When the JWKS HTTP response carries `Cache-Control: max-age=N` (RFC 9111), `JWKSource` reads the directive and uses it to compute `nextDueAt`. The behavior is governed by `CacheControlPolicy`:

| Policy | Behavior |
|---|---|
| `CLAMP` (default) | `chosenInterval = clamp(maxAge, minRefreshInterval, refreshInterval)`. Both sides of the clamp are needed: too-short `max-age` would amplify load; too-long `max-age` would stretch the rotation window past what the operator is comfortable with. |
| `IGNORE` | `chosenInterval = refreshInterval` always. The server's hint is discarded. |

`max-age=0` and `no-store` are treated as `chosenInterval = minRefreshInterval` under `CLAMP` (the floor), not as "refresh on every decode". This is intentional: an IdP setting `no-store` on its JWKS does not justify an unbounded refresh storm.

If no `Cache-Control` header is present, `chosenInterval = refreshInterval` regardless of policy.

This is a v1 feature because empirically, large IdPs (Auth0, Okta, AzureAD, Google Identity, Cognito) do publish `Cache-Control: public, max-age=...` on their JWKS endpoints — typically on the order of 5–60 minutes. Honoring it lets `JWKSource` follow the IdP's published rotation cadence rather than imposing its own.

### 2.7 Failure handling and exponential backoff

#### 2.7.1 Success path (recap)

`consecutiveFailures = 0` and `nextDueAt = now + chosenInterval` per §2.4.

#### 2.7.2 Failure path

When a refresh raises (network failure, non-2xx response, parse failure, etc.):

1. Log at `error` with the cause.
2. `consecutiveFailures++`.
3. Compute `backoff = min(refreshInterval, minRefreshInterval * 2^(consecutiveFailures-1))`. This produces the sequence `30s → 1m → 2m → 4m → 8m → 16m → 32m → 60m (cap)` with the default settings.
4. If the failed response carried `Retry-After` (RFC 9110 §10.2.3), use `nextDueAt = max(now + backoff, now + retryAfter)`. Honoring `Retry-After` lets the IdP throttle us beyond our own backoff curve, but never *under* our own minimum.
5. The snapshot is replaced with `Snapshot(prevByKid, prevFetchedAt, nextDueAt, consecutiveFailures)`. Existing keys remain available — availability over freshness — until the next successful refresh either restores them or the operator decides to take action based on `lastSuccessfulRefresh()`.

#### 2.7.3 Caller-visible behavior during failure

- `resolve()` continues to return cached verifiers from the prior successful snapshot.
- Misses against unknown `kid`s return `null` immediately once `nextDueAt` is in the future.
- `lastSuccessfulRefresh()` does not advance; an integrator monitoring this can alert on staleness.

There is no separate "circuit breaker open" state; the exponential-backoff `nextDueAt` *is* the circuit. After enough consecutive failures, `nextDueAt` settles at `now + refreshInterval` and the source effectively reverts to "try every full interval until something changes".

## 3. Concurrency model

| State | Mechanism |
|---|---|
| Current snapshot | `AtomicReference<Snapshot>`; lock-free reads, CAS on writes |
| Singleflight refresh | A single in-flight `CompletableFuture<Snapshot>`, replaced on completion; awaiters subscribe to it |
| `nextDueAt` and `consecutiveFailures` | Fields of the immutable snapshot; updated atomically with the snapshot itself |
| Scheduler | One virtual-thread scheduled task; cancellation via `close()` |
| Refresh dispatch | Virtual thread per refresh attempt (so a slow JWKS endpoint never blocks the scheduler tick) |

The goal of this state model is that a `resolve()` that hits the cache requires zero allocations and zero locks, regardless of how many concurrent refreshes are in flight or how often the scheduler is waking.

## 4. Threading model

- One scheduler. Created in `build()` only when `scheduledRefresh=true`. Backed by `Thread.ofVirtual().scheduler(...)` or the JDK common scheduler with virtual-thread dispatch. Cancelled in `close()`.
- One singleflight slot. Concurrent on-miss callers and the scheduler tick all funnel through this slot.
- Per-refresh virtual threads. Short-lived; GC'd when the refresh completes.
- `close()` is idempotent. It cancels the scheduler, marks the source closed (subsequent `resolve()` returns `null` and subsequent `refresh()` is a no-op), and waits up to `refreshTimeout` for any in-flight refresh to settle. It does not interrupt the in-flight refresh — the underlying `HttpURLConnection` already has its own connect/read timeouts.

## 5. Logging

Logging uses a small `Logger` interface in `org.lattejava.jwt.log`, mirroring the convention in `~/dev/latte-java/http`'s `org.lattejava.http.log.Logger`. The interface is package-local to this library — we do not depend on the HTTP project — but the shape is intentionally identical so callers can wrap a single SLF4J/JUL adapter and pass it to both.

```java
package org.lattejava.jwt.log;

public interface Logger {
  void trace(String message);
  void trace(String message, Object... values);
  void debug(String message);
  void debug(String message, Object... values);
  void debug(String message, Throwable throwable);
  void info(String message);
  void info(String message, Object... values);
  void error(String message);
  void error(String message, Throwable throwable);

  boolean isTraceEnabled();
  boolean isDebugEnabled();
  boolean isInfoEnabled();
  boolean isErrorEnabled();

  default boolean isEnabledForLevel(Level level) { /* switch */ }

  void setLevel(Level level);
}

public enum Level { Trace, Debug, Info, Error }
```

There is no `Warn` level — this matches `lattejava.http`. The standard rendering is: routine-but-noteworthy at `info`, anything actionable at `error`.

`JWKSource` events and their levels:

| Event | Level |
|---|---|
| Refresh dispatched (scheduler tick or on-miss) | `debug` |
| Refresh succeeded; key count, kid set delta | `info` |
| Refresh succeeded but `Cache-Control` clamped | `debug` |
| Refresh failed (network/parse/etc.) | `error` (with `Throwable`) |
| `Retry-After` honored | `info` |
| `close()` invoked | `debug` |

Default logger is `NoOpLogger` so the library is silent unless the integrator opts in. The interface shape is generic enough to absorb future events without an API change — that was the explicit reason for choosing a generic logger over a typed listener with named callbacks.

## 6. Composition with existing types

`JWKSource` is built on top of, not in place of, `JSONWebKeySetHelper`:

- `fromIssuer(...)` ⇒ `JSONWebKeySetHelper.retrieveKeysFromIssuer(issuer, customizer)`
- `fromWellKnownConfiguration(...)` ⇒ `JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration(url, customizer)`
- `fromJWKS(...)` ⇒ `JSONWebKeySetHelper.retrieveKeysFromJWKS(url, customizer)`

The existing helper already enforces the response/parse hardening (1 MiB cap, 3 redirects, JSON parse limits), so `JWKSource` inherits all of that for free.

One additive change to `JSONWebKeySetHelper` is required to support `Retry-After` honoring: we need package-visible variants of the three `retrieveKeysFrom*` methods that, on failure, surface the response status code and the `Retry-After` header (if any) to `JWKSource`. The existing public API and exception types are unchanged. The new variants live in the `org.lattejava.jwt.jwks` package and are not exported as part of the documented public surface.

`JWKSource` implements `VerifierResolver`, so:

```java
JWKSource source = JWKSource.fromIssuer("https://idp.example.com/")
    .scheduledRefresh(true)
    .refreshInterval(Duration.ofMinutes(15))
    .logger(myLogger)
    .build();

JWT jwt = JWT.decoder(source).decode(token);
```

## 7. Security considerations

| Threat | Mitigation |
|---|---|
| Algorithm confusion (asymmetric ↔ HMAC) | Each cached `Verifier` is built from a JWK that *requires* an `alg` member. JWKs without `alg` are rejected at refresh time. The `canVerify(alg)` defense-in-depth check in `VerifierResolver`'s contract catches it again at decode time. |
| Unknown-`kid` DoS amplification | Singleflight-coalesced refreshes + `nextDueAt` watermark with `minRefreshInterval` floor = at most one network call per `minRefreshInterval` window per source, regardless of attacker volume. |
| Slow-HTTP / hung IdP | `refreshTimeout` (default 2s) bounds blocking on the on-miss path. Scheduler ticks dispatch refreshes on virtual threads so a hung connection cannot wedge the scheduler. |
| Oversized JWKS response | Inherited from `JSONWebKeySetHelper`: 1 MiB body cap, 3-hop redirect limit, JSON parse limits. |
| Aggressive `Retry-After` (e.g. days) under attack | `nextDueAt` honors `Retry-After` only as a *floor extension* relative to `now + backoff`; the source still attempts at most one refresh per `nextDueAt` window. Because `lastSuccessfulRefresh()` does not advance, the integrator can detect prolonged staleness and intervene. |
| Excessive logging under attack | All event log calls except success/failure-of-refresh fire only when the level is enabled, and the success/failure rate is bounded by `nextDueAt`. |
| Cache poisoning via redirect | Redirect cap (3) inherited from `JSONWebKeySetHelper`; no special cookie/header handling. |

Two things we explicitly do **not** do in v1:

- **HTTPS enforcement.** The factory URL is taken at face value. This matches `JSONWebKeySetHelper`'s existing behavior and is necessary for test fixtures (loopback, self-hosted plain-HTTP IdPs). Operators who want HTTPS-only should validate their input or pass a `URL` whose scheme they have already checked.
- **Per-`kid` negative cache.** `nextDueAt` is global to the source; we do not remember "kid X was unknown N seconds ago". The global gate is sufficient — see analysis under §2.2.

## 8. Testing

Each test below describes intent; unit-test naming and structure follow project convention.

| # | Scenario |
|---|---|
| 1 | `fromIssuer` happy path: builds source, first `resolve()` triggers fetch, returns verifier for known `kid`. |
| 2 | `fromWellKnownConfiguration` with non-conventional discovery URL. |
| 3 | `fromJWKS` with non-OIDC issuer. |
| 4 | `scheduledRefresh=true` causes a fetch on each tick boundary; `currentKids()` reflects the latest snapshot. |
| 5 | `refreshOnMiss=true` triggers a fetch when an unknown `kid` arrives; subsequent decode finds the new key. |
| 6 | `refreshOnMiss=false` returns `null` for an unknown `kid` without fetching. |
| 7 | Singleflight: 100 concurrent `resolve()` calls with the same unknown `kid` produce exactly one network call. |
| 8 | `nextDueAt` gate: rapid unknown-`kid` decodes within `minRefreshInterval` produce exactly one refresh. |
| 9 | Exponential backoff: with default `minRefreshInterval=30s` / `refreshInterval=60m`, simulated consecutive failures produce the sequence 30s → 1m → 2m → 4m → 8m → 16m → 32m → 60m, then stay at 60m. |
| 10 | `Retry-After` honored: a 429 with `Retry-After: 60` extends `nextDueAt` to at least `now + 60s`. |
| 11 | `Retry-After` floor: a 429 with `Retry-After: 1` does *not* shrink `nextDueAt` below the backoff value. |
| 12 | `CacheControlPolicy.CLAMP` with `Cache-Control: max-age=10` clamps to `minRefreshInterval` (30s). |
| 13 | `CacheControlPolicy.CLAMP` with `Cache-Control: max-age=300` honors 300s when within `[minRefreshInterval, refreshInterval]`. |
| 14 | `CacheControlPolicy.IGNORE` ignores the server's `max-age` regardless of value. |
| 15 | Logger receives expected events at expected levels for: refresh-success, refresh-failure, `Retry-After`-honored. |
| 16 | `close()` cancels the scheduler; subsequent `resolve()` returns `null`; subsequent `refresh()` is a no-op. |
| 17 | Failure preserves prior keys: refresh fails, prior `kid`s still resolve; `lastSuccessfulRefresh()` does not advance. |

Tests use a small in-process HTTP server (one already exists in the repo's test sources for `JSONWebKeySetHelper`) so we can drive `Cache-Control`, `Retry-After`, and HTTP status codes directly.

## 9. Documentation / README updates

- Add a short `JWKSource` section to the project README under "Verifying tokens" pointing at the three factories.
- Add a Javadoc package-level overview to `org.lattejava.jwt.jwks` describing when to use `JWKSource` vs the lower-level `JSONWebKeySetHelper`.
- Per `feedback_javadoc_no_spec_refs`: do not link this spec from the production code's Javadoc.

## 10. Out of scope / future work

Captured here so reviewers know the line — these are deliberate v1 omissions, not oversights:

- **IETF `RateLimit-*` headers** (draft-ietf-httpapi-ratelimit-headers). Not stable enough to bake into v1; revisit when the draft becomes RFC.
- **`CacheControlPolicy.HONOR_ALWAYS`.** A mode that honors any `max-age` regardless of `minRefreshInterval`/`refreshInterval`. Easy to add later; deferred until someone has the use case.
- **`LoggerFactory` / per-instance loggers with names.** Single `Logger` per source for v1; if multiple sources warrant disambiguation, the integrator's `Logger` adapter handles that.
- **JWE support.** Out of scope; this is a JWS-verification helper.
- **Multi-source / multi-issuer composition.** A future `VerifierResolvers.tryEach(...)` could compose several `JWKSource`s. Not needed for v1; out of scope.
- **Disk persistence of the snapshot.** Cold-start latency is bounded by `refreshTimeout`; persistence adds operational complexity that the average integrator does not want.

## 11. Change log

- **rev 1 (2026-04-23)** — initial draft of the spec; outlined factory API, builder, defaults, snapshot model, threading.
- **rev 2 (2026-04-24)** — folded in review feedback:
  - Replaced the typed listener with a generic `Logger` interface mirroring `lattejava.http`'s convention; added `org.lattejava.jwt.log.{Logger,Level}` to the public surface.
  - Unified the cooldown concept into a single `nextDueAt` watermark on the snapshot, used by both the scheduler tick and the on-miss path.
  - Set the scheduler tick rate equal to `minRefreshInterval` instead of a separate knob.
  - Added `CacheControlPolicy` (`CLAMP` default, `IGNORE`) and brought Cache-Control honoring forward into v1.
  - Lowered default `refreshTimeout` from 5s to 2s.
  - Removed all proposed HTTPS enforcement; the library matches `JSONWebKeySetHelper`'s existing scheme-agnostic behavior.
  - Specified exponential backoff with `Retry-After` floor honoring and explicit caller-visible behavior during the failure window.
  - Renamed `KeyStore` → `JWKSource` (avoid shadowing `java.security.KeyStore`).
  - Added §6 note on the package-visible `JSONWebKeySetHelper` overload needed to surface `Retry-After`/status on failure.
  - Added §10 entries for IETF `RateLimit-*` headers, `CacheControlPolicy.HONOR_ALWAYS`, and `LoggerFactory`.
