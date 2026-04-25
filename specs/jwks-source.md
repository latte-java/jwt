# JWKSource — self-refreshing JWK cache + VerifierResolver

| Field | Value |
|------|------|
| Status | Draft |
| Revision | 3 |
| Last updated | 2026-04-25 |
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
  public void refresh();                           // synchronous, blocking, singleflight-coalesced; throws on failure
  @Override public void close();                   // idempotent, cancels scheduler, discards in-flight refresh

  // Observability (lock-free reads off the current snapshot)
  public Instant lastSuccessfulRefresh();          // null if no successful refresh yet
  public Instant lastFailedRefresh();              // null if no failure since the last success
  public int consecutiveFailures();                // 0 on the success path
  public Instant nextDueAt();                      // earliest time at which a refresh is allowed to start
  public Set<String> currentKids();                // unmodifiable snapshot of kids in the cache at call time
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

  // Diagnostics / tests
  public Builder clock(Clock clock);                             // default: Clock.systemUTC()

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

`refreshTimeout` is the **decode-time wait cap**: it bounds how long `resolve()` and `refresh()` will block waiting for an in-flight refresh to complete. It does **not** abort the underlying HTTP fetch — the JDK connect/read timeouts on the `HttpURLConnection` bound that — and it does **not** count toward `consecutiveFailures`. If the refresh ultimately succeeds within the HTTP timeout, the snapshot is updated even though the original caller already timed out waiting.

`clock` is intended for tests (advancing time to validate the scheduler and `nextDueAt` gate) and for diagnostic time sources. Production code should leave it at `Clock.systemUTC()`. This mirrors `JWTDecoder.Builder.clock(Clock)`.

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
| `clock` | `Clock.systemUTC()` | Tests and diagnostics only; production leaves the default. |

### 1.4 Validation

`build()` is the only place that throws on configuration:

- `refreshInterval` must be positive.
- `minRefreshInterval` must be positive.
- `refreshInterval` must be `>= minRefreshInterval` (since `minRefreshInterval` is the tick rate, a `refreshInterval` smaller than one tick would be unreachable).
- `refreshTimeout` must be positive.
- The factory URL must be non-null and non-empty. **No scheme enforcement** — leaving this to the caller matches `JSONWebKeySetHelper`'s existing behavior and supports test fixtures that use plain HTTP.

Validation messages are stand-alone (no parameter echo unless the value is bounded — see `feedback_exception_message_style` memory).

`build()` performs an initial synchronous load — see §2.1.

### 1.5 JWK → Verifier helper

The conversion of a parsed JWK into a `Verifier` is a stand-alone, public helper so callers wiring the lower-level `JSONWebKeySetHelper` directly (or building their own `VerifierResolver`) can use the same logic JWKSource uses internally:

```java
public final class JSONWebKey {
  /**
   * Parse this JWK's public-key material into a {@link PublicKey}. Equivalent
   * to {@code JSONWebKey.parse(this)}; provided as an instance shorthand.
   * Each call performs a fresh KeyFactory parse — cache the result if hot.
   */
  public PublicKey toPublicKey();
}

public final class Verifiers {
  /**
   * Build a {@link Verifier} from a JSON Web Key, applying the rules in §2.8.
   * Returns {@code null} if the JWK is not usable for signature verification
   * under those rules. Does not throw on a rejected JWK.
   */
  public static Verifier fromJWK(JSONWebKey jwk);
}
```

The conversion rules are documented in §2.8. `JWKSource` calls `Verifiers.fromJWK` for each JWK at refresh time and skips the ones that return `null`.

## 2. Behavioral spec

### 2.1 Snapshot model and initial load

The cache state is a single immutable snapshot:

```java
record Snapshot(
    Map<String, Verifier> byKid,
    Instant fetchedAt,            // time of the snapshot's last successful fetch (Instant.EPOCH if never)
    Instant nextDueAt,             // earliest time at which a refresh is allowed to start
    int consecutiveFailures,      // 0 on the success path
    Instant lastFailedRefresh     // null if no recorded failure since the last success
) {}
```

It is held in `AtomicReference<Snapshot>`. Reads (`resolve()`, `currentKids()`, observability getters) load the reference and read fields off the snapshot — there are no locks on the read path.

`build()` performs a synchronous initial load, bounded by `refreshTimeout`:

- **On success:** snapshot installed with `consecutiveFailures=0`, `fetchedAt=now`, `nextDueAt` per §2.4, `lastFailedRefresh=null`.
- **On failure:** snapshot installed with `byKid=emptyMap`, `consecutiveFailures=1`, `fetchedAt=Instant.EPOCH`, `lastFailedRefresh=now`, `nextDueAt` per the failure path in §2.7. Failure is logged at `error`. `build()` returns normally; `lastSuccessfulRefresh()` returns `null`.

Operators wanting fail-fast on initial load check `lastSuccessfulRefresh() == null` after `build()` and act accordingly. The library does not throw from `build()` on a network failure, by design — it preserves the same "availability over freshness" stance as the runtime failure path (§2.7), so a brief IdP outage at boot does not make the application unstartable.

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

If step 6's await elapses at `refreshTimeout` before the in-flight refresh completes, the in-flight fetch continues asynchronously; the await returns the current `ref.get()` (the pre-refresh snapshot), the on-miss path returns `null`, and a later decode benefits from the eventually-installed snapshot. The timeout is not a refresh failure; see §2.7.4.

Returning `null` triggers `MissingVerifierException` in `JWTDecoder` (per `VerifierResolver`'s contract). That is the correct behavior for "unknown `kid` and we already refreshed recently" — the token genuinely is unverifiable with this source.

### 2.3 `refresh()`

Synchronous, blocking, singleflight-coalesced. If a refresh is already in flight, the caller awaits its completion (bounded by `refreshTimeout`) and returns. If the refresh succeeds, the new snapshot is installed before `refresh()` returns.

`refresh()` is the explicit, operator-driven path — it **throws** on failure (network, parse, non-2xx), with the underlying cause wrapped in a `JWTException`-typed exception. The snapshot is updated per §2.7 (prior keys preserved, `consecutiveFailures` incremented, `nextDueAt` advanced) before the exception leaves the method. Operators can retry, surface to a health probe, or just catch + log if they prefer the silent-with-log behavior.

`refresh()` ignores `nextDueAt`. The gate exists to defend against amplification on the on-miss / scheduler paths, not to throttle deliberate operator action.

If the source has been closed, `refresh()` is a no-op and logs at `debug`.

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
2. If `now >= s.nextDueAt`, dispatch a refresh on a virtual thread. The dispatch goes through the same singleflight as the on-miss path. **The scheduler does not await the dispatched refresh** — it returns immediately and waits for the next tick. A slow JWKS endpoint cannot wedge the scheduler.
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

**Parse hardening.** Only `max-age` and `no-store` are interpreted; other directives are ignored. If the header value is malformed (e.g. `max-age=abc`, missing `=`, multiple conflicting `max-age` directives), it is treated as if no `Cache-Control` header were present and the situation is logged at `debug`. A negative `max-age` is treated as `0` and then clamped per the policy.

This is a v1 feature because empirically, large IdPs (Auth0, Okta, AzureAD, Google Identity, Cognito) do publish `Cache-Control: public, max-age=...` on their JWKS endpoints — typically on the order of 5–60 minutes. Honoring it lets `JWKSource` follow the IdP's published rotation cadence rather than imposing its own.

### 2.7 Failure handling and exponential backoff

#### 2.7.1 Success path (recap)

`consecutiveFailures = 0`, `lastFailedRefresh = null`, and `nextDueAt = now + chosenInterval` per §2.4.

#### 2.7.2 Failure path

When a refresh raises (network failure, non-2xx response, parse failure, etc.):

1. Log at `error` with the cause.
2. `consecutiveFailures++`; `lastFailedRefresh = now`.
3. Compute (in `long` ms, to avoid integer overflow at high consecutive-failure counts) `backoff = min(refreshInterval, minRefreshInterval * 2^(consecutiveFailures-1))`. With the default settings (30s / 60m) this produces the sequence `30s → 1m → 2m → 4m → 8m → 16m → 32m → 60m (cap)` and stays at 60m thereafter.
4. If the failed response carried `Retry-After` (RFC 9110 §10.2.3), use `nextDueAt = max(now + backoff, now + retryAfter)`. Honoring `Retry-After` lets the IdP throttle us beyond our own backoff curve, but never *under* our own minimum.
5. The snapshot is replaced with `Snapshot(prevByKid, prevFetchedAt, nextDueAt, consecutiveFailures, lastFailedRefresh)`. Existing keys remain available — availability over freshness — until the next successful refresh either restores them or the operator decides to take action based on `lastSuccessfulRefresh()`.

#### 2.7.3 Caller-visible behavior during failure

- `resolve()` continues to return cached verifiers from the prior successful snapshot.
- Misses against unknown `kid`s return `null` immediately once `nextDueAt` is in the future.
- `lastSuccessfulRefresh()` does not advance; an integrator monitoring this can alert on staleness.
- `lastFailedRefresh()` advances to `now`; `consecutiveFailures()` increments.

There is no separate "circuit breaker open" state; the exponential-backoff `nextDueAt` *is* the circuit. After enough consecutive failures, `nextDueAt` settles at `now + refreshInterval` and the source effectively reverts to "try every full interval until something changes".

#### 2.7.4 What does not count as a failure

`refreshTimeout` elapsing on the awaiter side does **not** count. It bounds how long `resolve()` and `refresh()` block waiting for the singleflight; it does not abort the underlying HTTP fetch and does not signal a refresh failure. Only HTTP-level outcomes (connect/read timeout, non-2xx status, response-too-large, parse failure, JWK conversion that produces an empty result — see §2.8) count toward `consecutiveFailures`.

### 2.8 JWK → Verifier conversion

Each JWK in the parsed JWKS array is run through `Verifiers.fromJWK(jwk)`. The rules a JWK must satisfy to produce a usable `Verifier`:

| Required | Rule |
|---|---|
| `kid` | Must be present. JWKs without `kid` are inexpressible in the kid-keyed map and are skipped. |
| `alg` | Must be present and a recognized JWA algorithm name (`Algorithm.of(...)` of one of the 15 standard algorithms). HMAC algorithms (`HS256`/`HS384`/`HS512`) on a public JWKS are skipped — symmetric secrets do not belong on a public endpoint. The verifier is constructed for this algorithm; defense-in-depth in the decode path re-checks `verifier.canVerify(header.alg())`. |
| `kty` | `RSA`, `EC`, or `OKP`. `oct` keys are skipped (same reason as HMAC `alg`). |
| `use` | If present, must be `sig`. `enc` is skipped; absence is permitted. |
| `alg` ↔ `crv` | For EC: `ES256`↔`P-256`, `ES384`↔`P-384`, `ES512`↔`P-521`, `ES256K`↔`secp256k1`. For OKP: `Ed25519`↔`Ed25519`, `Ed448`↔`Ed448`. Mismatches are skipped. |
| Parse | The JWK's key material must parse cleanly (`JSONWebKey.toPublicKey()` does not throw). Parse failures are skipped. |

When a JWK is skipped, the reason is logged at `debug` (or `warn` for the alg/crv mismatch and duplicate-`kid` cases — those almost always indicate an authoring or tampering signal worth surfacing). The refresh **does not fail** on a per-JWK rejection; the remaining valid JWKs are accepted into the snapshot.

**Duplicate `kid` handling.** If two JWKs in the same JWKS share a `kid`, the **first one wins**. Subsequent occurrences are skipped and logged at `warn`. First-write-wins is safer than last-write-wins against a JWKS that may have been tampered to append a second entry under an existing `kid`.

**Empty result.** If every JWK is rejected (e.g. a JWKS publishing only `oct` keys, or a JWKS whose every entry is malformed), the refresh is treated as a **failure** for the purposes of §2.7 — `consecutiveFailures` advances and `nextDueAt` is computed via the backoff formula. The fetch itself succeeded, but the source has nothing usable to install; treating it as a failure surfaces the configuration problem to the operator via the observability getters and the failure log.

## 3. Concurrency model

| State | Mechanism |
|---|---|
| Current snapshot | `AtomicReference<Snapshot>`; lock-free reads, CAS on writes |
| Singleflight refresh | A single in-flight `CompletableFuture<Snapshot>`; awaiters subscribe. **On completion, the `AtomicReference<Snapshot>` is updated first, then the singleflight slot is cleared.** Reverse ordering would let a new dispatch start before the new snapshot is observable. |
| `nextDueAt`, `consecutiveFailures`, `lastFailedRefresh` | Fields of the immutable snapshot; updated atomically with the snapshot itself |
| Scheduler | One virtual-thread scheduled task; cancellation via `close()` |
| Refresh dispatch | Virtual thread per refresh attempt (so a slow JWKS endpoint never blocks the scheduler tick) |

The goal of this state model is that a `resolve()` that hits the cache requires zero allocations and zero locks, regardless of how many concurrent refreshes are in flight or how often the scheduler is waking.

## 4. Threading model

- One scheduler. Created in `build()` only when `scheduledRefresh=true`. Backed by `Thread.ofVirtual().scheduler(...)` or the JDK common scheduler with virtual-thread dispatch. Cancelled in `close()`.
- One singleflight slot. Concurrent on-miss callers and the scheduler tick all funnel through this slot.
- Per-refresh virtual threads. Short-lived; GC'd when the refresh completes.
- `close()` is idempotent. It:
  1. Cancels the scheduler.
  2. Marks the source closed: subsequent `resolve()` returns `null`, subsequent `refresh()` is a no-op + debug log.
  3. Completes any pending singleflight awaiters with `null` (so callers blocked in `resolve()` unwind cleanly).
  4. Does **not** interrupt the in-flight HTTP fetch — `HttpURLConnection` doesn't expose a clean cancellation point, and the JDK connect/read timeouts will bound it. When that fetch eventually completes, **its result is discarded** — no snapshot update, no log emission.

## 5. Logging

Logging uses a small `Logger` interface in `org.lattejava.jwt.log`, mirroring the convention in `~/dev/latte-java/http`'s `org.lattejava.http.log.Logger`. The interface is package-local to this library — we do not depend on the HTTP project — but the shape is intentionally close so callers can wrap a single SLF4J/JUL adapter and pass it to both. The one deliberate divergence: this library adds a `warn` level. lattejava.http does not have one; the intent is to revisit lattejava.http and align it later (tracked in §10).

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
  void warn(String message);
  void warn(String message, Object... values);
  void warn(String message, Throwable throwable);
  void error(String message);
  void error(String message, Throwable throwable);

  boolean isTraceEnabled();
  boolean isDebugEnabled();
  boolean isInfoEnabled();
  boolean isWarnEnabled();
  boolean isErrorEnabled();

  default boolean isEnabledForLevel(Level level) { /* switch */ }

  void setLevel(Level level);
}

public enum Level { Trace, Debug, Info, Warn, Error }
```

`JWKSource` uses one `Logger` per source (no `LoggerFactory`); v1 deliberately avoids the named-logger machinery — integrators that need disambiguation handle it in the adapter they pass to `Builder.logger(...)`.

`JWKSource` events and their levels:

| Event | Level |
|---|---|
| Refresh dispatched (scheduler tick or on-miss) | `debug` |
| Refresh succeeded; key count, kid set delta | `info` |
| Refresh succeeded but `Cache-Control` clamped | `debug` |
| `Cache-Control` header unparseable; ignored | `debug` |
| Refresh succeeded but produced an empty kid map | `error` |
| Refresh failed (network/parse/etc.) | `error` (with `Throwable`) |
| Initial load at `build()` failed | `error` (with `Throwable`) |
| `Retry-After` honored | `info` |
| JWK rejected: alg/crv mismatch | `warn` |
| JWK rejected: duplicate `kid` in JWKS | `warn` |
| JWK rejected: missing `kid` / `kty=oct` / `use=enc` / parse error | `debug` |
| `close()` invoked | `debug` |

Default logger is `NoOpLogger` so the library is silent unless the integrator opts in. The interface shape is generic enough to absorb future events without an API change — that was the explicit reason for choosing a generic logger over a typed listener with named callbacks.

## 6. Composition with existing types

`JWKSource` is built on top of, not in place of, `JSONWebKeySetHelper`:

- `fromIssuer(...)` ⇒ `JSONWebKeySetHelper.retrieveKeysFromIssuer(issuer, customizer)`
- `fromWellKnownConfiguration(...)` ⇒ `JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration(url, customizer)`
- `fromJWKS(...)` ⇒ `JSONWebKeySetHelper.retrieveKeysFromJWKS(url, customizer)`

The existing helper already enforces the response/parse hardening (1 MiB cap, 3 redirects, JSON parse limits), so `JWKSource` inherits all of that for free.

`JWKSource` implements `VerifierResolver`, so:

```java
JWKSource source = JWKSource.fromIssuer("https://idp.example.com/")
    .scheduledRefresh(true)
    .refreshInterval(Duration.ofMinutes(15))
    .logger(myLogger)
    .build();

JWT jwt = JWT.decoder(source).decode(token);
```

Three additive changes to the wider codebase are required:

- **`AbstractHttpHelper.get` extension.** To support `Retry-After` and `Cache-Control` honoring, JWKSource needs visibility into the HTTP response on both success and failure. Concretely: change the success consumer signature from `Function<InputStream, T>` to `BiFunction<HttpURLConnection, InputStream, T>` (existing call sites pass a `BiFunction` that ignores the first arg), and have the failure path throw a richer exception type carrying `int statusCode` plus selected response headers (`Retry-After`, `Cache-Control`). The existing public exception types (`JSONWebKeyException`, `JSONWebKeySetException`) gain an optional cause-chain that surfaces this richer exception. Callers that don't care continue to see the same outer types.
- **`JSONWebKeySetHelper` `httpConnectionCustomizer` propagation.** Today, `retrieveKeysFromWellKnownConfiguration(endpoint, consumer)` applies the customizer only to the discovery hop; the inner `retrieveKeysFromJWKS(uri)` call drops it. Integrators adding `Authorization` for an authenticated JWKS endpoint silently lose it on the second hop. Fix in the same PR as JWKSource: thread the customizer through to the inner call.
- **`JSONWebKey.toPublicKey()` and `Verifiers.fromJWK(JSONWebKey)`.** See §1.5 / §2.8.

**Static configuration inheritance.** `JSONWebKeySetHelper.setMaxResponseSize`, `setMaxRedirects`, and the JSON parse limits are JVM-global. JWKSource inherits them; it does not provide per-instance overrides in v1. See §10.

## 7. Security considerations

| Threat | Mitigation |
|---|---|
| Algorithm confusion (asymmetric ↔ HMAC) | Each cached `Verifier` is built from a JWK that *requires* an `alg` member. JWKs without `alg`, with `kty=oct`, or with HMAC `alg` are skipped at refresh time (§2.8). The `canVerify(alg)` defense-in-depth check in `VerifierResolver`'s contract catches it again at decode time. |
| Unknown-`kid` DoS amplification | Singleflight-coalesced refreshes + `nextDueAt` watermark with `minRefreshInterval` floor = at most one network call per `minRefreshInterval` window per source, regardless of attacker volume. |
| Slow-HTTP / hung IdP | `refreshTimeout` (default 2s) bounds blocking on the on-miss path. Scheduler ticks dispatch refreshes on virtual threads so a hung connection cannot wedge the scheduler. JDK connect/read timeouts (10s each, set on the underlying `HttpURLConnection`) bound the underlying fetch. |
| Oversized JWKS response | Inherited from `JSONWebKeySetHelper`: 1 MiB body cap, 3-hop redirect limit, JSON parse limits. |
| Aggressive `Retry-After` (e.g. days) under attack | `nextDueAt` honors `Retry-After` only as a *floor extension* relative to `now + backoff`; the source still attempts at most one refresh per `nextDueAt` window. Because `lastSuccessfulRefresh()` does not advance, the integrator can detect prolonged staleness and intervene. |
| Excessive logging under attack | All event log calls except success/failure-of-refresh fire only when the level is enabled, and the success/failure rate is bounded by `nextDueAt`. |
| Cache poisoning via redirect | Redirect cap (3) inherited from `JSONWebKeySetHelper`; no special cookie/header handling. |
| JWKS tampered to append duplicate `kid` | First-write-wins on duplicate `kid` (§2.8); second occurrence rejected and logged at `warn`. |
| Internal-network probing via attacker-controlled issuer URL (SSRF) | The library performs no IP/host filtering; this is the **caller's responsibility**. Operators using untrusted issuer URLs must layer their own SSRF protection (e.g., an egress proxy, or a deny-list filter applied via the `httpConnectionCustomizer`). |

Two things we explicitly do **not** do in v1:

- **HTTPS enforcement.** The factory URL is taken at face value. This matches `JSONWebKeySetHelper`'s existing behavior and is necessary for test fixtures (loopback, self-hosted plain-HTTP IdPs). Operators who want HTTPS-only should validate their input or pass a `URL` whose scheme they have already checked.
- **Per-`kid` negative cache.** `nextDueAt` is global to the source; we do not remember "kid X was unknown N seconds ago". The global gate is sufficient — see analysis under §2.2.

## 8. Testing

Each test below describes intent; unit-test naming and structure follow project convention.

| # | Scenario |
|---|---|
| 1 | `fromIssuer` happy path: `build()` performs initial sync load; first `resolve()` is a hit (no fetch). |
| 2 | `fromWellKnownConfiguration` with non-conventional discovery URL. |
| 3 | `fromJWKS` with non-OIDC issuer. |
| 4 | `build()` initial-load failure leaves the source usable with empty cache, `consecutiveFailures=1`, `lastSuccessfulRefresh()=null`. |
| 5 | `scheduledRefresh=true` causes a fetch on each tick boundary; `currentKids()` reflects the latest snapshot (clock-driven). |
| 6 | `refreshOnMiss=true` triggers a fetch when an unknown `kid` arrives; subsequent decode finds the new key. |
| 7 | `refreshOnMiss=false` returns `null` for an unknown `kid` without fetching. |
| 8 | Singleflight: 100 concurrent `resolve()` calls with the same unknown `kid` produce exactly one network call. |
| 9 | `nextDueAt` gate: rapid unknown-`kid` decodes within `minRefreshInterval` produce exactly one refresh. |
| 10 | Exponential backoff: with default `minRefreshInterval=30s` / `refreshInterval=60m`, simulated consecutive failures produce the sequence 30s → 1m → 2m → 4m → 8m → 16m → 32m → 60m, then stay at 60m. |
| 11 | `Retry-After` honored: a 429 with `Retry-After: 60` extends `nextDueAt` to at least `now + 60s`. |
| 12 | `Retry-After` floor: a 429 with `Retry-After: 1` does *not* shrink `nextDueAt` below the backoff value. |
| 13 | `CacheControlPolicy.CLAMP` with `Cache-Control: max-age=10` clamps to `minRefreshInterval` (30s). |
| 14 | `CacheControlPolicy.CLAMP` with `Cache-Control: max-age=300` honors 300s when within `[minRefreshInterval, refreshInterval]`. |
| 15 | `CacheControlPolicy.CLAMP` with malformed `Cache-Control` (`max-age=abc`) is treated as absent. |
| 16 | `CacheControlPolicy.IGNORE` ignores the server's `max-age` regardless of value. |
| 17 | Logger receives expected events at expected levels for: refresh-success, refresh-failure, `Retry-After`-honored, JWK rejected, duplicate kid. |
| 18 | `close()` cancels the scheduler; subsequent `resolve()` returns `null`; subsequent `refresh()` is a no-op. |
| 19 | Failure preserves prior keys: refresh fails, prior `kid`s still resolve; `lastSuccessfulRefresh()` does not advance; `lastFailedRefresh()` and `consecutiveFailures()` do. |
| 20 | `refresh()` throws on failure (network, parse, non-2xx). |
| 21 | `Verifiers.fromJWK` skips: `kty=oct`; `use=enc`; missing `kid`; missing `alg`; HMAC `alg`; `alg`/`crv` mismatch; key parse failure. |
| 22 | Duplicate `kid` in JWKS: first wins; second is logged at `warn`; the first-occurrence verifier is the one in the snapshot. |
| 23 | Empty post-conversion result is treated as a failure (counts toward `consecutiveFailures`). |
| 24 | `httpConnectionCustomizer` is applied to **both** the discovery hop and the JWKS hop after a discovery resolution. |
| 25 | `refreshTimeout` elapsing on the awaiter does NOT count as a failure; the in-flight refresh's eventual success updates the snapshot. |

Tests use the in-process HTTP server already present in the repo (`HttpServerBuilder` / `BuilderHTTPHandler` / `ExpectedResponse`) for `Cache-Control`, `Retry-After`, and HTTP status codes. The handler's `ExpectedResponse` will need a small extension to set arbitrary response headers (`Cache-Control`, `Retry-After`) — additive change.

## 9. Documentation / README updates

- Add a short `JWKSource` section to the project README under "Verifying tokens" pointing at the three factories.
- Add a Javadoc package-level overview to `org.lattejava.jwt.jwks` describing when to use `JWKSource` vs the lower-level `JSONWebKeySetHelper`.
- Per `feedback_javadoc_no_spec_refs`: do not link this spec from the production code's Javadoc.

## 10. Out of scope / future work

Captured here so reviewers know the line — these are deliberate v1 omissions, not oversights:

- **IETF `RateLimit-*` headers** (draft-ietf-httpapi-ratelimit-headers). Not stable enough to bake into v1; revisit when the draft becomes RFC.
- **`CacheControlPolicy.HONOR_ALWAYS`.** A mode that honors any `max-age` regardless of `minRefreshInterval`/`refreshInterval`. Easy to add later; deferred until someone has the use case.
- **`LoggerFactory` / per-instance loggers with names.** Single `Logger` per source for v1; if multiple sources warrant disambiguation, the integrator's `Logger` adapter handles that.
- **Per-instance HTTP/parse hardening overrides on JWKSource** (response size, redirects, JSON parse limits). JWKSource inherits the JVM-global `JSONWebKeySetHelper` static settings in v1. Adopt when `JSONWebKeySetHelper` itself moves off static config.
- **Reconciling Logger shape with lattejava.http.** This library adds a `warn` level; lattejava.http does not have one. Revisit lattejava.http and align both libraries on the same shape.
- **JWE support.** Out of scope; this is a JWS-verification helper.
- **Multi-source / multi-issuer composition.** A future `VerifierResolvers.tryEach(...)` could compose several `JWKSource`s. Not needed for v1; out of scope.
- **Disk persistence of the snapshot.** Cold-start latency is bounded by `refreshTimeout`; persistence adds operational complexity that the average integrator does not want.
- **Programmatic Metrics SPI.** Observability getters are exposed (§1.1); a generic OpenTelemetry / Prometheus / Dropwizard-compatible Metrics interface is deferred until a concrete integration use case materializes.

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
- **rev 3 (2026-04-25)** — second review pass:
  - Replaced the placeholder `VerifierFactory` with a public, stand-alone helper: `Verifiers.fromJWK(JSONWebKey)` and `JSONWebKey.toPublicKey()` (§1.5). Defined the JWK→Verifier conversion rules in §2.8 (skip on missing `kid`/`alg`, HMAC `alg`, `kty=oct`, `use=enc`, alg/crv mismatch, parse failure; first-write-wins on duplicate `kid`; empty post-conversion result treated as a refresh failure).
  - Pinned `build()` semantics: synchronous initial load bounded by `refreshTimeout`; on failure, the source is still usable with empty cache and `consecutiveFailures=1` (no throw from `build()` on a network failure).
  - `refresh()` now throws on failure; documented as the explicit, operator-driven path.
  - Specified `close()` semantics in detail: cancel scheduler, complete awaiters with `null`, do not interrupt the in-flight HTTP fetch, discard its result.
  - Pinned the singleflight ordering: snapshot updated first, slot cleared second (§3).
  - Made the scheduler tick fire-and-forget explicit (§2.5).
  - Added `Cache-Control` parse hardening (unparseable header treated as absent; debug log).
  - Added observability getters: `consecutiveFailures()`, `nextDueAt()`, `lastFailedRefresh()`. Added `Builder.clock(Clock)` for tests/diagnostics.
  - Added a `warn` level to the `Logger` interface (diverges from lattejava.http; revisit there). Added `JWK rejected` and `duplicate kid` warn-level events.
  - Added SSRF row to §7.
  - Documented `httpConnectionCustomizer` propagation fix to `JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration`.
  - Documented the `AbstractHttpHelper.get` extension shape: success consumer becomes `BiFunction<HttpURLConnection, InputStream, T>`; failure path throws a richer exception type carrying status + selected headers.
  - Reframed `refreshTimeout` as the **decode-time wait cap**; clarified that elapsing it does not count toward `consecutiveFailures` (§2.7.4).
  - Documented JWKSource's static-config inheritance from `JSONWebKeySetHelper` (per-instance overrides deferred to §10).
  - `Snapshot` record gained a `lastFailedRefresh` field.
