/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.HTTPResponseException;
import org.lattejava.jwt.Header;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.Verifiers;
import org.lattejava.jwt.log.Logger;
import org.lattejava.jwt.log.NoOpLogger;

import java.net.HttpURLConnection;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * A self-refreshing {@link VerifierResolver} backed by a remote JWKS endpoint.
 */
public final class JWKSource implements VerifierResolver, AutoCloseable {
  private volatile boolean closed;
  private final AtomicReference<CompletableFuture<Snapshot>> inflight = new AtomicReference<>();
  private final AtomicReference<Snapshot> ref = new AtomicReference<>();
  private volatile Thread refreshThread;
  private final CacheControlPolicy cacheControlPolicy;
  private final Clock clock;
  private final Consumer<HttpURLConnection> httpConnectionCustomizer;
  private final Logger logger;
  private final Duration minRefreshInterval;
  private final Duration refreshInterval;
  private final boolean refreshOnMiss;
  private final Duration refreshTimeout;
  private final ScheduledExecutorService scheduler;
  private final boolean scheduledRefresh;
  private final FetchSource source;
  private final String url;

  private JWKSource(Builder b) {
    this.cacheControlPolicy = b.cacheControlPolicy;
    this.clock = b.clock;
    this.httpConnectionCustomizer = b.httpConnectionCustomizer;
    this.logger = b.logger;
    this.minRefreshInterval = b.minRefreshInterval;
    this.refreshInterval = b.refreshInterval;
    this.refreshOnMiss = b.refreshOnMiss;
    this.refreshTimeout = b.refreshTimeout;
    this.scheduledRefresh = b.scheduledRefresh;
    this.source = b.source;
    this.url = b.url();
    // Empty initial snapshot. nextDueAt=EPOCH so the first on-miss / scheduler
    // tick / build-time await is allowed to dispatch a refresh.
    this.ref.set(new Snapshot(Map.of(), Instant.EPOCH, Instant.EPOCH, 0, null));
    // build() bounds the awaiter by refreshTimeout but does not throw on
    // a network failure — failures land in the snapshot via singleflight;
    // timeouts leave the empty initial snapshot in place while the in-flight
    // fetch continues.
    CompletableFuture<Snapshot> initial = singleflightRefresh();
    try {
      initial.get(refreshTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException ignored) {
      // empty snapshot stays; VT continues asynchronously
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException ignored) {
      // failure snapshot is already installed by singleflight's catch path
    }
    if (scheduledRefresh) {
      this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jwks-source-scheduler");
        t.setDaemon(true);
        return t;
      });
      long tickMs = minRefreshInterval.toMillis();
      this.scheduler.scheduleAtFixedRate(this::onTick, tickMs, tickMs, TimeUnit.MILLISECONDS);
    } else {
      this.scheduler = null;
    }
  }

  private void onTick() {
    if (closed) return;
    Snapshot s = ref.get();
    Instant now = Instant.now(clock);
    if (now.isBefore(s.nextDueAt())) return;
    // Fire-and-forget: singleflightRefresh dispatches on a virtual thread; we do not await.
    singleflightRefresh();
  }

  // --- Factory entry points ---

  public static Builder fromIssuer(String issuer) {
    return new Builder(FetchSource.ISSUER, issuer);
  }

  public static Builder fromJWKS(String jwksURL) {
    return new Builder(FetchSource.JWKS, jwksURL);
  }

  public static Builder fromWellKnownConfiguration(String wellKnownURL) {
    return new Builder(FetchSource.WELL_KNOWN, wellKnownURL);
  }

  // --- Operational surface (filled in by later tasks) ---

  @Override
  public Verifier resolve(Header header) {
    Objects.requireNonNull(header, "header");
    if (closed) return null;
    String kid = header.kid();
    if (kid == null) return null;

    Snapshot snapshot = ref.get();
    Verifier v = snapshot.byKid().get(kid);
    if (v != null) {
      return v.canVerify(header.alg()) ? v : null;
    }
    if (!refreshOnMiss) return null;

    Instant now = Instant.now(clock);
    if (now.isBefore(snapshot.nextDueAt())) return null;

    CompletableFuture<Snapshot> fut = singleflightRefresh();
    try {
      fut.get(refreshTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException te) {
      return null;
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      return null;
    } catch (ExecutionException ee) {
      return null;
    }

    Snapshot fresh = ref.get();
    Verifier v2 = fresh.byKid().get(kid);
    if (v2 == null) return null;
    return v2.canVerify(header.alg()) ? v2 : null;
  }

  public void refresh() {
    if (closed) {
      if (logger.isDebugEnabled()) logger.debug("refresh() called on closed JWKSource");
      return;
    }
    CompletableFuture<Snapshot> fut = singleflightRefresh();
    try {
      fut.get(refreshTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException te) {
      return;
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      return;
    } catch (ExecutionException ee) {
      Throwable c = ee.getCause();
      if (c instanceof RuntimeException re) throw re;
      throw new RuntimeException(c);
    }
  }

  @Override
  public void close() {
    if (closed) return;
    closed = true;
    if (scheduler != null) {
      scheduler.shutdownNow();
    }
    CompletableFuture<Snapshot> in = inflight.get();
    if (in != null && !in.isDone()) {
      in.complete(null);
    }
    Thread t = refreshThread;
    if (t != null) {
      t.interrupt();
    }
    if (logger.isDebugEnabled()) logger.debug("JWKSource closed");
  }

  public int consecutiveFailures() {
    return ref.get().consecutiveFailures();
  }

  public Set<String> currentKids() {
    return Collections.unmodifiableSet(new LinkedHashSet<>(ref.get().byKid().keySet()));
  }

  public Instant lastFailedRefresh() {
    return ref.get().lastFailedRefresh();
  }

  public Instant lastSuccessfulRefresh() {
    Snapshot s = ref.get();
    return s.fetchedAt().equals(Instant.EPOCH) ? null : s.fetchedAt();
  }

  public Instant nextDueAt() {
    return ref.get().nextDueAt();
  }

  // --- Refresh internals ---

  /**
   * Exponential backoff, computed in long ms to avoid integer overflow at
   * high consecutive-failure counts. Returns
   * {@code min(refreshInterval, minRefreshInterval * 2^(consecutiveFailures-1))}.
   */
  static Duration backoff(int consecutiveFailures, Duration minRefreshInterval, Duration refreshInterval) {
    if (consecutiveFailures <= 0) return Duration.ZERO;
    long minMs = minRefreshInterval.toMillis();
    long capMs = refreshInterval.toMillis();
    int shift = Math.min(consecutiveFailures - 1, 62);
    long ms = Math.min(capMs, minMs * (1L << shift));
    if (ms < 0 || ms > capMs) ms = capMs;
    return Duration.ofMillis(ms);
  }

  /**
   * Returns the {@link Duration} to use for {@code nextDueAt}. Honors the
   * server's {@code Cache-Control: max-age} when {@link CacheControlPolicy#CLAMP}
   * is configured, clamped into {@code [minRefreshInterval, refreshInterval]};
   * the caller applies the {@code minRefreshInterval} floor again as a final
   * guard.
   */
  private Duration chosenInterval(JWKSResponse resp) {
    if (cacheControlPolicy == CacheControlPolicy.IGNORE) return refreshInterval;
    String cc = resp.selectedHeaders().get("Cache-Control");
    if (cc == null) return refreshInterval;

    Long maxAge = parseMaxAge(cc);
    if (maxAge == null) {
      if (logger.isDebugEnabled()) {
        logger.debug("Unparseable Cache-Control header [" + cc + "]; treating as absent");
      }
      return refreshInterval;
    }

    long ms = Math.max(0, maxAge) * 1000L;
    Duration desired = Duration.ofMillis(ms);
    if (desired.compareTo(minRefreshInterval) < 0) return minRefreshInterval;
    if (desired.compareTo(refreshInterval) > 0) return refreshInterval;
    return desired;
  }

  private static Duration maxOf(Duration a, Duration b) {
    return a.compareTo(b) >= 0 ? a : b;
  }

  /**
   * Parses {@code max-age=N} from a Cache-Control header. Returns {@code 0L}
   * for {@code no-store} or {@code max-age=0}. Returns {@code null} if the
   * header is malformed (unparseable {@code max-age}, multiple conflicting
   * {@code max-age} directives).
   *
   * <p>{@code no-store} takes precedence: a header carrying both {@code no-store}
   * and a {@code max-age} returns {@code 0L} and the {@code max-age} value is
   * discarded.</p>
   */
  static Long parseMaxAge(String headerValue) {
    if (headerValue == null) return null;
    boolean noStore = false;
    Long maxAge = null;
    boolean multiple = false;
    for (String tok : headerValue.split(",")) {
      String t = tok.trim().toLowerCase(java.util.Locale.ROOT);
      if (t.equals("no-store")) {
        noStore = true;
        continue;
      }
      if (t.startsWith("max-age=")) {
        try {
          long v = Long.parseLong(t.substring("max-age=".length()));
          if (maxAge != null && maxAge != v) multiple = true;
          maxAge = v;
        } catch (NumberFormatException nfe) {
          return null;
        }
      }
    }
    if (multiple) return null;
    if (noStore) return 0L;
    return maxAge;
  }

  /**
   * Returns the in-flight refresh future, dispatching a new one on a virtual
   * thread if no refresh is currently active. Order on completion: snapshot
   * updated first, then awaiters notified, then slot cleared.
   *
   * <p>If the refresh fails, the future completes exceptionally with the
   * underlying cause so that the operator-driven {@link #refresh()} path can
   * surface it. The on-miss path swallows the exception.</p>
   */
  private CompletableFuture<Snapshot> singleflightRefresh() {
    CompletableFuture<Snapshot> existing = inflight.get();
    if (existing != null) return existing;

    CompletableFuture<Snapshot> mine = new CompletableFuture<>();
    if (!inflight.compareAndSet(null, mine)) {
      CompletableFuture<Snapshot> winner = inflight.get();
      // The winner can complete and clear the slot between the failed CAS and
      // this read; in that case the snapshot has already been installed, so
      // hand the loser a completed future over the latest snapshot.
      return winner != null ? winner : CompletableFuture.completedFuture(ref.get());
    }

    if (logger.isDebugEnabled()) {
      logger.debug("JWKS refresh dispatched");
    }
    Thread.ofVirtual().start(() -> {
      refreshThread = Thread.currentThread();
      try {
        Snapshot prev = ref.get();
        Snapshot fresh;
        Throwable failureCause = null;
        try {
          fresh = doRefreshOrThrow(prev);
        } catch (Throwable t) {
          failureCause = t;
          if (logger.isErrorEnabled()) {
            logger.error("JWKS refresh failed", t);
          }
          fresh = failureSnapshot(prev, Instant.now(clock), t);
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

    return mine;
  }

  /**
   * Performs the refresh: fetch JWKS, build verifiers, install a Snapshot.
   * Throws on network/parse/non-2xx/empty-result so the singleflight catch
   * can complete the future exceptionally for the operator-driven
   * {@link #refresh()} path.
   */
  private Snapshot doRefreshOrThrow(Snapshot prev) {
    Instant now = Instant.now(clock);
    JWKSResponse resp = fetch();
    Map<String, Verifier> byKid = new LinkedHashMap<>();
    for (JSONWebKey jwk : resp.keys()) {
      Verifier v = Verifiers.fromJWK(jwk);
      if (v == null) continue;
      if (byKid.containsKey(jwk.kid())) {
        if (logger.isWarnEnabled()) {
          logger.warn("JWKS contains duplicate kid [" + jwk.kid() + "]; first-write-wins");
        }
        continue;
      }
      byKid.put(jwk.kid(), v);
    }
    if (byKid.isEmpty()) {
      throw new IllegalStateException("Empty kid map after JWK conversion");
    }
    Duration chosen = chosenInterval(resp);
    Instant nextDue = now.plus(maxOf(minRefreshInterval, chosen));
    if (logger.isInfoEnabled()) {
      logger.info("JWKS refresh succeeded; kids=[" + byKid.keySet() + "]");
    }
    return new Snapshot(Map.copyOf(byKid), now, nextDue, 0, null);
  }

  private JWKSResponse fetch() {
    return switch (source) {
      case ISSUER     -> JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer(url, httpConnectionCustomizer);
      case WELL_KNOWN -> JSONWebKeySetHelper.retrieveJWKSResponseFromWellKnownConfiguration(url, httpConnectionCustomizer);
      case JWKS       -> JSONWebKeySetHelper.retrieveJWKSResponseFromJWKS(url, httpConnectionCustomizer);
    };
  }

  /**
   * Build a failure-path {@link Snapshot}: carry forward the prior verifier
   * map, increment {@code consecutiveFailures}, and compute {@code nextDueAt}
   * as {@code now + backoff(...)}, extended to honor a {@code Retry-After}
   * header when present and stricter than the backoff.
   */
  private Snapshot failureSnapshot(Snapshot prev, Instant now, Throwable cause) {
    int prior = (prev == null) ? 0 : prev.consecutiveFailures();
    int next = prior + 1;
    Map<String, Verifier> byKid = (prev == null) ? Map.of() : prev.byKid();
    Instant fetchedAt = (prev == null) ? Instant.EPOCH : prev.fetchedAt();
    Duration off = backoff(next, minRefreshInterval, refreshInterval);
    Instant nextDue = now.plus(off);

    HTTPResponseException httpEx = unwrapHTTP(cause);
    if (httpEx != null) {
      String ra = httpEx.headerValue("Retry-After");
      if (ra != null) {
        Duration raDur = parseRetryAfter(ra);
        if (raDur != null) {
          Instant raNext = now.plus(raDur);
          if (raNext.isAfter(nextDue)) {
            nextDue = raNext;
            if (logger.isInfoEnabled()) {
              logger.info("Retry-After honored; nextDueAt extended by [" + raDur + "]");
            }
          }
        }
      }
    }
    return new Snapshot(byKid, fetchedAt, nextDue, next, now);
  }

  private static HTTPResponseException unwrapHTTP(Throwable t) {
    while (t != null) {
      if (t instanceof HTTPResponseException he) return he;
      t = t.getCause();
    }
    return null;
  }

  /**
   * Parse a Retry-After header (RFC 9110 §10.2.3). Supports the seconds form;
   * the HTTP-date form returns {@code null} (not needed in v1).
   */
  static Duration parseRetryAfter(String value) {
    if (value == null) return null;
    try {
      long seconds = Long.parseLong(value.trim());
      return seconds < 0 ? Duration.ZERO : Duration.ofSeconds(seconds);
    } catch (NumberFormatException nfe) {
      return null;
    }
  }

  // --- Internal types ---

  enum FetchSource { ISSUER, JWKS, WELL_KNOWN }

  /** Immutable cache snapshot. */
  record Snapshot(
      Map<String, Verifier> byKid,
      Instant fetchedAt,
      Instant nextDueAt,
      int consecutiveFailures,
      Instant lastFailedRefresh) {}

  // --- Builder ---

  public static final class Builder {
    private CacheControlPolicy cacheControlPolicy = CacheControlPolicy.CLAMP;
    private Clock clock = Clock.systemUTC();
    private Consumer<HttpURLConnection> httpConnectionCustomizer;
    private Logger logger = NoOpLogger.INSTANCE;
    private Duration minRefreshInterval = Duration.ofSeconds(30);
    private Duration refreshInterval = Duration.ofMinutes(60);
    private boolean refreshOnMiss = true;
    private Duration refreshTimeout = Duration.ofSeconds(2);
    private boolean scheduledRefresh = false;
    private final FetchSource source;
    private final String url;

    Builder(FetchSource source, String url) {
      this.source = source;
      this.url = url;
    }

    public Builder cacheControlPolicy(CacheControlPolicy p) {
      this.cacheControlPolicy = Objects.requireNonNull(p, "cacheControlPolicy");
      return this;
    }

    public Builder clock(Clock c) {
      this.clock = Objects.requireNonNull(c, "clock");
      return this;
    }

    public Builder httpConnectionCustomizer(Consumer<HttpURLConnection> c) {
      this.httpConnectionCustomizer = c;
      return this;
    }

    public Builder logger(Logger l) {
      this.logger = (l == null) ? NoOpLogger.INSTANCE : l;
      return this;
    }

    public Builder minRefreshInterval(Duration d) {
      this.minRefreshInterval = Objects.requireNonNull(d, "minRefreshInterval");
      return this;
    }

    public Builder refreshInterval(Duration d) {
      this.refreshInterval = Objects.requireNonNull(d, "refreshInterval");
      return this;
    }

    public Builder refreshOnMiss(boolean enabled) {
      this.refreshOnMiss = enabled;
      return this;
    }

    public Builder refreshTimeout(Duration d) {
      this.refreshTimeout = Objects.requireNonNull(d, "refreshTimeout");
      return this;
    }

    public Builder scheduledRefresh(boolean enabled) {
      this.scheduledRefresh = enabled;
      return this;
    }

    public JWKSource build() {
      Objects.requireNonNull(url, "url");
      if (url.isEmpty()) {
        throw new IllegalArgumentException("url must be non-empty");
      }
      if (refreshInterval.isZero() || refreshInterval.isNegative()) {
        throw new IllegalArgumentException("refreshInterval must be > 0 but found [" + refreshInterval + "]");
      }
      if (minRefreshInterval.isZero() || minRefreshInterval.isNegative()) {
        throw new IllegalArgumentException("minRefreshInterval must be > 0 but found [" + minRefreshInterval + "]");
      }
      if (refreshInterval.compareTo(minRefreshInterval) < 0) {
        throw new IllegalArgumentException(
            "refreshInterval [" + refreshInterval + "] must be >= minRefreshInterval [" + minRefreshInterval + "]");
      }
      if (refreshTimeout.isZero() || refreshTimeout.isNegative()) {
        throw new IllegalArgumentException("refreshTimeout must be > 0 but found [" + refreshTimeout + "]");
      }
      return new JWKSource(this);
    }

    String url() { return url; }
  }
}
