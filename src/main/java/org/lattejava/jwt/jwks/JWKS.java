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

import org.lattejava.jwt.FetchLimits;
import org.lattejava.jwt.HTTPResponseException;
import org.lattejava.jwt.Header;
import org.lattejava.jwt.InvalidJWKException;
import org.lattejava.jwt.OpenIDConnectConfiguration;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.Verifiers;
import org.lattejava.jwt.log.Logger;
import org.lattejava.jwt.log.NoOpLogger;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
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
public final class JWKS implements VerifierResolver, AutoCloseable {
  private final CacheControlPolicy cacheControlPolicy;
  private final Clock clock;
  private volatile boolean closed;
  private final boolean failFast;
  private final FetchLimits fetchLimits;
  private final Consumer<HttpURLConnection> httpConnectionCustomizer;
  private final AtomicReference<CompletableFuture<Snapshot>> inflight = new AtomicReference<>();
  private final Logger logger;
  private final Duration minRefreshInterval;
  private final AtomicReference<Snapshot> ref = new AtomicReference<>();
  private final Duration refreshInterval;
  private final boolean refreshOnMiss;
  private volatile Thread refreshThread;
  private final Duration refreshTimeout;
  private final boolean scheduledRefresh;
  private final ScheduledExecutorService scheduler;
  private final FetchSource source;
  private final boolean staticMode;
  private final String url;

  private JWKS(Builder b) {
    this.cacheControlPolicy = b.cacheControlPolicy;
    this.clock = b.clock;
    this.failFast = b.failFast;
    this.fetchLimits = b.fetchLimits;
    this.httpConnectionCustomizer = b.httpConnectionCustomizer;
    this.logger = b.logger;
    this.minRefreshInterval = b.minRefreshInterval;
    this.refreshInterval = b.refreshInterval;
    this.refreshOnMiss = b.refreshOnMiss;
    this.refreshTimeout = b.refreshTimeout;
    this.scheduledRefresh = b.scheduledRefresh;
    this.source = b.source;
    this.staticMode = false;
    this.url = b.url();
    this.ref.set(new Snapshot(List.of(), Map.of(), Map.of(), Instant.EPOCH, Instant.EPOCH, 0, null));
    CompletableFuture<Snapshot> initial = singleflightRefresh();
    try {
      initial.get(refreshTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException ignored) {
      // empty snapshot stays; the worker continues asynchronously
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException ignored) {
      // closed is necessarily false during construction, so the worker's
      // !closed guard always passes here and the failure snapshot is in ref
    }
    if (scheduledRefresh) {
      this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jwks-scheduler");
        t.setDaemon(true);
        return t;
      });
      long tickMs = minRefreshInterval.toMillis();
      this.scheduler.scheduleAtFixedRate(this::onTick, tickMs, tickMs, TimeUnit.MILLISECONDS);
    } else {
      this.scheduler = null;
    }
  }

  private JWKS(List<JSONWebKey> staticKeys) {
    this.cacheControlPolicy = CacheControlPolicy.IGNORE;
    this.clock = Clock.systemUTC();
    this.failFast = false;
    this.fetchLimits = FetchLimits.defaults();
    this.httpConnectionCustomizer = null;
    this.logger = NoOpLogger.INSTANCE;
    this.minRefreshInterval = Duration.ofMinutes(60);
    this.refreshInterval = Duration.ofMinutes(60);
    this.refreshOnMiss = false;
    this.refreshTimeout = Duration.ofSeconds(2);
    this.scheduledRefresh = false;
    this.scheduler = null;
    this.source = FetchSource.JWKS;
    this.staticMode = true;
    this.url = null;

    List<JSONWebKey> allKeys = new ArrayList<>();
    Map<String, Verifier> byKid = new LinkedHashMap<>();
    Map<String, JSONWebKey> jwkByKid = new LinkedHashMap<>();
    for (JSONWebKey jwk : staticKeys) {
      Verifier v;
      try {
        v = Verifiers.fromJWK(jwk);
      } catch (InvalidJWKException reject) {
        if (reject.reason() == InvalidJWKException.Reason.MISSING_KID) {
          allKeys.add(jwk);
        }
        continue;
      }
      String kid = jwk.kid();
      if (kid != null && byKid.containsKey(kid)) {
        continue;
      }
      allKeys.add(jwk);
      if (kid != null) {
        byKid.put(kid, v);
        jwkByKid.put(kid, jwk);
      }
    }
    this.ref.set(new Snapshot(
        Collections.unmodifiableList(new ArrayList<>(allKeys)),
        Collections.unmodifiableMap(new LinkedHashMap<>(byKid)),
        Collections.unmodifiableMap(new LinkedHashMap<>(jwkByKid)),
        Instant.EPOCH,
        Instant.EPOCH,
        0,
        null));
  }

  // --- Public static methods ---

  public static Builder fromConfiguration(OpenIDConnectConfiguration cfg) {
    Objects.requireNonNull(cfg, "cfg");
    return new Builder(FetchSource.JWKS, cfg.jwksURI(), cfg);
  }

  public static Builder fromIssuer(String issuer) {
    return new Builder(FetchSource.ISSUER, issuer);
  }

  public static Builder fromJWKS(String jwksURL) {
    return new Builder(FetchSource.JWKS, jwksURL);
  }

  public static Builder fromWellKnown(String wellKnownURL) {
    return new Builder(FetchSource.WELL_KNOWN, wellKnownURL);
  }

  public static JWKS of(JSONWebKey... keys) {
    return new JWKS(keys == null ? List.of() : Arrays.asList(keys));
  }

  public static JWKS of(List<JSONWebKey> keys) {
    Objects.requireNonNull(keys, "keys");
    return new JWKS(keys);
  }

  // --- Package-private static methods (test-visible) ---

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
   * Parse a {@code Cache-Control} header value into {@link CacheControlDirectives}.
   * Distinguishes "header present but no max-age directive" (e.g. {@code Cache-Control: public})
   * from "header is malformed" (e.g. {@code max-age=abc}, conflicting {@code max-age}).
   */
  static CacheControlDirectives parseCacheControl(String headerValue) {
    if (headerValue == null) return new CacheControlDirectives(null, false, false);
    boolean noStore = false;
    Long firstMaxAge = null;
    boolean malformed = false;
    for (String tok : headerValue.split(",")) {
      String t = tok.trim().toLowerCase(Locale.ROOT);
      if (t.equals("no-store")) {
        noStore = true;
        continue;
      }
      if (t.startsWith("max-age=")) {
        try {
          long v = Long.parseLong(t.substring("max-age=".length()));
          if (firstMaxAge != null && firstMaxAge != v) {
            malformed = true;
          } else if (firstMaxAge == null) {
            firstMaxAge = v;
          }
        } catch (NumberFormatException nfe) {
          malformed = true;
        }
      }
    }
    return new CacheControlDirectives(firstMaxAge, noStore, malformed);
  }

  /**
   * Parse a {@code Retry-After} header value (RFC 9110 §10.2.3). Supports
   * the delta-seconds form and the HTTP-date (RFC 1123) form. Returns
   * {@code null} if neither parse succeeds.
   *
   * @param value the header value
   * @param now the reference instant for HTTP-date deltas (the source's {@link Clock})
   */
  static Duration parseRetryAfter(String value, Instant now) {
    if (value == null) return null;
    String trimmed = value.trim();
    try {
      long seconds = Long.parseLong(trimmed);
      return seconds < 0 ? Duration.ZERO : Duration.ofSeconds(seconds);
    } catch (NumberFormatException ignored) {
      // fall through to HTTP-date parsing
    }
    try {
      ZonedDateTime when = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME);
      Duration delta = Duration.between(now, when.toInstant());
      return delta.isNegative() ? Duration.ZERO : delta;
    } catch (DateTimeParseException ignored) {
      return null;
    }
  }

  // --- Private static methods ---

  private static Duration maxOf(Duration a, Duration b) {
    return a.compareTo(b) >= 0 ? a : b;
  }

  private static HTTPResponseException unwrapHTTP(Throwable t) {
    while (t != null) {
      if (t instanceof HTTPResponseException he) return he;
      t = t.getCause();
    }
    return null;
  }

  // --- Public instance methods ---

  @Override
  public void close() {
    if (staticMode) return;
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
    if (logger.isDebugEnabled()) logger.debug("JWKS closed");
  }

  public int consecutiveFailures() {
    if (staticMode) return 0;
    return ref.get().consecutiveFailures();
  }

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

  /**
   * Synchronous, blocking, singleflight-coalesced refresh. Throws a
   * {@link JWKSFetchException} on failure, with a categorical
   * {@link JWKSFetchException#reason()} so callers can dispatch
   * programmatically without unwrapping the cause chain.
   *
   * @throws JWKSFetchException if the refresh fails or times out
   */
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
      // worker always wraps; defense-in-depth path
      throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
          "JWKS refresh failed", c != null ? c : ee);
    }
  }

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

  // --- Private instance methods ---

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

    CacheControlDirectives d = parseCacheControl(cc);
    if (d.malformed()) {
      if (logger.isWarnEnabled()) {
        logger.warn("Malformed Cache-Control header [" + cc + "]; treating as absent");
      }
      return refreshInterval;
    }
    if (d.noStore()) {
      // no-store and max-age=0 both clamp to the floor under CLAMP per spec §2.6
      return minRefreshInterval;
    }
    if (d.maxAge() == null) {
      // header present but had no max-age directive (e.g. "Cache-Control: public")
      return refreshInterval;
    }

    long secs = Math.max(0, d.maxAge());
    long ms = (secs > Long.MAX_VALUE / 1000L) ? Long.MAX_VALUE : secs * 1000L;
    Duration desired = Duration.ofMillis(ms);
    if (desired.compareTo(minRefreshInterval) < 0) return minRefreshInterval;
    if (desired.compareTo(refreshInterval) > 0) return refreshInterval;
    return desired;
  }

  /**
   * Classify a non-{@link JWKSFetchException} failure into a refresh reason.
   * HTTP-status failures land as {@code NON_2XX}; IOExceptions land as
   * {@code NETWORK}; everything else lands as {@code PARSE}.
   */
  private JWKSFetchException classifyFailure(Exception e) {
    if (unwrapHTTP(e) != null) {
      return new JWKSFetchException(JWKSFetchException.Reason.NON_2XX,
          "JWKS refresh failed: non-2xx HTTP response", e);
    }
    Throwable t = e;
    while (t != null) {
      if (t instanceof IOException) {
        return new JWKSFetchException(JWKSFetchException.Reason.NETWORK,
            "JWKS refresh failed: network error", e);
      }
      t = t.getCause();
    }
    return new JWKSFetchException(JWKSFetchException.Reason.PARSE,
        "JWKS refresh failed: parse error", e);
  }

  /**
   * Performs the refresh: fetch JWKS, build verifiers, install a Snapshot.
   * Throws {@link JWKSFetchException} for the empty-result case so the
   * worker can complete the future exceptionally; other failures from
   * {@code fetch()} propagate directly and are classified by the worker.
   */
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
        if (reject.reason() == InvalidJWKException.Reason.MISSING_KID) {
          // Kidless JWKs land in allKeys (visible via keys()) but cannot be resolved by kid.
          allKeys.add(jwk);
        } else {
          if (reject.reason() == InvalidJWKException.Reason.ALG_CRV_MISMATCH) {
            if (logger.isWarnEnabled()) {
              logger.warn("JWK rejected [" + reject.reason() + "]: " + reject.getMessage());
            }
          } else if (logger.isDebugEnabled()) {
            logger.debug("JWK rejected [" + reject.reason() + "]: " + reject.getMessage());
          }
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

  /**
   * Build a failure-path {@link Snapshot}: carry forward the prior verifier
   * map, increment {@code consecutiveFailures}, and compute {@code nextDueAt}
   * as {@code now + backoff(...)}, extended to honor a {@code Retry-After}
   * header when present and stricter than the backoff.
   */
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

  private JWKSResponse fetch() {
    return switch (source) {
      case ISSUER     -> JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer(url, httpConnectionCustomizer);
      case WELL_KNOWN -> JSONWebKeySetHelper.retrieveJWKSResponseFromWellKnownConfiguration(url, httpConnectionCustomizer);
      case JWKS       -> JSONWebKeySetHelper.retrieveJWKSResponseFromJWKS(url, httpConnectionCustomizer);
    };
  }

  private void onTick() {
    if (closed) return;
    Snapshot s = ref.get();
    Instant now = Instant.now(clock);
    if (now.isBefore(s.nextDueAt())) return;
    // Fire-and-forget: singleflightRefresh dispatches on a virtual thread; we do not await.
    singleflightRefresh();
  }

  /**
   * Returns the in-flight refresh future, dispatching a new one on a virtual
   * thread if no refresh is currently active. Order on completion: snapshot
   * updated first, then awaiters notified, then slot cleared.
   *
   * <p>If the refresh fails, the future completes exceptionally with a
   * {@link JWKSFetchException} carrying the categorical reason. The
   * operator-driven {@link #refresh()} surfaces it; the on-miss path
   * swallows the exception.</p>
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
        } catch (JWKSFetchException re) {
          failureCause = re;
          if (logger.isErrorEnabled()) {
            logger.error("JWKS refresh failed [" + re.reason() + "]", re);
          }
          fresh = failureSnapshot(prev, Instant.now(clock), re);
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

    return mine;
  }

  // --- Inner types ---

  public static final class Builder {
    private CacheControlPolicy cacheControlPolicy = CacheControlPolicy.CLAMP;
    private final OpenIDConnectConfiguration cfg;
    private Clock clock = Clock.systemUTC();
    private boolean failFast = false;
    private FetchLimits fetchLimits = FetchLimits.defaults();
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
      this(source, url, null);
    }

    Builder(FetchSource source, String url, OpenIDConnectConfiguration cfg) {
      this.source = source;
      this.url = url;
      this.cfg = cfg;
    }

    public JWKS build() {
      if (cfg != null) {
        if (cfg.jwksURI() == null || cfg.jwksURI().isEmpty()) {
          throw new IllegalArgumentException("Cannot build a JWKS from a configuration with a null or empty jwksURI");
        }
      }
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
      return new JWKS(this);
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

    String url() { return url; }
  }

  /**
   * Result of parsing a {@code Cache-Control} header. Distinguishes
   * "no max-age directive of interest" ({@code maxAge==null && !noStore && !malformed})
   * from "directive(s) present" and "header was malformed".
   */
  record CacheControlDirectives(Long maxAge, boolean noStore, boolean malformed) {}

  enum FetchSource { ISSUER, JWKS, WELL_KNOWN }

  /** Immutable cache snapshot. */
  record Snapshot(
      List<JSONWebKey> allKeys,
      Map<String, Verifier> byKid,
      Map<String, JSONWebKey> jwkByKid,
      Instant fetchedAt,
      Instant nextDueAt,
      int consecutiveFailures,
      Instant lastFailedRefresh) {}
}
