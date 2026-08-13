/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.jwks;

import java.io.*;
import java.net.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.internal.*;
import org.lattejava.jwt.internal.http.*;
import org.lattejava.jwt.log.*;

/**
 * A self-refreshing {@link VerifierResolver} backed by a remote JWKS endpoint.
 *
 * <p>The URL scheme is not enforced, so that {@code http} remains usable against a local test server. While not
 * enforced, please use {@code https} in production: the fetched keys determine which tokens are trusted, and over
 * {@code http} they can be substituted in transit.</p>
 */
public final class JWKS implements VerifierResolver, AutoCloseable {
  private final CacheControlPolicy cacheControlPolicy;
  private final Clock clock;
  private final boolean failFast;
  private final FetchLimits fetchLimits;
  private final Consumer<HttpURLConnection> httpConnectionCustomizer;
  private final AtomicReference<CompletableFuture<Snapshot>> inflight = new AtomicReference<>();
  private final Logger logger;
  private final Duration maxStaleness;
  private final Duration minRefreshInterval;
  private final AtomicReference<Snapshot> ref = new AtomicReference<>();
  private final Duration refreshInterval;
  private final boolean refreshOnMiss;
  private final Duration refreshTimeout;
  private final boolean scheduledRefresh;
  private final ScheduledExecutorService scheduler;
  private final FetchSource source;
  private final boolean staticMode;
  private final String url;
  volatile String lockedJWKSURI = null;
  private volatile boolean closed;
  private volatile Throwable initialFetchFailure;
  private volatile Thread refreshThread;

  private JWKS(Builder b) {
    this.cacheControlPolicy = b.cacheControlPolicy;
    this.clock = b.clock;
    this.failFast = b.failFast;
    this.fetchLimits = b.fetchLimits;
    this.httpConnectionCustomizer = b.httpConnectionCustomizer;
    this.logger = b.logger;
    this.maxStaleness = b.maxStaleness;
    this.minRefreshInterval = b.minRefreshInterval;
    this.refreshInterval = b.refreshInterval;
    this.refreshOnMiss = b.refreshOnMiss;
    this.refreshTimeout = b.refreshTimeout;
    this.scheduledRefresh = b.scheduledRefresh;
    this.source = b.source;
    this.staticMode = false;
    this.url = b.url();
    this.ref.set(new Snapshot(List.of(), Map.of(), Map.of(), Instant.EPOCH, Instant.EPOCH, 0, null, Instant.EPOCH));
    CompletableFuture<Snapshot> initial = singleflightRefresh();
    try {
      initial.get(refreshTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException ignored) {
      // empty snapshot stays; the worker continues asynchronously
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException ee) {
      // closed is necessarily false during construction, so the worker's
      // !closed guard always passes here and the failure snapshot is in ref
      Throwable c = ee.getCause();
      this.initialFetchFailure = (c != null) ? c : ee;
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
    this.maxStaleness = null;
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
        null,
        Instant.EPOCH));
  }

  // --- Public static methods ---

  /**
   * Performs a one-shot fetch of the JWKS at {@code jwksURL} and returns the parsed keys. Uses
   * {@link FetchLimits#defaults()} for all hardening limits.
   *
   * @param jwksURL the JWKS endpoint URL
   * @return the list of parsed {@link JSONWebKey} objects
   * @throws JWKSFetchException if the fetch or parse fails
   */
  public static List<JSONWebKey> fetch(String jwksURL) {
    return fetch(jwksURL, FetchLimits.defaults(), null);
  }

  /**
   * Performs a one-shot fetch of the JWKS at {@code jwksURL}, applying {@code customizer} to the connection before the
   * request is sent.
   *
   * @param jwksURL    the JWKS endpoint URL
   * @param customizer an optional consumer to configure the connection (e.g., set request headers)
   * @return the list of parsed {@link JSONWebKey} objects
   * @throws JWKSFetchException if the fetch or parse fails
   */
  public static List<JSONWebKey> fetch(String jwksURL, Consumer<HttpURLConnection> customizer) {
    return fetch(jwksURL, FetchLimits.defaults(), customizer);
  }

  /**
   * Performs a one-shot fetch of the JWKS at {@code jwksURL} with the supplied hardening limits.
   *
   * @param jwksURL the JWKS endpoint URL
   * @param limits  the hardening limits to apply
   * @return the list of parsed {@link JSONWebKey} objects
   * @throws JWKSFetchException if the fetch or parse fails
   */
  public static List<JSONWebKey> fetch(String jwksURL, FetchLimits limits) {
    return fetch(jwksURL, limits, null);
  }

  /**
   * Performs a one-shot fetch of the JWKS at {@code jwksURL} with the supplied hardening limits and connection
   * customizer.
   *
   * @param jwksURL    the JWKS endpoint URL
   * @param limits     the hardening limits to apply
   * @param customizer an optional consumer to configure the connection before sending
   * @return the list of parsed {@link JSONWebKey} objects
   * @throws JWKSFetchException if the fetch or parse fails
   */
  public static List<JSONWebKey> fetch(String jwksURL, FetchLimits limits, Consumer<HttpURLConnection> customizer) {
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
          JWKS::classifyFetchFailure);
    } catch (JWKSFetchException e) {
      throw e;
    } catch (RuntimeException e) {
      throw classifyFetchFailure("JWKS fetch failed", e);
    }
  }

  /**
   * Builds from a discovery document that has already been fetched, using its {@code jwks_uri}.
   *
   * @param cfg the previously fetched provider configuration.
   */
  public static Builder fromConfiguration(OpenIDConnectConfiguration cfg) {
    Objects.requireNonNull(cfg, "cfg");
    return new Builder(FetchSource.JWKS, cfg.jwksURI(), cfg);
  }

  /**
   * Builds from an OIDC issuer, discovering the JWKS URL from the issuer's {@code /.well-known/openid-configuration}.
   *
   * @param issuer the OIDC issuer URL
   */
  public static Builder fromIssuer(String issuer) {
    return new Builder(FetchSource.ISSUER, issuer);
  }

  /**
   * Builds from a JWKS endpoint directly, skipping discovery.
   *
   * @param jwksURL the JWKS endpoint URL
   */
  public static Builder fromJWKS(String jwksURL) {
    return new Builder(FetchSource.JWKS, jwksURL);
  }

  /**
   * Builds from a fully-qualified discovery URL, taking the JWKS URL from the document it returns.
   *
   * @param wellKnownURL the discovery document URL
   */
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
   * Exponential backoff, computed in long ms to avoid integer overflow at high consecutive-failure counts. Returns
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
   * Parse a {@code Cache-Control} header value into {@link CacheControlDirectives}. Distinguishes "header present but
   * no max-age directive" (e.g. {@code Cache-Control: public}) from "header is malformed" (e.g. {@code max-age=abc},
   * conflicting {@code max-age}).
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
   * Parse a {@code Retry-After} header value (RFC 9110 §10.2.3). Supports the delta-seconds form and the HTTP-date (RFC
   * 1123) form. Returns {@code null} if neither parse succeeds.
   *
   * @param value the header value
   * @param now   the reference instant for HTTP-date deltas (the source's {@link Clock})
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

  private static List<JSONWebKey> parseJWKSResponseKeys(HttpURLConnection conn, InputStream is, FetchLimits limits) {
    Map<String, Object> map = HardenedJSON.parse(is, limits);
    Object keys = map.get("keys");
    if (!(keys instanceof List<?> keyList)) {
      throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
          "JWKS endpoint [" + MessageSanitizer.forMessage(conn.getURL().toString()) + "] response is missing the [keys] array");
    }
    List<JSONWebKey> result = new ArrayList<>();
    for (Object element : keyList) {
      if (!(element instanceof Map<?, ?> elementMap)) {
        throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
            "JWKS endpoint [" + MessageSanitizer.forMessage(conn.getURL().toString()) + "] response contains a non-object element in [keys]");
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> typed = (Map<String, Object>) elementMap;
      result.add(JSONWebKey.fromMap(typed));
    }
    return result;
  }

  /**
   * Render key IDs for a log message. Each is passed through {@link MessageSanitizer} because the values are supplied
   * by the remote JWKS.
   */
  private static String sanitizedKids(Set<String> kids) {
    StringJoiner joiner = new StringJoiner(", ");
    for (String kid : kids) {
      joiner.add(MessageSanitizer.forMessage(kid));
    }
    return joiner.toString();
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

  public Instant lastRefreshAttempt() {
    if (staticMode) return null;
    Snapshot s = ref.get();
    return s.lastAttemptAt().equals(Instant.EPOCH) ? null : s.lastAttemptAt();
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
   * Synchronous, blocking, singleflight-coalesced refresh. Throws a {@link JWKSFetchException} on failure, with a
   * categorical {@link JWKSFetchException#reason()} so callers can dispatch programmatically without unwrapping the
   * cause chain.
   *
   * <p>While discovery has not yet succeeded, this method re-attempts discovery and may throw
   * {@link OpenIDConnectException}. After the JWKS URL has been locked from the first successful discovery, only
   * {@link JWKSFetchException} is thrown. Both extend {@link RuntimeException}, so callers catching the parent are
   * unaffected.</p>
   *
   * @throws JWKSFetchException     if the JWKS fetch or parse fails, or times out
   * @throws OpenIDConnectException if discovery has not yet succeeded and the discovery attempt fails
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
      if (c instanceof OpenIDConnectException oe) throw oe;
      throw new JWKSFetchException(JWKSFetchException.Reason.PARSE,
          "JWKS refresh failed", c != null ? c : ee);
    }
  }

  /**
   * Resolves the {@link Verifier} for the token's {@code kid}.
   *
   * <p>Past {@code maxStaleness} a {@code kid} hit is not returned directly: a refresh is attempted, and the resolve
   * returns {@code null} unless it succeeds. {@link #keys()} and {@link #get(String)} report cache state as-is and are
   * not subject to the bound.</p>
   */
  @Override
  public Verifier resolve(Header header) {
    Objects.requireNonNull(header, "header");
    if (closed) return null;
    String kid = header.kid();
    if (kid == null) return null;

    Instant now = Instant.now(clock);
    Snapshot snapshot = ref.get();
    boolean stale = isStale(snapshot, now);
    Verifier v = snapshot.byKid().get(kid);
    if (v != null && !stale) {
      return v.canVerify(header.alg()) ? v : null;
    }

    // Stale keys always warrant a refresh attempt; a plain kid miss only does so when refreshOnMiss is enabled.
    if (!stale && !refreshOnMiss) return null;
    if (now.isBefore(snapshot.lastAttemptAt().plus(minRefreshInterval))) return null;

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
    if (isStale(fresh, Instant.now(clock))) return null;
    Verifier v2 = fresh.byKid().get(kid);
    if (v2 == null) return null;
    return v2.canVerify(header.alg()) ? v2 : null;
  }

  // --- Private instance methods ---

  /**
   * Returns the {@link Duration} to use for {@code nextDueAt}. Honors the server's {@code Cache-Control: max-age} when
   * {@link CacheControlPolicy#CLAMP} is configured, clamped into {@code [minRefreshInterval, refreshInterval]}.
   */
  private Duration chosenInterval(JWKSResponse resp) {
    if (cacheControlPolicy == CacheControlPolicy.IGNORE) return refreshInterval;
    String cc = resp.selectedHeaders().get("Cache-Control");
    if (cc == null) return refreshInterval;

    CacheControlDirectives d = parseCacheControl(cc);
    if (d.malformed()) {
      if (logger.isWarnEnabled()) {
        logger.warn("Malformed Cache-Control header [" + MessageSanitizer.forMessage(cc) + "]; treating as absent");
      }
      return refreshInterval;
    }
    if (d.noStore()) {
      // no-store is clamped to the minRefreshInterval floor (same treatment as max-age=0 below).
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
   * Classify a non-{@link JWKSFetchException} failure into a refresh reason. HTTP-status failures land as
   * {@code NON_2XX}; IOExceptions land as {@code NETWORK}; everything else lands as {@code PARSE}.
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
   * Performs the refresh: fetch JWKS, build verifiers, install a Snapshot. Throws {@link JWKSFetchException} for the
   * empty-result case so the worker can complete the future exceptionally; other failures from {@code fetch()}
   * propagate directly and are classified by the worker.
   */
  private Snapshot doRefreshOrThrow(Snapshot prev) {
    Instant now = Instant.now(clock);
    JWKSResponse resp = fetchFromSource();
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
          logger.warn("JWKS contains duplicate kid [" + MessageSanitizer.forMessage(kid) + "]; first-write-wins");
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
    Instant nextDue = now.plus(chosenInterval(resp));
    if (logger.isInfoEnabled()) {
      logger.info("JWKS refresh succeeded; kids=[" + sanitizedKids(byKid.keySet()) + "]");
    }
    List<JSONWebKey> allKeysSnapshot = Collections.unmodifiableList(new ArrayList<>(allKeys));
    Map<String, Verifier> byKidSnapshot = Collections.unmodifiableMap(new LinkedHashMap<>(byKid));
    Map<String, JSONWebKey> jwkByKidSnapshot = Collections.unmodifiableMap(new LinkedHashMap<>(jwkByKid));
    return new Snapshot(allKeysSnapshot, byKidSnapshot, jwkByKidSnapshot, now, nextDue, 0, null, now);
  }

  /**
   * Build a failure-path {@link Snapshot}: carry forward the prior verifier map, increment {@code consecutiveFailures},
   * and compute {@code nextDueAt} as {@code now + backoff(...)}, extended to honor a {@code Retry-After} header when
   * present and stricter than the backoff.
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
          logger.debug("Retry-After header [" + MessageSanitizer.forMessage(ra) + "] could not be parsed; falling back to backoff");
        }
      }
    }
    return new Snapshot(allKeys, byKid, jwkByKid, fetchedAt, nextDue, next, now, now);
  }

  private JWKSResponse fetchFromSource() {
    String effectiveURL;
    if (lockedJWKSURI != null) {
      effectiveURL = lockedJWKSURI;
    } else {
      effectiveURL = switch (source) {
        case ISSUER -> resolveJWKSURIFromIssuer(url);
        case WELL_KNOWN -> resolveJWKSURIFromWellKnown(url);
        case JWKS -> url;
      };
    }
    JWKSResponse response = fetchJWKSDirect(effectiveURL);
    // First successful JWKS fetch on a discovery-derived path -> lock the URL.
    if (lockedJWKSURI == null && source != FetchSource.JWKS) {
      lockedJWKSURI = effectiveURL;
    }
    return response;
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
          try {
            status = conn.getResponseCode();
          } catch (IOException ignored) {
          }
          Map<String, String> sel = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
          for (String name : new String[]{"Cache-Control", "Retry-After"}) {
            String v = conn.getHeaderField(name);
            if (v != null) sel.put(name, v);
          }
          return new JWKSResponse(keys, status, sel);
        },
        JWKS::classifyFetchFailure);
  }

  /**
   * Whether {@code snapshot}'s keys are older than {@code maxStaleness}. False when no bound is configured, and when
   * no fetch has succeeded yet ({@code fetchedAt} is the epoch), since that snapshot holds no keys to serve.
   */
  private boolean isStale(Snapshot snapshot, Instant now) {
    if (maxStaleness == null) return false;
    Instant fetchedAt = snapshot.fetchedAt();
    if (fetchedAt.equals(Instant.EPOCH)) return false;
    return now.isAfter(fetchedAt.plus(maxStaleness));
  }

  private void onTick() {
    if (closed) return;
    Snapshot s = ref.get();
    Instant now = Instant.now(clock);
    if (now.isBefore(s.nextDueAt())) return;
    // Fire-and-forget: singleflightRefresh dispatches on a virtual thread; we do not await.
    singleflightRefresh();
  }

  private String resolveJWKSURIFromIssuer(String issuer) {
    OpenIDConnectConfiguration cfg = OpenIDConnect.discover(issuer, fetchLimits, httpConnectionCustomizer);
    return cfg.jwksURI();
  }

  private String resolveJWKSURIFromWellKnown(String wellKnownURL) {
    OpenIDConnectConfiguration cfg = OpenIDConnect.discoverFromWellKnown(wellKnownURL, fetchLimits, httpConnectionCustomizer);
    return cfg.jwksURI();
  }

  /**
   * Returns the in-flight refresh future, dispatching a new one on a virtual thread if no refresh is currently active.
   * Order on completion: snapshot updated first, then awaiters notified, then slot cleared.
   *
   * <p>If the refresh fails, the future completes exceptionally with a
   * {@link JWKSFetchException} carrying the categorical reason. The operator-driven {@link #refresh()} surfaces it; the
   * on-miss path swallows the exception.</p>
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
          initialFetchFailure = null;
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

  enum FetchSource {ISSUER, JWKS, WELL_KNOWN}

  public static final class Builder {
    private final OpenIDConnectConfiguration cfg;
    private final FetchSource source;
    private final String url;
    private CacheControlPolicy cacheControlPolicy = CacheControlPolicy.CLAMP;
    private Clock clock = Clock.systemUTC();
    private boolean failFast = false;
    private FetchLimits fetchLimits = FetchLimits.defaults();
    private Consumer<HttpURLConnection> httpConnectionCustomizer;
    private Logger logger = NoOpLogger.INSTANCE;
    private Duration maxStaleness;
    private Duration minRefreshInterval = Duration.ofSeconds(30);
    private Duration refreshInterval = Duration.ofMinutes(60);
    private boolean refreshOnMiss = true;
    private Duration refreshTimeout = Duration.ofSeconds(2);
    private boolean scheduledRefresh = false;

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
      if (maxStaleness != null) {
        if (maxStaleness.isZero() || maxStaleness.isNegative()) {
          throw new IllegalArgumentException("maxStaleness must be > 0 but found [" + maxStaleness + "]");
        }
        // A bound tighter than the refresh cadence would mark keys stale before the scheduled refresh could renew
        // them, turning every resolve into a blocking fetch.
        if (maxStaleness.compareTo(refreshInterval) < 0) {
          throw new IllegalArgumentException(
              "maxStaleness [" + maxStaleness + "] must be >= refreshInterval [" + refreshInterval + "]");
        }
      }
      JWKS jwks = new JWKS(this);
      if (failFast && jwks.initialFetchFailure != null) {
        Throwable f = jwks.initialFetchFailure;
        jwks.close();
        if (f instanceof JWKSFetchException jfe) throw jfe;
        if (f instanceof OpenIDConnectException oce) throw oce;
        throw new JWKSFetchException(JWKSFetchException.Reason.PARSE, "Initial JWKS fetch failed", f);
      }
      return jwks;
    }

    public Builder cacheControlPolicy(CacheControlPolicy p) {
      this.cacheControlPolicy = Objects.requireNonNull(p, "cacheControlPolicy");
      return this;
    }

    public Builder clock(Clock c) {
      this.clock = Objects.requireNonNull(c, "clock");
      return this;
    }

    public Builder failFast(boolean failFast) {
      this.failFast = failFast;
      return this;
    }

    public Builder fetchLimits(FetchLimits limits) {
      this.fetchLimits = Objects.requireNonNull(limits, "fetchLimits");
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

    /**
     * The longest a cached key set may be served after the last successful fetch. Past that bound
     * {@link JWKS#resolve(Header)} stops returning verifiers until a refresh succeeds, bounding how long a key
     * revoked at the provider stays trusted while the endpoint is unreachable.
     *
     * <p>Default: {@code null}, meaning unlimited — keys are retained across an outage of any length. Setting a bound
     * trades availability for key freshness. A bound below {@code refreshInterval} is rejected, since keys would go
     * stale before the scheduled refresh could renew them.</p>
     *
     * @param d the maximum staleness, or {@code null} for unlimited; must be positive and &gt;=
     *          {@code refreshInterval}.
     * @return this builder.
     */
    public Builder maxStaleness(Duration d) {
      this.maxStaleness = d;
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

    String url() {
      return url;
    }
  }

  /**
   * Result of parsing a {@code Cache-Control} header. Distinguishes "no max-age directive of interest"
   * ({@code maxAge==null && !noStore && !malformed}) from "directive(s) present" and "header was malformed".
   */
  record CacheControlDirectives(Long maxAge, boolean noStore, boolean malformed) {
  }

  /**
   * Immutable cache snapshot.
   */
  record Snapshot(
      List<JSONWebKey> allKeys,
      Map<String, Verifier> byKid,
      Map<String, JSONWebKey> jwkByKid,
      Instant fetchedAt,
      Instant nextDueAt,
      int consecutiveFailures,
      Instant lastFailedRefresh,
      Instant lastAttemptAt) {
  }
}
