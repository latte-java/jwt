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
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * A self-refreshing {@link VerifierResolver} backed by a remote JWKS endpoint.
 * See {@code specs/jwks-source.md} for the full specification (rev 3).
 */
public final class JWKSource implements VerifierResolver, AutoCloseable {
  private final AtomicReference<Snapshot> ref = new AtomicReference<>();
  private final CacheControlPolicy cacheControlPolicy;
  private final Clock clock;
  private final Consumer<HttpURLConnection> httpConnectionCustomizer;
  private final Logger logger;
  private final Duration minRefreshInterval;
  private final Duration refreshInterval;
  private final boolean refreshOnMiss;
  private final Duration refreshTimeout;
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
    this.ref.set(doRefresh(null));
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
    // Implemented in Task 11.
    return null;
  }

  public void refresh() {
    // Implemented in Task 17.
    throw new UnsupportedOperationException("not yet implemented");
  }

  @Override
  public void close() {
    // Implemented in Task 19.
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

  private static Duration maxOf(Duration a, Duration b) {
    return a.compareTo(b) >= 0 ? a : b;
  }

  /**
   * Single-threaded refresh used by the constructor. Returns the Snapshot to install.
   * Singleflight wiring is added in Task 13; the constructor calls this directly.
   */
  private Snapshot doRefresh(Snapshot prev) {
    Instant now = Instant.now(clock);
    try {
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
        if (logger.isErrorEnabled()) {
          logger.error("JWKS refresh produced an empty kid map; treating as failure");
        }
        return failureSnapshot(prev, now, new IllegalStateException("Empty kid map after JWK conversion"));
      }
      Duration chosenInterval = refreshInterval;
      Instant nextDue = now.plus(maxOf(minRefreshInterval, chosenInterval));
      if (logger.isInfoEnabled()) {
        logger.info("JWKS refresh succeeded; kids=" + byKid.keySet());
      }
      return new Snapshot(Map.copyOf(byKid), now, nextDue, 0, null);
    } catch (RuntimeException e) {
      if (logger.isErrorEnabled()) {
        logger.error("JWKS refresh failed", e);
      }
      return failureSnapshot(prev, now, e);
    }
  }

  private JWKSResponse fetch() {
    return switch (source) {
      case ISSUER     -> JSONWebKeySetHelper.retrieveJWKSResponseFromIssuer(url, httpConnectionCustomizer);
      case WELL_KNOWN -> JSONWebKeySetHelper.retrieveJWKSResponseFromWellKnownConfiguration(url, httpConnectionCustomizer);
      case JWKS       -> JSONWebKeySetHelper.retrieveJWKSResponseFromJWKS(url, httpConnectionCustomizer);
    };
  }

  /**
   * Failure-path Snapshot. Backoff and Retry-After are applied in Tasks 15/16;
   * for now nextDueAt = now + minRefreshInterval.
   */
  private Snapshot failureSnapshot(Snapshot prev, Instant now, Throwable cause) {
    int prior = (prev == null) ? 0 : prev.consecutiveFailures();
    Map<String, Verifier> byKid = (prev == null) ? Map.of() : prev.byKid();
    Instant fetchedAt = (prev == null) ? Instant.EPOCH : prev.fetchedAt();
    return new Snapshot(byKid, fetchedAt, now.plus(minRefreshInterval), prior + 1, now);
  }

  // --- Internal types ---

  enum FetchSource { ISSUER, JWKS, WELL_KNOWN }

  /** Immutable cache snapshot. See spec §2.1. */
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
