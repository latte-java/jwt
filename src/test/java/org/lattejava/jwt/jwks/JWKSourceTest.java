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

import org.lattejava.jwt.BaseTest;
import org.lattejava.jwt.ExpectedResponse;
import org.testng.annotations.Test;

import java.time.Duration;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class JWKSourceTest extends BaseTest {
  private static final int PORT = 4244;

  private static final String RSA_JWKS_BODY = "{\"keys\":[{"
      + "\"kty\":\"RSA\","
      + "\"kid\":\"k1\","
      + "\"alg\":\"RS256\","
      + "\"use\":\"sig\","
      + "\"n\":\"sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw\","
      + "\"e\":\"AQAB\""
      + "}]}";

  @Test
  public void builder_rejects_nonPositive_refreshInterval() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKSource.fromJWKS("http://localhost:9999/jwks.json")
            .refreshInterval(Duration.ZERO)
            .build());
  }

  @Test
  public void builder_rejects_nonPositive_minRefreshInterval() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKSource.fromJWKS("http://localhost:9999/jwks.json")
            .minRefreshInterval(Duration.ofSeconds(-1))
            .build());
  }

  @Test
  public void builder_rejects_refreshInterval_below_minRefreshInterval() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKSource.fromJWKS("http://localhost:9999/jwks.json")
            .minRefreshInterval(Duration.ofMinutes(5))
            .refreshInterval(Duration.ofSeconds(30))
            .build());
  }

  @Test
  public void builder_rejects_nonPositive_refreshTimeout() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKSource.fromJWKS("http://localhost:9999/jwks.json")
            .refreshTimeout(Duration.ZERO)
            .build());
  }

  @Test
  public void builder_rejects_null_or_empty_URL() {
    assertThrows(IllegalArgumentException.class, () -> JWKSource.fromJWKS("").build());
    assertThrows(NullPointerException.class, () -> JWKSource.fromJWKS(null).build());
  }

  @Test
  public void build_initialLoad_success_populatesSnapshot() throws Exception {
    // Use case: build() performs a synchronous initial JWKS fetch; first resolve()
    // reads from the cache without triggering another fetch.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    assertNotNull(source.lastSuccessfulRefresh());
    assertEquals(source.consecutiveFailures(), 0);
    assertEquals(source.currentKids(), java.util.Set.of("k1"));
    source.close();
  }

  @Test
  public void refreshTimeout_doesNotCountAsFailure() throws Exception {
    // Use case: spec test #25 — refreshTimeout elapsing on the awaiter is not a refresh failure.
    // Handler sleeps 800ms; refreshTimeout=100ms. Awaiter times out, but the in-flight fetch
    // eventually succeeds and updates the snapshot.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.delayMillis = 800)));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .refreshTimeout(Duration.ofMillis(100))
        .build();
    // Initial build's load timed out on the awaiter; consecutiveFailures stays 0
    // because the in-flight fetch is still running.
    assertEquals(source.consecutiveFailures(), 0);

    Thread.sleep(2_000);
    assertNotNull(source.lastSuccessfulRefresh());
    source.close();
  }

  @Test
  public void failure_preservesPriorKeys_andAdvancesObservability() throws Exception {
    // Use case: spec test #19 — refresh fails, prior kids still resolve;
    // lastSuccessfulRefresh does not advance, lastFailedRefresh and consecutiveFailures do.
    org.lattejava.jwt.HttpServerBuilder b = new org.lattejava.jwt.HttpServerBuilder()
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json"));
    startHttpServer(b);

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .minRefreshInterval(Duration.ofMillis(100))
        .refreshInterval(Duration.ofSeconds(60))
        .build();
    java.time.Instant priorSuccess = source.lastSuccessfulRefresh();
    assertNotNull(priorSuccess);
    assertNull(source.lastFailedRefresh());
    assertEquals(source.consecutiveFailures(), 0);

    b.responses.get("/jwks.json").status = 500;
    assertThrows(RuntimeException.class, source::refresh);

    assertEquals(source.lastSuccessfulRefresh(), priorSuccess,
        "lastSuccessfulRefresh must not advance on failure");
    assertNotNull(source.lastFailedRefresh());
    assertEquals(source.consecutiveFailures(), 1);

    assertNotNull(source.resolve(org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS256).kid("k1").build()));
    source.close();
  }

  @Test
  public void close_cancelsScheduler_andResolveReturnsNull() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .scheduledRefresh(true)
        .minRefreshInterval(Duration.ofMillis(100))
        .refreshInterval(Duration.ofMillis(100))
        .build();

    source.close();

    assertNull(source.resolve(org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS256).kid("k1").build()));
    source.refresh();
    source.close();
  }

  @Test
  public void fromIssuer_happyPath() throws Exception {
    // Use case: spec test #1 — fromIssuer composes /.well-known/openid-configuration,
    // reads jwks_uri, and fetches the JWKS.
    String discoveryBody = "{\"jwks_uri\":\"http://localhost:" + PORT + "/jwks.json\"}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/.well-known/openid-configuration")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = discoveryBody)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json"))
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromIssuer("http://localhost:" + PORT).build();
    assertEquals(source.currentKids(), java.util.Set.of("k1"));
    source.close();
  }

  @Test
  public void fromWellKnownConfiguration_nonConventionalURL() throws Exception {
    // Use case: spec test #2 — discovery doc lives at a non-standard path.
    String discoveryBody = "{\"jwks_uri\":\"http://localhost:" + PORT + "/keys\"}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/.custom-discovery")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = discoveryBody)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json"))
        .handleURI("/keys")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromWellKnownConfiguration(
        "http://localhost:" + PORT + "/.custom-discovery").build();
    assertEquals(source.currentKids(), java.util.Set.of("k1"));
    source.close();
  }

  @Test
  public void emptyPostConversionResult_isFailure() throws Exception {
    // Use case: spec test #23 — JWKS publishes only oct keys → no usable verifiers
    // → refresh treated as failure.
    String octOnlyBody = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"alg\":\"HS256\",\"k\":\"AAAA\"}]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = octOnlyBody)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    assertNull(source.lastSuccessfulRefresh());
    assertEquals(source.consecutiveFailures(), 1);
    assertTrue(source.currentKids().isEmpty());
    assertThrows(RuntimeException.class, source::refresh);
    source.close();
  }

  static final class RecordingLogger implements org.lattejava.jwt.log.Logger {
    final java.util.List<String> events = new java.util.concurrent.CopyOnWriteArrayList<>();

    private void record(org.lattejava.jwt.log.Level level, String message, Throwable t) {
      events.add(level + " " + message + (t == null ? "" : " :: " + t.getClass().getSimpleName()));
    }
    @Override public void trace(String m) { record(org.lattejava.jwt.log.Level.Trace, m, null); }
    @Override public void trace(String m, Object... v) { record(org.lattejava.jwt.log.Level.Trace, m, null); }
    @Override public void debug(String m) { record(org.lattejava.jwt.log.Level.Debug, m, null); }
    @Override public void debug(String m, Object... v) { record(org.lattejava.jwt.log.Level.Debug, m, null); }
    @Override public void debug(String m, Throwable t) { record(org.lattejava.jwt.log.Level.Debug, m, t); }
    @Override public void info(String m) { record(org.lattejava.jwt.log.Level.Info, m, null); }
    @Override public void info(String m, Object... v) { record(org.lattejava.jwt.log.Level.Info, m, null); }
    @Override public void warn(String m) { record(org.lattejava.jwt.log.Level.Warn, m, null); }
    @Override public void warn(String m, Object... v) { record(org.lattejava.jwt.log.Level.Warn, m, null); }
    @Override public void warn(String m, Throwable t) { record(org.lattejava.jwt.log.Level.Warn, m, t); }
    @Override public void error(String m) { record(org.lattejava.jwt.log.Level.Error, m, null); }
    @Override public void error(String m, Throwable t) { record(org.lattejava.jwt.log.Level.Error, m, t); }
    @Override public boolean isTraceEnabled() { return true; }
    @Override public boolean isDebugEnabled() { return true; }
    @Override public boolean isInfoEnabled() { return true; }
    @Override public boolean isWarnEnabled() { return true; }
    @Override public boolean isErrorEnabled() { return true; }
    @Override public void setLevel(org.lattejava.jwt.log.Level level) {}
  }

  @Test
  public void logger_emits_refreshSuccess_at_info() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    RecordingLogger logger = new RecordingLogger();
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .logger(logger)
        .build();
    assertTrue(logger.events.stream().anyMatch(e ->
        e.startsWith("Info ") && e.contains("JWKS refresh succeeded")));
    source.close();
  }

  @Test
  public void logger_emits_refreshFailure_at_error_with_throwable() {
    RecordingLogger logger = new RecordingLogger();
    JWKSource source = JWKSource.fromJWKS("http://127.0.0.1:1/jwks.json")
        .refreshTimeout(Duration.ofMillis(500))
        .logger(logger)
        .build();
    assertTrue(logger.events.stream().anyMatch(e -> e.startsWith("Error ")),
        "expected an Error-level event, got: " + logger.events);
    source.close();
  }

  @Test
  public void logger_emits_duplicateKid_at_warn() throws Exception {
    String dupBody = "{\"keys\":[" +
        "{\"kty\":\"RSA\",\"kid\":\"k1\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw\",\"e\":\"AQAB\"}," +
        "{\"kty\":\"RSA\",\"kid\":\"k1\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw\",\"e\":\"AQAB\"}" +
        "]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = dupBody)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    RecordingLogger logger = new RecordingLogger();
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .logger(logger)
        .build();
    assertTrue(logger.events.stream().anyMatch(e ->
        e.startsWith("Warn ") && e.contains("duplicate kid")), logger.events.toString());
    source.close();
  }

  @Test
  public void logger_emits_retryAfterHonored_at_info() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = "{}")
            .with(r -> r.status = 429)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Retry-After", "600"))));
    RecordingLogger logger = new RecordingLogger();
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .logger(logger)
        .build();
    assertTrue(logger.events.stream().anyMatch(e ->
        e.startsWith("Info ") && e.contains("Retry-After honored")), logger.events.toString());
    source.close();
  }

  @Test
  public void scheduledRefresh_fires_atTickBoundary() throws Exception {
    // Use case: with scheduledRefresh=true and a 200ms tick rate, the scheduler
    // dispatches a refresh on its own. Real wall-clock time.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .scheduledRefresh(true)
        .minRefreshInterval(Duration.ofMillis(200))
        .refreshInterval(Duration.ofMillis(200))
        .build();
    int callsAfterBuild = httpHandlers.get(httpHandlers.size() - 1).called;
    Thread.sleep(700);
    assertTrue(httpHandlers.get(httpHandlers.size() - 1).called > callsAfterBuild);
    source.close();
  }

  @Test
  public void refresh_succeeds_updatesSnapshot() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    int before = httpHandlers.get(httpHandlers.size() - 1).called;
    source.refresh();
    assertTrue(httpHandlers.get(httpHandlers.size() - 1).called > before);
    source.close();
  }

  @Test
  public void refresh_throwsOnFailure() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();

    httpServers.get(httpServers.size() - 1).stop(0);
    assertThrows(RuntimeException.class, source::refresh);
    assertEquals(source.consecutiveFailures(), 1);
    source.close();
  }

  @Test
  public void retryAfter_extendsNextDueAt_aboveBackoff() throws Exception {
    // Use case: 429 with Retry-After: 600s extends nextDueAt past the 30s backoff.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = "{\"error\":\"throttled\"}")
            .with(r -> r.status = 429)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Retry-After", "600"))));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .build();
    assertEquals(source.consecutiveFailures(), 1);
    assertTrue(!source.nextDueAt().isBefore(fixedNow.plusSeconds(600)));
    source.close();
  }

  @Test
  public void retryAfter_belowBackoff_doesNotShrinkNextDueAt() throws Exception {
    // Use case: 429 with Retry-After: 1s does not pull nextDueAt below the 30s backoff floor.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = "{}")
            .with(r -> r.status = 429)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Retry-After", "1"))));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .minRefreshInterval(Duration.ofSeconds(30))
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plusSeconds(30));
    source.close();
  }

  @Test
  public void backoffSequence_30s_to_60m_capped() {
    // Use case: spec §2.7.2 backoff formula in long ms; sequence with default settings.
    Duration min = Duration.ofSeconds(30);
    Duration max = Duration.ofMinutes(60);
    long[] expectedSeconds = {30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600};
    for (int i = 0; i < expectedSeconds.length; i++) {
      Duration actual = JWKSource.backoff(i + 1, min, max);
      assertEquals(actual.getSeconds(), expectedSeconds[i],
          "consecutiveFailures=" + (i + 1));
    }
  }

  @Test
  public void cacheControl_CLAMP_maxAgeWithinBounds_honored() throws Exception {
    // Use case: max-age=300 sits within [30s, 60m] — chosenInterval = 300s.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Cache-Control", "public, max-age=300"))));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plusSeconds(300));
    source.close();
  }

  @Test
  public void cacheControl_CLAMP_maxAgeBelowMin_clampedToFloor() throws Exception {
    // Use case: max-age=10 is below minRefreshInterval (30s) — clamp to 30s.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Cache-Control", "max-age=10"))));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plusSeconds(30));
    source.close();
  }

  @Test
  public void cacheControl_IGNORE_alwaysUsesRefreshInterval() throws Exception {
    // Use case: server's max-age is ignored; chosenInterval = refreshInterval.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Cache-Control", "max-age=300"))));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .refreshInterval(Duration.ofMinutes(15))
        .cacheControlPolicy(CacheControlPolicy.IGNORE)
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plusSeconds(15 * 60));
    source.close();
  }

  @Test
  public void cacheControl_malformed_treatedAsAbsent() throws Exception {
    // Use case: max-age=abc is unparseable → behave as if no Cache-Control set.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.headers = java.util.Map.of("Cache-Control", "max-age=abc"))));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .refreshInterval(Duration.ofMinutes(15))
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plusSeconds(15 * 60));
    source.close();
  }

  @Test
  public void successfulRefresh_setsNextDueAt_atLeastMinRefreshIntervalFromNow() throws Exception {
    // Use case: even when refreshInterval > minRefreshInterval, nextDueAt = now + refreshInterval.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .refreshInterval(Duration.ofMinutes(15))
        .minRefreshInterval(Duration.ofSeconds(30))
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plus(Duration.ofMinutes(15)));
    source.close();
  }

  @Test
  public void resolve_cacheHit_returnsVerifier() throws Exception {
    // Use case: kid in the snapshot resolves to a verifier without a network hop.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    org.lattejava.jwt.Header h = org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS256).kid("k1").build();
    org.lattejava.jwt.Verifier v = source.resolve(h);
    assertNotNull(v);
    assertTrue(v.canVerify(org.lattejava.jwt.Algorithm.RS256));
    source.close();
  }

  @Test
  public void resolve_canVerifyMismatch_returnsNull() throws Exception {
    // Use case: header alg disagrees with the resolved verifier's bound alg → null.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    org.lattejava.jwt.Header h = org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS512).kid("k1").build();
    assertNull(source.resolve(h));
    source.close();
  }

  @Test
  public void resolve_unknownKid_refreshOnMissFalse_returnsNullWithoutFetch() throws Exception {
    // Use case: refreshOnMiss=false makes the on-miss path return null immediately.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .refreshOnMiss(false)
        .build();
    int callsBefore = httpHandlers.get(httpHandlers.size() - 1).called;
    org.lattejava.jwt.Header h = org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS256).kid("unknown").build();
    assertNull(source.resolve(h));
    assertEquals(httpHandlers.get(httpHandlers.size() - 1).called, callsBefore);
    source.close();
  }

  @Test
  public void resolve_unknownKid_refreshOnMissTrue_singleflight_oneFetch_for_concurrent_calls() throws Exception {
    // Use case: 100 concurrent unknown-kid resolves past nextDueAt coalesce into a single fetch.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .minRefreshInterval(Duration.ofMillis(200))
        .refreshInterval(Duration.ofMillis(200))
        .build();
    int callsAfterBuild = httpHandlers.get(httpHandlers.size() - 1).called;
    Thread.sleep(250);  // pass nextDueAt window

    java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();
    java.util.List<java.util.concurrent.Future<org.lattejava.jwt.Verifier>> futures = new java.util.ArrayList<>();
    for (int i = 0; i < 100; i++) {
      futures.add(pool.submit(() -> source.resolve(org.lattejava.jwt.Header.builder()
          .alg(org.lattejava.jwt.Algorithm.RS256).kid("unknown").build())));
    }
    for (var f : futures) f.get();
    pool.shutdown();
    assertEquals(httpHandlers.get(httpHandlers.size() - 1).called, callsAfterBuild + 1);
    source.close();
  }

  @Test
  public void resolve_unknownKid_inside_minRefreshInterval_returnsNullWithoutFetch() throws Exception {
    // Use case: §2.2 step 5 — within nextDueAt's window, second miss does not refetch.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    java.time.Instant fixedNow = java.time.Instant.parse("2026-04-25T12:00:00Z");
    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .minRefreshInterval(Duration.ofMinutes(5))
        .refreshInterval(Duration.ofMinutes(60))
        .build();
    int callsAfterBuild = httpHandlers.get(httpHandlers.size() - 1).called;
    for (int i = 0; i < 10; i++) {
      assertNull(source.resolve(org.lattejava.jwt.Header.builder()
          .alg(org.lattejava.jwt.Algorithm.RS256).kid("unknown").build()));
    }
    assertEquals(httpHandlers.get(httpHandlers.size() - 1).called, callsAfterBuild);
    source.close();
  }

  @Test
  public void resolve_onMissRefresh_findsNewlyAddedKid() throws Exception {
    // Use case: rotation — a fresh kid not in the cache triggers a fetch and resolves.
    String body1 = RSA_JWKS_BODY;
    String body2 = body1.replace("\"kid\":\"k1\"", "\"kid\":\"k2\"");
    org.lattejava.jwt.HttpServerBuilder b = new org.lattejava.jwt.HttpServerBuilder()
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body1)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json"));
    startHttpServer(b);

    JWKSource source = JWKSource.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .minRefreshInterval(Duration.ofMillis(100))
        .refreshInterval(Duration.ofMillis(100))
        .build();
    assertEquals(source.currentKids(), java.util.Set.of("k1"));

    b.responses.get("/jwks.json").response = body2;
    Thread.sleep(150);  // pass nextDueAt window

    org.lattejava.jwt.Verifier v = source.resolve(org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS256).kid("k2").build());
    assertNotNull(v);
    source.close();
  }

  @Test
  public void build_initialLoad_failure_leavesSourceUsable() {
    // Use case: build() returns normally on a network failure; source has empty
    // cache, consecutiveFailures=1, lastSuccessfulRefresh()==null.
    JWKSource source = JWKSource.fromJWKS("http://127.0.0.1:1/jwks.json")
        .refreshTimeout(Duration.ofMillis(500))
        .build();
    assertNull(source.lastSuccessfulRefresh());
    assertEquals(source.consecutiveFailures(), 1);
    assertTrue(source.currentKids().isEmpty());
    source.close();
  }
}
