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

import com.sun.net.httpserver.HttpServer;
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.BaseTest;
import org.lattejava.jwt.ExpectedResponse;
import org.lattejava.jwt.FetchLimits;
import org.lattejava.jwt.Header;
import org.lattejava.jwt.KeyType;
import org.lattejava.jwt.OpenIDConnectConfiguration;
import org.lattejava.jwt.OpenIDConnectException;
import org.testng.annotations.Test;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;
import static org.testng.Assert.fail;

public class JWKSTest extends BaseTest {
  private static final int PORT = 4244;

  private static final String RSA_JWKS_BODY = readResource("src/test/resources/jwks/rsa_one_key.json");

  private static final String RSA_JWKS_DUPLICATE_KID_BODY = readResource("src/test/resources/jwks/rsa_duplicate_kid.json");

  private static String readResource(String path) {
    try {
      return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));
    } catch (java.io.IOException e) {
      throw new RuntimeException("Failed to read test resource [" + path + "]", e);
    }
  }

  @Test
  public void builder_rejects_nonPositive_refreshInterval() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKS.fromJWKS("http://localhost:9999/jwks.json")
            .refreshInterval(Duration.ZERO)
            .build());
  }

  @Test
  public void builder_rejects_nonPositive_minRefreshInterval() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKS.fromJWKS("http://localhost:9999/jwks.json")
            .minRefreshInterval(Duration.ofSeconds(-1))
            .build());
  }

  @Test
  public void builder_rejects_refreshInterval_below_minRefreshInterval() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKS.fromJWKS("http://localhost:9999/jwks.json")
            .minRefreshInterval(Duration.ofMinutes(5))
            .refreshInterval(Duration.ofSeconds(30))
            .build());
  }

  @Test
  public void builder_rejects_nonPositive_refreshTimeout() {
    assertThrows(IllegalArgumentException.class,
        () -> JWKS.fromJWKS("http://localhost:9999/jwks.json")
            .refreshTimeout(Duration.ZERO)
            .build());
  }

  @Test
  public void builder_rejects_null_or_empty_URL() {
    assertThrows(IllegalArgumentException.class, () -> JWKS.fromJWKS("").build());
    assertThrows(NullPointerException.class, () -> JWKS.fromJWKS(null).build());
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    assertNotNull(source.lastSuccessfulRefresh());
    assertEquals(source.consecutiveFailures(), 0);
    assertEquals(source.keyIds(), java.util.Set.of("k1"));
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .minRefreshInterval(Duration.ofMillis(100))
        .refreshInterval(Duration.ofSeconds(60))
        .build();
    java.time.Instant priorSuccess = source.lastSuccessfulRefresh();
    assertNotNull(priorSuccess);
    assertNull(source.lastFailedRefresh());
    assertEquals(source.consecutiveFailures(), 0);

    b.responses.get("/jwks.json").status = 500;
    JWKSFetchException ex = expectThrows(JWKSFetchException.class, source::refresh);
    assertEquals(ex.reason(), JWKSFetchException.Reason.NON_2XX);

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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
  public void fromConfiguration_throws_IllegalArgumentException_when_jwks_uri_is_empty() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").jwksURI("").build();
    assertThrows(IllegalArgumentException.class, () -> JWKS.fromConfiguration(cfg).build());
  }

  @Test
  public void fromConfiguration_throws_IllegalArgumentException_when_jwks_uri_is_null() {
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").build();
    assertThrows(IllegalArgumentException.class, () -> JWKS.fromConfiguration(cfg).build());
  }

  @Test
  public void fromConfiguration_with_jwks_uri_builds_remote_backed_jwks() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("ignored")
        .jwksURI("http://localhost:" + PORT + "/jwks.json")
        .build();
    try (JWKS jwks = JWKS.fromConfiguration(cfg).build()) {
      assertNotNull(jwks.get("k1"));
    }
  }

  @Test
  public void fromIssuer_happyPath() throws Exception {
    // Use case: spec test #1 — fromIssuer composes /.well-known/openid-configuration,
    // reads jwks_uri, and fetches the JWKS. The discovery doc must include the issuer
    // field so that OpenIDConnect.discover() issuer-equality validation passes.
    String issuer = "http://localhost:" + PORT;
    String discoveryBody = "{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + issuer + "/jwks.json\"}";
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

    JWKS source = JWKS.fromIssuer(issuer).build();
    assertEquals(source.keyIds(), java.util.Set.of("k1"));
    source.close();
  }

  @Test
  public void fromWellKnown_nonConventionalURL() throws Exception {
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

    JWKS source = JWKS.fromWellKnown(
        "http://localhost:" + PORT + "/.custom-discovery").build();
    assertEquals(source.keyIds(), java.util.Set.of("k1"));
    source.close();
  }

  @Test
  public void get_returns_jwk_for_known_kid() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertNotNull(jwks.get("k1"));
      assertEquals(jwks.get("k1").kid(), "k1");
    }
  }

  @Test
  public void get_returns_null_for_null_kid() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertNull(jwks.get(null));
    }
  }

  @Test
  public void get_returns_null_for_unknown_kid() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertNull(jwks.get("not-present"));
    }
  }

  @Test
  public void keyIds_excludes_null_kids() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = rsaJWKSBodyWithKidlessMiddle("kid-A", "kid-B"))
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertEquals(jwks.keyIds(), new java.util.LinkedHashSet<>(java.util.List.of("kid-A", "kid-B")));
    }
  }

  @Test
  public void keyIds_returns_unmodifiable_view() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertThrows(UnsupportedOperationException.class, () -> jwks.keyIds().clear());
    }
  }

  @Test
  public void keys_preserves_insertion_order_and_includes_kidless() throws Exception {
    // Use case: kidless JWKs land in keys() but not in keyIds() / get(kid).
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = rsaJWKSBodyWithKidlessMiddle("kid-A", "kid-B"))
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      java.util.List<String> kids = jwks.keys().stream().map(JSONWebKey::kid).toList();
      assertEquals(kids, java.util.Arrays.asList("kid-A", null, "kid-B"));
    }
  }

  @Test
  public void keys_returns_unmodifiable_view() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertThrows(UnsupportedOperationException.class, () -> jwks.keys().clear());
    }
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
    assertNull(source.lastSuccessfulRefresh());
    assertEquals(source.consecutiveFailures(), 1);
    assertTrue(source.keyIds().isEmpty());
    JWKSFetchException ex = expectThrows(JWKSFetchException.class, source::refresh);
    assertEquals(ex.reason(), JWKSFetchException.Reason.EMPTY_RESULT);
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
  public void kidless_only_jwks_is_a_valid_snapshot() throws Exception {
    // Use case: a JWKS containing only kidless JWKs is permitted; keys() returns them,
    // but keyIds() and resolve() can't match anything. build() must NOT throw.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = rsaJWKSBodyAllKidless())
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertEquals(jwks.keys().size(), 1);
      assertTrue(jwks.keyIds().isEmpty());
      assertNull(jwks.get("anything"));
      assertEquals(jwks.consecutiveFailures(), 0);
      assertNotNull(jwks.lastSuccessfulRefresh());
    }
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .logger(logger)
        .build();
    assertTrue(logger.events.stream().anyMatch(e ->
        e.startsWith("Info ") && e.contains("JWKS refresh succeeded")));
    source.close();
  }

  @Test
  public void logger_emits_refreshFailure_at_error_with_throwable() {
    RecordingLogger logger = new RecordingLogger();
    JWKS source = JWKS.fromJWKS("http://127.0.0.1:1/jwks.json")
        .refreshTimeout(Duration.ofMillis(500))
        .logger(logger)
        .build();
    assertTrue(logger.events.stream().anyMatch(e -> e.startsWith("Error ")),
        "expected an Error-level event, got: " + logger.events);
    source.close();
  }

  @Test
  public void logger_emits_duplicateKid_at_warn() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_DUPLICATE_KID_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    RecordingLogger logger = new RecordingLogger();
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();

    httpServers.get(httpServers.size() - 1).stop(0);
    JWKSFetchException ex = expectThrows(JWKSFetchException.class, source::refresh);
    assertEquals(ex.reason(), JWKSFetchException.Reason.NETWORK);
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .clock(java.time.Clock.fixed(fixedNow, java.time.ZoneOffset.UTC))
        .minRefreshInterval(Duration.ofSeconds(30))
        .build();
    assertEquals(source.nextDueAt(), fixedNow.plusSeconds(30));
    source.close();
  }

  @Test
  public void backoffSequence_30s_to_60m_capped() {
    // Use case: backoff sequence with default settings is 30s, 60s, 120s, ... capped at 60m.
    Duration min = Duration.ofSeconds(30);
    Duration max = Duration.ofMinutes(60);
    long[] expectedSeconds = {30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600};
    for (int i = 0; i < expectedSeconds.length; i++) {
      Duration actual = JWKS.backoff(i + 1, min, max);
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build();
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
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
    String body2 = body1.replace("\"k1\"", "\"k2\"");
    org.lattejava.jwt.HttpServerBuilder b = new org.lattejava.jwt.HttpServerBuilder()
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body1)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json"));
    startHttpServer(b);

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .minRefreshInterval(Duration.ofMillis(100))
        .refreshInterval(Duration.ofMillis(100))
        .build();
    assertEquals(source.keyIds(), java.util.Set.of("k1"));

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
    JWKS source = JWKS.fromJWKS("http://127.0.0.1:1/jwks.json")
        .refreshTimeout(Duration.ofMillis(500))
        .build();
    assertNull(source.lastSuccessfulRefresh());
    assertEquals(source.consecutiveFailures(), 1);
    assertTrue(source.keyIds().isEmpty());
    source.close();
  }

  @Test
  public void duplicate_kid_first_write_wins() throws Exception {
    // Use case: a JWKS with two entries sharing the same kid keeps only the first; subsequent ones are dropped.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_DUPLICATE_KID_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    try (JWKS jwks = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json").build()) {
      assertEquals(jwks.keys().size(), 1);
      assertNotNull(jwks.get("k1"));
    }
  }

  @Test
  public void duplicateKid_firstWriteWins_firstKeyVerifies() throws Exception {
    // Use case: spec scenario #22 — a JWKS containing two valid RSA JWKs sharing the same kid
    // must keep the first one. The functional assertion: a signature produced by the first
    // private key verifies through the resolved Verifier. Last-wins would fail this check.
    java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    java.security.KeyPair kp1 = kpg.generateKeyPair();
    java.security.KeyPair kp2 = kpg.generateKeyPair();

    byte[] payload = "first-wins-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    java.security.Signature sigGen = java.security.Signature.getInstance("SHA256withRSA");
    sigGen.initSign(kp1.getPrivate());
    sigGen.update(payload);
    byte[] signature = sigGen.sign();

    String jwks = "{\"keys\":["
        + rsaJWKWithKid("k1", (java.security.interfaces.RSAPublicKey) kp1.getPublic())
        + ","
        + rsaJWKWithKid("k1", (java.security.interfaces.RSAPublicKey) kp2.getPublic())
        + "]}";

    RecordingLogger logger = new RecordingLogger();
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = jwks)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .logger(logger)
        .build();
    org.lattejava.jwt.Verifier v = source.resolve(org.lattejava.jwt.Header.builder()
        .alg(org.lattejava.jwt.Algorithm.RS256).kid("k1").build());
    assertNotNull(v);
    v.verify(payload, signature);  // throws if last-wins (kp2 cannot verify kp1's signature)
    assertTrue(logger.events.stream().anyMatch(e ->
        e.startsWith("Warn ") && e.contains("duplicate kid")), logger.events.toString());
    source.close();
  }

  @Test
  public void close_whileRefreshInflight_lateResultIsDiscarded() throws Exception {
    // Use case: after close(), the in-flight fetch's result is discarded. The snapshot must not
    // advance even though the underlying fetch eventually succeeds.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = RSA_JWKS_BODY)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")
            .with(r -> r.delayMillis = 800)));

    JWKS source = JWKS.fromJWKS("http://localhost:" + PORT + "/jwks.json")
        .refreshTimeout(Duration.ofMillis(50))
        .build();
    // build() awaiter timed out at 50ms; the fetch is still running.
    java.time.Instant priorSuccess = source.lastSuccessfulRefresh();
    assertNull(priorSuccess);

    source.close();
    // Wait past the 800ms handler delay so the fetch definitely completed.
    Thread.sleep(1_500);
    // Snapshot must not have advanced.
    assertNull(source.lastSuccessfulRefresh());
  }

  @Test
  public void of_first_write_wins_on_duplicate_kid() {
    // Use case: two JSONWebKeys with the same kid — static of() keeps the first, drops the second.
    JSONWebKey first = rsaJWK("shared-kid");
    JSONWebKey second = rsaJWK("shared-kid");
    JWKS jwks = JWKS.of(first, second);
    assertEquals(jwks.keys().size(), 1);
    assertSame(jwks.get("shared-kid"), first);
  }

  @Test
  public void of_no_args_is_permitted() {
    JWKS jwks = JWKS.of();
    assertNotNull(jwks);
    assertTrue(jwks.keys().isEmpty());
  }

  @Test
  public void of_static_refresh_is_noop() {
    JWKS jwks = JWKS.of(rsaJWK("kid-A"));
    jwks.refresh();
    assertEquals(jwks.consecutiveFailures(), 0);
    assertNull(jwks.lastFailedRefresh());
    assertNull(jwks.lastSuccessfulRefresh());
    assertNull(jwks.nextDueAt());
    jwks.close();  // no-op
  }

  @Test
  public void of_with_empty_list_is_permitted_and_returns_null_from_resolve() {
    JWKS jwks = JWKS.of(List.of());
    assertNotNull(jwks);
    assertTrue(jwks.keys().isEmpty());
    assertTrue(jwks.keyIds().isEmpty());
    assertNull(jwks.get("anything"));
    Header h = Header.builder().alg(Algorithm.HS256).kid("anything").build();
    assertNull(jwks.resolve(h));
  }

  @Test
  public void of_with_keys_returns_resolvable_static_set() {
    JSONWebKey k1 = rsaJWK("kid-A");
    JSONWebKey k2 = rsaJWK("kid-B");
    JWKS jwks = JWKS.of(k1, k2);
    assertEquals(jwks.keys().size(), 2);
    assertEquals(jwks.keyIds(), new LinkedHashSet<>(List.of("kid-A", "kid-B")));
    assertNotNull(jwks.get("kid-A"));
    assertNull(jwks.get("nope"));
  }

  @Test
  public void parseCacheControl_publicAlone_silentNoMaxAge() {
    // Use case: a header with no max-age directive (e.g. "Cache-Control: public") is not
    // malformed; it just doesn't supply a hint. parseCacheControl returns (null, false, false).
    JWKS.CacheControlDirectives d = JWKS.parseCacheControl("public");
    assertNull(d.maxAge());
    assertEquals(d.noStore(), false);
    assertEquals(d.malformed(), false);
  }

  @Test
  public void parseCacheControl_noStoreAlone_returnsFloor() {
    JWKS.CacheControlDirectives d = JWKS.parseCacheControl("no-store");
    assertEquals(d.noStore(), true);
    assertEquals(d.malformed(), false);
  }

  @Test
  public void parseCacheControl_conflictingMaxAge_isMalformed() {
    JWKS.CacheControlDirectives d = JWKS.parseCacheControl("max-age=300, max-age=600");
    assertEquals(d.malformed(), true);
  }

  @Test
  public void parseCacheControl_emptyMaxAgeValue_isMalformed() {
    JWKS.CacheControlDirectives d = JWKS.parseCacheControl("max-age=");
    assertEquals(d.malformed(), true);
  }

  @Test
  public void parseCacheControl_nonNumericMaxAge_isMalformed() {
    JWKS.CacheControlDirectives d = JWKS.parseCacheControl("max-age=abc");
    assertEquals(d.malformed(), true);
  }

  @Test
  public void parseRetryAfter_HTTPDateForm_returnsRelativeDuration() {
    // Use case: Cloudflare and several CDNs send HTTP-date Retry-After. Parser must honor it.
    java.time.Instant now = java.time.Instant.parse("2026-04-25T12:00:00Z");
    Duration d = JWKS.parseRetryAfter("Sat, 25 Apr 2026 12:01:00 GMT", now);
    assertNotNull(d);
    assertEquals(d, Duration.ofSeconds(60));
  }

  @Test
  public void parseRetryAfter_HTTPDate_inPastClampsToZero() {
    java.time.Instant now = java.time.Instant.parse("2026-04-25T12:00:00Z");
    Duration d = JWKS.parseRetryAfter("Sat, 25 Apr 2026 11:00:00 GMT", now);
    assertEquals(d, Duration.ZERO);
  }

  @Test
  public void parseRetryAfter_unparseable_returnsNull() {
    java.time.Instant now = java.time.Instant.parse("2026-04-25T12:00:00Z");
    assertNull(JWKS.parseRetryAfter("not-a-time", now));
  }

  // --- Discovery lock (Task 13) tests ---

  @Test
  public void fromIssuer_first_refresh_hits_discovery_then_jwks() throws Exception {
    // Use case: build() runs discovery exactly once and then fetches the JWKS once.
    AtomicInteger discoveryHits = new AtomicInteger();
    AtomicInteger jwksHits = new AtomicInteger();
    HttpServer srv = startOIDCServer(discoveryHits, jwksHits, new AtomicReference<>(null));

    try (JWKS jwks = JWKS.fromIssuer("http://localhost:" + PORT).build()) {
      assertEquals(jwks.keyIds(), java.util.Set.of("k1"));
      assertEquals(discoveryHits.get(), 1);
      assertEquals(jwksHits.get(), 1);
    } finally {
      srv.stop(0);
    }
  }

  @Test
  public void fromIssuer_subsequent_refresh_skips_discovery() throws Exception {
    // Use case: after the first successful fetch the jwks_uri is locked; subsequent
    // refresh() calls hit the JWKS endpoint directly and never re-run discovery.
    AtomicInteger discoveryHits = new AtomicInteger();
    AtomicInteger jwksHits = new AtomicInteger();
    HttpServer srv = startOIDCServer(discoveryHits, jwksHits, new AtomicReference<>(null));

    try (JWKS jwks = JWKS.fromIssuer("http://localhost:" + PORT).build()) {
      assertEquals(discoveryHits.get(), 1);
      assertEquals(jwksHits.get(), 1);

      jwks.refresh();

      assertEquals(discoveryHits.get(), 1, "discovery must not be called again after the lock");
      assertEquals(jwksHits.get(), 2);
    } finally {
      srv.stop(0);
    }
  }

  @Test
  public void fromIssuer_refresh_reattempts_discovery_until_first_success() throws Exception {
    // Use case: discovery fails once (500) then succeeds; every attempt before the
    // first lock re-runs discovery.
    AtomicInteger discoveryHits = new AtomicInteger();
    AtomicInteger jwksHits = new AtomicInteger();
    // First call to /.well-known/openid-configuration returns 500
    AtomicInteger discoveryFailsRemaining = new AtomicInteger(1);
    HttpServer srv = HttpServer.create(new InetSocketAddress(PORT), 0);
    httpServers.add(srv);
    String jwksBody = RSA_JWKS_BODY;
    String issuerBase = "http://localhost:" + PORT;
    String discoveryDoc = "{\"issuer\":\"" + issuerBase + "\",\"jwks_uri\":\"" + issuerBase + "/jwks.json\"}";
    srv.createContext("/.well-known/openid-configuration", exchange -> {
      discoveryHits.incrementAndGet();
      byte[] body;
      int status;
      if (discoveryFailsRemaining.getAndDecrement() > 0) {
        body = "{}".getBytes();
        status = 500;
      } else {
        body = discoveryDoc.getBytes();
        status = 200;
      }
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(status, body.length);
      exchange.getResponseBody().write(body);
      exchange.getResponseBody().close();
    });
    srv.createContext("/jwks.json", exchange -> {
      jwksHits.incrementAndGet();
      byte[] body = jwksBody.getBytes();
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.getResponseBody().close();
    });
    srv.start();

    // Initial build: discovery fails (500) -> OpenIDConnectException -> failFast=false, no throw
    JWKS jwks = JWKS.fromIssuer(issuerBase)
        .refreshTimeout(Duration.ofSeconds(2))
        .build();
    try {
      assertEquals(discoveryHits.get(), 1, "first attempt hits discovery");
      assertEquals(jwksHits.get(), 0, "jwks endpoint not reached when discovery failed");
      assertNull(jwks.lockedJWKSURI, "lock must not be set when discovery failed");

      // Second attempt: discovery succeeds, JWKS fetched, lock is set
      jwks.refresh();

      assertEquals(discoveryHits.get(), 2, "second attempt must re-run discovery");
      assertEquals(jwksHits.get(), 1, "JWKS fetched after successful discovery");
      assertNotNull(jwks.lockedJWKSURI, "lock must be set after first successful fetch");
    } finally {
      jwks.close();
      srv.stop(0);
    }
  }

  @Test
  public void fromIssuer_refresh_throws_OpenIDConnectException_while_discovery_not_yet_succeeded() throws Exception {
    // Use case: discovery always returns 500; calling refresh() must throw
    // OpenIDConnectException (not JWKSFetchException).
    HttpServer srv = HttpServer.create(new InetSocketAddress(PORT), 0);
    httpServers.add(srv);
    srv.createContext("/", exchange -> {
      exchange.sendResponseHeaders(500, 0);
      exchange.getResponseBody().close();
    });
    srv.start();

    JWKS jwks = JWKS.fromIssuer("http://localhost:" + PORT)
        .refreshTimeout(Duration.ofSeconds(2))
        .build();
    try {
      assertNull(jwks.lockedJWKSURI, "lock must not be set when discovery always fails");
      expectThrows(OpenIDConnectException.class, jwks::refresh);
    } finally {
      jwks.close();
      srv.stop(0);
    }
  }

  @Test
  public void fromIssuer_refresh_throws_JWKSFetchException_after_discovery_locked() throws Exception {
    // Use case: discovery succeeds and locks the jwks_uri; then the JWKS endpoint is
    // broken. Subsequent refresh() must throw JWKSFetchException, not OpenIDConnectException.
    AtomicInteger discoveryHits = new AtomicInteger();
    AtomicInteger jwksHits = new AtomicInteger();
    AtomicReference<String> jwksOverride = new AtomicReference<>(null);
    HttpServer srv = startOIDCServer(discoveryHits, jwksHits, jwksOverride);

    JWKS jwks = JWKS.fromIssuer("http://localhost:" + PORT).build();
    try {
      assertEquals(discoveryHits.get(), 1);
      assertEquals(jwksHits.get(), 1);
      assertNotNull(jwks.lockedJWKSURI, "lock must be set after first successful fetch");

      // Break the JWKS endpoint
      jwksOverride.set("FAIL");

      JWKSFetchException ex = expectThrows(JWKSFetchException.class, jwks::refresh);
      assertEquals(ex.reason(), JWKSFetchException.Reason.NON_2XX);
      assertEquals(discoveryHits.get(), 1, "discovery must not be called again after the lock");
    } finally {
      jwks.close();
      srv.stop(0);
    }
  }

  @Test
  public void fromConfiguration_does_not_perform_discovery_at_build() throws Exception {
    // Use case: JWKS.fromConfiguration(cfg) uses FetchSource.JWKS directly; no discovery hop.
    AtomicInteger discoveryHits = new AtomicInteger();
    AtomicInteger jwksHits = new AtomicInteger();
    HttpServer srv = startOIDCServer(discoveryHits, jwksHits, new AtomicReference<>(null));

    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
        .issuer("http://localhost:" + PORT)
        .jwksURI("http://localhost:" + PORT + "/jwks.json")
        .build();
    try (JWKS jwks = JWKS.fromConfiguration(cfg).build()) {
      assertEquals(jwks.keyIds(), java.util.Set.of("k1"));
      assertEquals(discoveryHits.get(), 0, "fromConfiguration must not perform discovery");
      assertEquals(jwksHits.get(), 1);
    } finally {
      srv.stop(0);
    }
  }

  /**
   * Starts an inline OIDC server on {@link #PORT} serving a discovery document at
   * {@code /.well-known/openid-configuration} and a JWKS at {@code /jwks.json}.
   * Hit counts are tracked via the provided {@link AtomicInteger} arguments.
   * When {@code jwksOverride} is set to {@code "FAIL"}, the JWKS endpoint returns 500.
   */
  private HttpServer startOIDCServer(AtomicInteger discoveryHits, AtomicInteger jwksHits,
      AtomicReference<String> jwksOverride) throws Exception {
    HttpServer srv = HttpServer.create(new InetSocketAddress(PORT), 0);
    httpServers.add(srv);
    String issuerBase = "http://localhost:" + PORT;
    String discoveryDoc = "{\"issuer\":\"" + issuerBase + "\",\"jwks_uri\":\"" + issuerBase + "/jwks.json\"}";
    String jwksBody = RSA_JWKS_BODY;
    srv.createContext("/.well-known/openid-configuration", exchange -> {
      discoveryHits.incrementAndGet();
      byte[] body = discoveryDoc.getBytes();
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.getResponseBody().close();
    });
    srv.createContext("/jwks.json", exchange -> {
      jwksHits.incrementAndGet();
      if ("FAIL".equals(jwksOverride.get())) {
        exchange.sendResponseHeaders(500, 0);
        exchange.getResponseBody().close();
        return;
      }
      byte[] body = jwksBody.getBytes();
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.getResponseBody().close();
    });
    srv.start();
    return srv;
  }

  /**
   * Returns a valid RSA JWK (RS256) with the given kid, using the fixed test modulus and exponent.
   */
  private static JSONWebKey rsaJWK(String kid) {
    String n = "sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw";
    return JSONWebKey.builder()
        .kty(KeyType.RSA)
        .alg(Algorithm.RS256)
        .kid(kid)
        .use("sig")
        .n(n)
        .e("AQAB")
        .build();
  }

  private static String rsaJWKWithKid(String kid, java.security.interfaces.RSAPublicKey pub) {
    java.util.Base64.Encoder enc = java.util.Base64.getUrlEncoder().withoutPadding();
    String n = enc.encodeToString(stripLeadingZero(pub.getModulus().toByteArray()));
    String e = enc.encodeToString(stripLeadingZero(pub.getPublicExponent().toByteArray()));
    return "{\"kty\":\"RSA\",\"kid\":\"" + kid + "\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
  }

  private static byte[] stripLeadingZero(byte[] bytes) {
    if (bytes.length > 1 && bytes[0] == 0) {
      byte[] out = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, out, 0, out.length);
      return out;
    }
    return bytes;
  }

  /**
   * Returns a JWKS JSON body containing a single kidless RSA JWK.
   */
  private static String rsaJWKSBodyAllKidless() {
    String n = "sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw";
    String e = "AQAB";
    String kidless = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
    return "{\"keys\":[" + kidless + "]}";
  }

  /**
   * Returns a JWKS JSON body containing three RSA JWKs: [kid0, kidless, kid1]. The kidless key
   * uses the same modulus/exponent as the keyed entries; tests use this to verify that kidless
   * JWKs appear in {@code keys()} but not in {@code keyIds()} or {@code get(kid)}.
   */
  private static String rsaJWKSBodyWithKidlessMiddle(String kid0, String kid1) {
    // Reuse a fixed modulus/exponent from the test RSA key -- distinct kids so no duplicate-kid drop.
    String n = "sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw";
    String e = "AQAB";
    String keyed0 = "{\"kty\":\"RSA\",\"kid\":\"" + kid0 + "\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
    String kidless = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
    String keyed1 = "{\"kty\":\"RSA\",\"kid\":\"" + kid1 + "\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
    return "{\"keys\":[" + keyed0 + "," + kidless + "," + keyed1 + "]}";
  }

  // --- failFast and fetch tests ---

  @Test
  public void builder_failFast_default_false_does_not_throw_on_initial_failure() throws Exception {
    // Use case: failFast defaults to false; a network-unreachable URL returns a usable (empty) JWKS.
    String url = "http://127.0.0.1:1/no-such-server";
    try (JWKS jwks = JWKS.fromJWKS(url).build()) {
      assertNotNull(jwks);
      assertNull(jwks.lastSuccessfulRefresh());
    }
  }

  @Test
  public void builder_failFast_does_not_leak_threads_on_failure() throws Exception {
    // Use case: when failFast throws, the scheduler is shut down and no jwks-* threads remain.
    long before = countJWKSThreads();
    String url = "http://127.0.0.1:1/no-such-server";
    assertThrows(JWKSFetchException.class,
        () -> JWKS.fromJWKS(url).failFast(true).scheduledRefresh(true).build());
    Thread.sleep(200);
    long after = countJWKSThreads();
    assertTrue(after <= before, "expected no new jwks-* threads but went from " + before + " to " + after);
  }

  @Test
  public void builder_failFast_throws_on_initial_failure() throws Exception {
    // Use case: failFast(true) re-raises the initial fetch exception synchronously from build().
    String url = "http://127.0.0.1:1/no-such-server";
    assertThrows(JWKSFetchException.class,
        () -> JWKS.fromJWKS(url).failFast(true).build());
  }

  @Test
  public void builder_fetchLimits_applies_to_jwks_response_size_cap() throws Exception {
    // Use case: a tight maxResponseBytes forces the initial fetch to fail; consecutiveFailures >= 1.
    String url = startJWKSServerReturningLargeBody();
    FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
    try (JWKS jwks = JWKS.fromJWKS(url).fetchLimits(tight).build()) {
      Thread.sleep(200);  // give async worker time to fail
      assertTrue(jwks.consecutiveFailures() >= 1);
    }
  }

  @Test
  public void fetch_rejects_cross_origin_redirect_by_default() throws Exception {
    // Use case: fetch uses sameOriginRedirectsOnly=true by default; cross-origin redirect is rejected.
    String url = startServerThatRedirectsToDifferentHost();
    JWKSFetchException ex = null;
    try {
      JWKS.fetch(url);
      fail("expected JWKSFetchException");
    } catch (JWKSFetchException e) {
      ex = e;
    }
    assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"),
        "Unexpected: " + ex.getMessage());
  }

  @Test
  public void fetch_returns_keys_from_jwks_endpoint() throws Exception {
    // Use case: fetch performs a one-shot fetch and returns all parsed keys.
    String url = startJWKSServer("kid-1", "kid-2");
    List<JSONWebKey> keys = JWKS.fetch(url);
    assertEquals(keys.stream().map(JSONWebKey::kid).toList(), List.of("kid-1", "kid-2"));
  }

  @Test
  public void fetch_with_FetchLimits_enforces_response_cap() throws Exception {
    // Use case: a tight maxResponseBytes causes fetch to throw JWKSFetchException.
    String url = startJWKSServerReturningLargeBody();
    FetchLimits tight = FetchLimits.builder().maxResponseBytes(64).build();
    assertThrows(JWKSFetchException.class, () -> JWKS.fetch(url, tight));
  }

  @Test
  public void fetch_with_customizer_applies_to_connection() throws Exception {
    // Use case: the customizer Consumer is called before the request is sent.
    AtomicBoolean called = new AtomicBoolean();
    String url = startJWKSServer("kid-1");
    JWKS.fetch(url, conn -> { called.set(true); conn.setRequestProperty("X-Test", "y"); });
    assertTrue(called.get());
  }

  private static long countJWKSThreads() {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(t -> t.getName().startsWith("jwks-"))
        .count();
  }

  /**
   * Starts an HTTP server that serves a minimal JWKS body containing RSA keys with the given kids,
   * and returns the URL to the endpoint.
   */
  private String startJWKSServer(String... kids) throws Exception {
    StringBuilder keys = new StringBuilder();
    String n = "sXch9_uEVyZw4d4XNjUMl7-DnbBwfXz9V_DwiHCNL5KNg6oHEcF7T7zJDSsBmWxAOKtc6vK4Ek5oN_R5kxdovfBdRRiClNxrRwmExZGMC8oBROHFEJiOFdDmqNJZbJ-w_e8KE2j_yWctgxX9LowhOWy0VEArLjr5tLqhwAtFm6gK_DfXXyZjU2DBBL_3Iaiu0YQz-jRR4lA1IAKVLA98m_4cP3pUvP6m9Eds3qpf0CzrI4DT9byOPQQX-FQOPaWTBcOJG6L9_kg7XYmbgrUKf6JhPYiTEVNvSXpHlxF6PoJiLvCNpyhGzFtOZf3GkmwNRbAdyOJ2HyjgNtuKnHcPlw";
    for (int i = 0; i < kids.length; i++) {
      if (i > 0) keys.append(",");
      keys.append("{\"kty\":\"RSA\",\"kid\":\"").append(kids[i])
          .append("\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"").append(n)
          .append("\",\"e\":\"AQAB\"}");
    }
    String body = "{\"keys\":[" + keys + "]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    return "http://localhost:" + PORT + "/jwks.json";
  }

  /**
   * Starts an HTTP server that returns a JWKS response body larger than 64 bytes
   * (triggering a maxResponseBytes cap), and returns the URL to the endpoint.
   */
  private String startJWKSServerReturningLargeBody() throws Exception {
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.responseSize = 1024 * 10)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));
    return "http://localhost:" + PORT + "/jwks.json";
  }

  /**
   * Starts an HTTP server that redirects to a different host (cross-origin), and returns the
   * URL to the redirecting endpoint.
   */
  private String startServerThatRedirectsToDifferentHost() throws Exception {
    // Redirect from 127.0.0.1 to localhost — these are distinct hostnames even though both
    // typically resolve to the loopback address, satisfying the cross-origin check.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.status = 302)
            .with(r -> r.redirectLocation = "http://localhost:" + PORT + "/jwks.json")));
    return "http://127.0.0.1:" + PORT + "/jwks.json";
  }
}
