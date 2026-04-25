/*
 * Copyright (c) 2026, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.BaseTest;
import org.lattejava.jwt.ExpectedResponse;
import org.lattejava.jwt.ResponseTooLargeException;
import org.lattejava.jwt.TooManyRedirectsException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Response-hardening tests for {@link JSONWebKeySetHelper}.
 *
 * <p>Each test stands up a local HTTP server via {@link BaseTest#startHttpServer}
 * so we can exercise the body-size cap, redirect-count cap, and per-hop
 * size enforcement without depending on any external network host.</p>
 *
 * @author Daniel DeGroff
 */
public class JSONWebKeySetHelperTest extends BaseTest {
  private static final int PORT = 4243;

  @AfterMethod
  public void resetHelperConfig() {
    // Restore defaults so tests stay isolated.
    JSONWebKeySetHelper.resetDefaults();
  }

  @Test
  public void retrieve_keys_over_http_succeeds() throws Exception {
    // Use case: HTTP (not HTTPS) URL accepted (no scheme restriction by default)
    // Use case: JWKS endpoint response with mixed key types (RSA, EC) parses without error
    String body = "{\"keys\":["
        + "{\"kty\":\"RSA\",\"kid\":\"a\",\"n\":\"AQAB\",\"e\":\"AQAB\"},"
        + "{\"kty\":\"EC\",\"kid\":\"b\",\"crv\":\"P-256\",\"x\":\"AAAA\",\"y\":\"AAAA\"}"
        + "]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
    assertEquals(keys.size(), 2);
    assertEquals(keys.get(0).kid(), "a");
    assertEquals(keys.get(1).kid(), "b");
  }

  @Test
  public void response_exactly_at_max_response_bytes_is_accepted() throws Exception {
    // Use case: Response of exactly maxResponseBytes accepted
    // A 256-byte body that is valid JSON (the JWK parser will reject it for
    // missing structure, but we are testing the size cap path -- a valid
    // body is supplied via the JSON-shaped padding).
    int size = 256;
    StringBuilder sb = new StringBuilder("{\"keys\":[]");
    while (sb.length() < size - 1) sb.append(' ');
    sb.append('}');
    String body = sb.toString();
    assertEquals(body.length(), size);

    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxResponseSize(size);
    List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
    assertEquals(keys.size(), 0);
  }

  @Test
  public void response_one_byte_over_cap_is_rejected() throws Exception {
    // Use case: Response of maxResponseBytes + 1 rejected with ResponseTooLargeException
    int cap = 128;
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.responseSize = cap + 1)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxResponseSize(cap);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeyException with ResponseTooLargeException cause.");
    } catch (RuntimeException e) {
      assertTrue(containsCause(e, ResponseTooLargeException.class), "expected ResponseTooLargeException in cause chain, got: " + e);
    }
  }

  @Test
  public void three_redirects_are_followed() throws Exception {
    // Use case: 3 sequential 301 redirects followed, 4th response returned
    String body = "{\"keys\":[]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/r1")
        .andReturn(new ExpectedResponse()
            .with(r -> r.status = 301)
            .with(r -> r.redirectLocation = "http://localhost:" + PORT + "/r2")
            .with(r -> r.contentType = null))
        .handleURI("/r2")
        .andReturn(new ExpectedResponse()
            .with(r -> r.status = 301)
            .with(r -> r.redirectLocation = "http://localhost:" + PORT + "/r3")
            .with(r -> r.contentType = null))
        .handleURI("/r3")
        .andReturn(new ExpectedResponse()
            .with(r -> r.status = 301)
            .with(r -> r.redirectLocation = "http://localhost:" + PORT + "/jwks.json")
            .with(r -> r.contentType = null))
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxRedirects(3);
    List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/r1");
    assertNotNull(keys);
    assertEquals(keys.size(), 0);
  }

  @Test
  public void four_redirects_are_rejected() throws Exception {
    // Use case: 4 sequential redirects rejected (default maxRedirects=3)
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/r1")
        .andReturn(new ExpectedResponse().with(r -> r.status = 301).with(r -> r.redirectLocation = "http://localhost:" + PORT + "/r2").with(r -> r.contentType = null))
        .handleURI("/r2")
        .andReturn(new ExpectedResponse().with(r -> r.status = 301).with(r -> r.redirectLocation = "http://localhost:" + PORT + "/r3").with(r -> r.contentType = null))
        .handleURI("/r3")
        .andReturn(new ExpectedResponse().with(r -> r.status = 301).with(r -> r.redirectLocation = "http://localhost:" + PORT + "/r4").with(r -> r.contentType = null))
        .handleURI("/r4")
        .andReturn(new ExpectedResponse().with(r -> r.status = 301).with(r -> r.redirectLocation = "http://localhost:" + PORT + "/jwks.json").with(r -> r.contentType = null))
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse().with(r -> r.response = "{\"keys\":[]}").with(r -> r.status = 200)));

    JSONWebKeySetHelper.setMaxRedirects(3);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/r1");
      fail("Expected TooManyRedirectsException.");
    } catch (TooManyRedirectsException expected) {
      // good
    } catch (RuntimeException e) {
      assertTrue(containsCause(e, TooManyRedirectsException.class), "expected TooManyRedirectsException in cause chain, got: " + e);
    }
  }

  @Test
  public void per_hop_size_cap_enforced_after_redirect() throws Exception {
    // Use case: Redirect to a final body that exceeds maxResponseBytes still rejected
    // cleanly (size cap applies per-hop)
    int cap = 128;
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/r1")
        .andReturn(new ExpectedResponse()
            .with(r -> r.status = 302)
            .with(r -> r.redirectLocation = "http://localhost:" + PORT + "/big")
            .with(r -> r.contentType = null))
        .handleURI("/big")
        .andReturn(new ExpectedResponse()
            .with(r -> r.responseSize = cap + 1)
            .with(r -> r.status = 200)));

    JSONWebKeySetHelper.setMaxResponseSize(cap);
    JSONWebKeySetHelper.setMaxRedirects(3);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/r1");
      fail("Expected ResponseTooLargeException after redirect.");
    } catch (RuntimeException e) {
      assertTrue(containsCause(e, ResponseTooLargeException.class), "expected ResponseTooLargeException in cause chain, got: " + e);
    }
  }

  @Test
  public void setMaxResponseSize_rejectsNonPositive() {
    // Use case: the response cap cannot be disabled. Clients that attempt to pass -1 or 0
    // (common "disable the limit" idiom) receive IllegalArgumentException rather than silently
    // removing the DoS defense.
    try {
      JSONWebKeySetHelper.setMaxResponseSize(-1);
      fail("Expected IllegalArgumentException for maxResponseSize=-1");
    } catch (IllegalArgumentException expected) {
    }
    try {
      JSONWebKeySetHelper.setMaxResponseSize(0);
      fail("Expected IllegalArgumentException for maxResponseSize=0");
    } catch (IllegalArgumentException expected) {
    }
  }

  @Test
  public void setMaxNestingDepth_rejectsNonPositive() {
    // Use case: a zero/negative nesting cap would silently disable the depth defense.
    try {
      JSONWebKeySetHelper.setMaxNestingDepth(0);
      fail("Expected IllegalArgumentException for maxNestingDepth=0");
    } catch (IllegalArgumentException expected) {
    }
    try {
      JSONWebKeySetHelper.setMaxNestingDepth(-1);
      fail("Expected IllegalArgumentException for maxNestingDepth=-1");
    } catch (IllegalArgumentException expected) {
    }
  }

  @Test
  public void setMaxNumberLength_rejectsNonPositive() {
    // Use case: a zero/negative number-length cap would silently disable the parser's
    // BigInteger/BigDecimal blow-up defense.
    try {
      JSONWebKeySetHelper.setMaxNumberLength(0);
      fail("Expected IllegalArgumentException for maxNumberLength=0");
    } catch (IllegalArgumentException expected) {
    }
    try {
      JSONWebKeySetHelper.setMaxNumberLength(-1);
      fail("Expected IllegalArgumentException for maxNumberLength=-1");
    } catch (IllegalArgumentException expected) {
    }
  }

  @Test
  public void setMaxObjectMembers_rejectsNonPositive() {
    // Use case: a zero/negative object-members cap would silently disable the parser's
    // wide-object fan-out defense.
    try {
      JSONWebKeySetHelper.setMaxObjectMembers(0);
      fail("Expected IllegalArgumentException for maxObjectMembers=0");
    } catch (IllegalArgumentException expected) {
    }
    try {
      JSONWebKeySetHelper.setMaxObjectMembers(-1);
      fail("Expected IllegalArgumentException for maxObjectMembers=-1");
    } catch (IllegalArgumentException expected) {
    }
  }

  @Test
  public void setMaxArrayElements_rejectsNonPositive() {
    // Use case: a zero/negative array-elements cap would silently disable the parser's
    // wide-array fan-out defense.
    try {
      JSONWebKeySetHelper.setMaxArrayElements(0);
      fail("Expected IllegalArgumentException for maxArrayElements=0");
    } catch (IllegalArgumentException expected) {
    }
    try {
      JSONWebKeySetHelper.setMaxArrayElements(-1);
      fail("Expected IllegalArgumentException for maxArrayElements=-1");
    } catch (IllegalArgumentException expected) {
    }
  }

  @Test
  public void parse_rejectsExcessivelyWideObject() throws Exception {
    // Use case: a JWKS response whose top-level object has more members than maxObjectMembers
    // is rejected at parse time rather than being deserialized into a wide map.
    StringBuilder sb = new StringBuilder("{\"keys\":[]");
    for (int i = 0; i < 20; i++) {
      sb.append(",\"k").append(i).append("\":1");
    }
    sb.append('}');
    String body = sb.toString();
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxObjectMembers(5);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeySetException due to maxObjectMembers cap");
    } catch (RuntimeException e) {
      assertTrue(e.getMessage() != null && (e.getMessage().contains("maxObjectMembers")
          || (e.getCause() != null && String.valueOf(e.getCause().getMessage()).contains("maxObjectMembers"))),
          "expected maxObjectMembers message, got: " + e);
    }
  }

  @Test
  public void parse_rejectsExcessivelyWideArray() throws Exception {
    // Use case: a JWKS response whose [keys] array has more elements than maxArrayElements
    // is rejected at parse time rather than being walked as a wide list.
    StringBuilder sb = new StringBuilder("{\"keys\":[");
    for (int i = 0; i < 20; i++) {
      if (i > 0) sb.append(',');
      sb.append("{\"kty\":\"oct\",\"kid\":\"").append(i).append("\"}");
    }
    sb.append("]}");
    String body = sb.toString();
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxArrayElements(5);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeySetException due to maxArrayElements cap");
    } catch (RuntimeException e) {
      assertTrue(e.getMessage() != null && (e.getMessage().contains("maxArrayElements")
          || (e.getCause() != null && String.valueOf(e.getCause().getMessage()).contains("maxArrayElements"))),
          "expected maxArrayElements message, got: " + e);
    }
  }

  @Test
  public void parse_rejectsExcessivelyDeepNesting() throws Exception {
    // Use case: a JWKS response whose JSON nesting exceeds maxNestingDepth is rejected
    // at parse time rather than being deserialized into a deeply-nested structure that
    // could blow the stack downstream.
    StringBuilder sb = new StringBuilder("{\"keys\":[");
    int depth = 5;
    for (int i = 0; i < depth; i++) {
      sb.append('[');
    }
    for (int i = 0; i < depth; i++) {
      sb.append(']');
    }
    sb.append("]}");
    String body = sb.toString();
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxNestingDepth(3);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeySetException due to nesting cap");
    } catch (RuntimeException e) {
      // The parser raises JSONProcessingException; the helper wraps it as a JWKS-set
      // failure. Either appears in the cause chain.
      assertTrue(e.getMessage() != null && (e.getMessage().contains("nesting")
          || (e.getCause() != null && String.valueOf(e.getCause().getMessage()).contains("nesting"))),
          "expected nesting-depth message, got: " + e);
    }
  }

  @Test
  public void parse_rejectsExcessivelyLongNumber() throws Exception {
    // Use case: a JWKS response whose JSON contains a single number longer than
    // maxNumberLength is rejected at parse time rather than being passed to
    // BigInteger/BigDecimal where it could cost O(n^2) to construct.
    StringBuilder digits = new StringBuilder();
    for (int i = 0; i < 200; i++) {
      digits.append('1');
    }
    String body = "{\"keys\":[],\"x\":" + digits + "}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setMaxNumberLength(50);
    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeySetException due to number-length cap");
    } catch (RuntimeException e) {
      assertTrue(e.getMessage() != null && (e.getMessage().contains("maxNumberLength")
          || (e.getCause() != null && String.valueOf(e.getCause().getMessage()).contains("maxNumberLength"))),
          "expected maxNumberLength message, got: " + e);
    }
  }

  @Test
  public void parse_rejectsDuplicateKeysByDefault() throws Exception {
    // Use case: a JWKS response with a duplicate top-level member is rejected by default
    // -- a caller cannot smuggle a second value past the parser by including the key twice.
    String body = "{\"keys\":[],\"keys\":[{\"kty\":\"oct\"}]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeySetException due to duplicate key");
    } catch (RuntimeException e) {
      assertTrue(e.getMessage() != null && (e.getMessage().contains("Duplicate")
          || (e.getCause() != null && String.valueOf(e.getCause().getMessage()).contains("Duplicate"))),
          "expected Duplicate-key message, got: " + e);
    }
  }

  @Test
  public void parse_allowsDuplicateKeysWhenConfigured() throws Exception {
    // Use case: when a caller explicitly opts into duplicate-key tolerance, the parser
    // accepts the response (last value wins, per LinkedHashMap put semantics).
    String body = "{\"keys\":[],\"keys\":[]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = body)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    JSONWebKeySetHelper.setAllowDuplicateJSONKeys(true);
    List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
    assertEquals(keys.size(), 0);
  }

  @Test
  public void non2xx_response_throws_with_HTTPResponseException_cause() throws Exception {
    // Use case: a 429 with Retry-After must be reachable from the thrown exception's
    // cause chain — JWKSource depends on this to honor Retry-After.
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = "{\"error\":\"rate-limited\"}")
            .with(r -> r.status = 429)
            .with(r -> r.contentType = "application/json")));

    try {
      JSONWebKeySetHelper.retrieveKeysFromJWKS("http://localhost:" + PORT + "/jwks.json");
      fail("Expected JSONWebKeyException for 429.");
    } catch (RuntimeException e) {
      Throwable cause = e.getCause();
      while (cause != null && !(cause instanceof org.lattejava.jwt.HTTPResponseException)) {
        cause = cause.getCause();
      }
      assertNotNull(cause, "HTTPResponseException must appear in the cause chain");
      org.lattejava.jwt.HTTPResponseException httpEx = (org.lattejava.jwt.HTTPResponseException) cause;
      assertEquals(httpEx.statusCode(), 429);
    }
  }

  @Test
  public void customizer_is_applied_to_both_discovery_and_JWKS_hops() throws Exception {
    // Use case: an Authorization header set via httpConnectionCustomizer must reach
    // both the discovery hop and the JWKS hop after a discovery resolution.
    String discoveryBody = "{\"jwks_uri\":\"http://localhost:" + PORT + "/jwks.json\"}";
    String jwksBody = "{\"keys\":[]}";
    startHttpServer(server -> server
        .listenOn(PORT)
        .handleURI("/.well-known/openid-configuration")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = discoveryBody)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json"))
        .handleURI("/jwks.json")
        .andReturn(new ExpectedResponse()
            .with(r -> r.response = jwksBody)
            .with(r -> r.status = 200)
            .with(r -> r.contentType = "application/json")));

    java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
    java.util.function.Consumer<java.net.HttpURLConnection> customizer = c -> {
      calls.incrementAndGet();
      c.setRequestProperty("X-Test-Marker", "applied");
    };

    List<JSONWebKey> keys = JSONWebKeySetHelper.retrieveKeysFromWellKnownConfiguration(
        "http://localhost:" + PORT + "/.well-known/openid-configuration", customizer);
    assertEquals(keys.size(), 0);
    // 2 = once on the discovery hop, once on the JWKS hop. Pre-fix, this was 1.
    assertEquals(calls.get(), 2);
  }

  private static boolean containsCause(Throwable t, Class<? extends Throwable> needle) {
    while (t != null) {
      if (needle.isInstance(t)) return true;
      t = t.getCause();
    }
    return false;
  }
}
