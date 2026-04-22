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
 * @author The Latte Project
 */
public class JSONWebKeySetHelperTest extends BaseTest {
  private static final int PORT = 4243;

  @AfterMethod
  public void resetHelperConfig() {
    // Restore defaults so tests stay isolated.
    JSONWebKeySetHelper.setMaxResponseSize(JSONWebKeySetHelper.DEFAULT_MAX_RESPONSE_BYTES);
    JSONWebKeySetHelper.setMaxRedirects(JSONWebKeySetHelper.DEFAULT_MAX_REDIRECTS);
  }

  // Use case: HTTP (not HTTPS) URL accepted (no scheme restriction by default)
  // Use case: JWKS endpoint response with mixed key types (RSA, EC) parses without error
  @Test
  public void retrieve_keys_over_http_succeeds() throws Exception {
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

  // Use case: Response of exactly maxResponseBytes accepted
  @Test
  public void response_exactly_at_max_response_bytes_is_accepted() throws Exception {
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

  // Use case: Response of maxResponseBytes + 1 rejected with ResponseTooLargeException
  @Test
  public void response_one_byte_over_cap_is_rejected() throws Exception {
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
      fail("Expected JSONWebKeyBuilderException with ResponseTooLargeException cause.");
    } catch (RuntimeException e) {
      assertTrue(containsCause(e, ResponseTooLargeException.class), "expected ResponseTooLargeException in cause chain, got: " + e);
    }
  }

  // Use case: 3 sequential 301 redirects followed, 4th response returned
  @Test
  public void three_redirects_are_followed() throws Exception {
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

  // Use case: 4 sequential redirects rejected (default maxRedirects=3)
  @Test
  public void four_redirects_are_rejected() throws Exception {
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

  // Use case: Redirect to a final body that exceeds maxResponseBytes still rejected
  // cleanly (size cap applies per-hop)
  @Test
  public void per_hop_size_cap_enforced_after_redirect() throws Exception {
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

  private static boolean containsCause(Throwable t, Class<? extends Throwable> needle) {
    while (t != null) {
      if (needle.isInstance(t)) return true;
      t = t.getCause();
    }
    return false;
  }
}
