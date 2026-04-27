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

package org.lattejava.jwt;

import com.sun.net.httpserver.HttpServer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class OpenIDConnectDiscoverTest {
  private HttpServer server;
  private String baseURL;

  @BeforeMethod
  public void setUp() throws IOException {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    server.start();
    int port = server.getAddress().getPort();
    baseURL = "http://localhost:" + port;
  }

  @AfterMethod
  public void tearDown() {
    if (server != null) {
      server.stop(0);
    }
  }

  private void serveJSON(String path, String body) {
    server.createContext(path, ex -> {
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().add("Content-Type", "application/json");
      ex.sendResponseHeaders(200, bytes.length);
      ex.getResponseBody().write(bytes);
      ex.close();
    });
  }

  @Test
  public void discover_appends_well_known_path_and_strips_trailing_slash_from_issuer() {
    // Use case: discover(issuer + "/") strips the trailing slash, appends /.well-known/openid-configuration,
    // and returns a parsed config when the response issuer matches.
    String body = "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\"}";
    serveJSON("/.well-known/openid-configuration", body);

    OpenIDConnectConfiguration cfg = OpenIDConnect.discover(baseURL + "/");
    assertNotNull(cfg);
    assertEquals(cfg.issuer(), baseURL);
    assertEquals(cfg.jwksURI(), baseURL + "/jwks");
  }

  @Test
  public void discover_passes_response_through_typed_routing() {
    // Use case: typed fields and unknown extension keys are both preserved in the parsed config.
    String body = "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\"," +
        "\"response_types_supported\":[\"code\",\"token\"],\"x_custom_extension\":\"hello\"}";
    serveJSON("/.well-known/openid-configuration", body);

    OpenIDConnectConfiguration cfg = OpenIDConnect.discover(baseURL);
    assertNotNull(cfg.responseTypesSupported());
    assertEquals(cfg.responseTypesSupported().size(), 2);
    assertEquals(cfg.otherClaims().get("x_custom_extension"), "hello");
  }

  @Test
  public void discover_rejects_issuer_equality_mismatch() {
    // Use case: response issuer differs from the expected issuer → OpenIDConnectException with attacker host in message.
    String body = "{\"issuer\":\"https://attacker.example\",\"jwks_uri\":\"" + baseURL + "/jwks\"}";
    serveJSON("/.well-known/openid-configuration", body);

    try {
      OpenIDConnect.discover(baseURL);
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertTrue(ex.getMessage().contains("attacker.example"),
          "Expected message to contain [attacker.example] but got: " + ex.getMessage());
      assertTrue(ex.getMessage().contains(baseURL),
          "Expected message to contain expected-issuer value, got: " + ex.getMessage());
    }
  }

  @Test
  public void discover_normalizes_trailing_slash_on_both_sides_of_issuer_check() {
    // Use case: trailing-slash normalization applies to both input and response, so
    // (issuer without slash / response with slash) and (issuer with slash / response without slash) both succeed.
    // Two contexts on the same server: root path and /x/ path.
    // Context 1: response issuer has trailing slash; input issuer does not
    String bodyRootWithSlash = "{\"issuer\":\"" + baseURL + "/\",\"jwks_uri\":\"" + baseURL + "/jwks\"}";
    // Context 2: response issuer has no trailing slash; input issuer has trailing slash
    String bodySubWithoutSlash = "{\"issuer\":\"" + baseURL + "/x\",\"jwks_uri\":\"" + baseURL + "/x/jwks\"}";
    serveJSON("/.well-known/openid-configuration", bodyRootWithSlash);
    serveJSON("/x/.well-known/openid-configuration", bodySubWithoutSlash);

    // input without slash, response issuer has trailing slash — both normalize to same value
    OpenIDConnectConfiguration cfg1 = OpenIDConnect.discover(baseURL);
    assertNotNull(cfg1);

    // input with slash, response issuer has no trailing slash — both normalize to same value
    OpenIDConnectConfiguration cfg2 = OpenIDConnect.discover(baseURL + "/x/");
    assertNotNull(cfg2);
  }

  @Test
  public void discover_throws_when_issuer_field_is_missing() {
    // Use case: missing issuer field in discovery response → OpenIDConnectException.
    String body = "{\"jwks_uri\":\"" + baseURL + "/jwks\"}";
    serveJSON("/.well-known/openid-configuration", body);

    try {
      OpenIDConnect.discover(baseURL);
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertTrue(ex.getMessage().contains("issuer"),
          "Expected message to mention [issuer] but got: " + ex.getMessage());
    }
  }

  @Test
  public void discoverFromWellKnown_does_not_validate_issuer_equality() {
    // Use case: discoverFromWellKnown passes null expectedIssuer, so differing issuer in response is accepted.
    String body = "{\"issuer\":\"https://some-other-host.example\",\"jwks_uri\":\"" + baseURL + "/jwks\"}";
    serveJSON("/.well-known/openid-configuration", body);

    OpenIDConnectConfiguration cfg = OpenIDConnect.discoverFromWellKnown(baseURL + "/.well-known/openid-configuration");
    assertNotNull(cfg);
    assertEquals(cfg.issuer(), "https://some-other-host.example");
  }

  @Test
  public void discoverFromWellKnown_throws_on_missing_jwks_uri() {
    // Use case: missing jwks_uri field → OpenIDConnectException mentioning jwks_uri.
    String body = "{\"issuer\":\"" + baseURL + "\"}";
    serveJSON("/.well-known/openid-configuration", body);

    try {
      OpenIDConnect.discoverFromWellKnown(baseURL + "/.well-known/openid-configuration");
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertTrue(ex.getMessage().contains("jwks_uri"),
          "Expected message to contain [jwks_uri] but got: " + ex.getMessage());
    }
  }

  @Test
  public void discover_throws_OpenIDConnectException_on_non_2xx() {
    // Use case: server returns 500 → OpenIDConnectException.
    server.createContext("/.well-known/openid-configuration", ex -> {
      ex.sendResponseHeaders(500, 0);
      ex.close();
    });

    try {
      OpenIDConnect.discover(baseURL);
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertNotNull(ex.getMessage());
    }
  }

  @Test
  public void discover_throws_OpenIDConnectException_on_unparseable_body() {
    // Use case: body is not valid JSON → OpenIDConnectException.
    server.createContext("/.well-known/openid-configuration", ex -> {
      byte[] bytes = "not-json".getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, bytes.length);
      ex.getResponseBody().write(bytes);
      ex.close();
    });

    try {
      OpenIDConnect.discover(baseURL);
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertNotNull(ex.getMessage());
    }
  }

  @Test
  public void discover_enforces_response_byte_cap_via_FetchLimits() {
    // Use case: FetchLimits.maxResponseBytes(64) causes a large response to throw OpenIDConnectException.
    StringBuilder sb = new StringBuilder("{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\",\"x_padding\":\"");
    while (sb.length() < 200) {
      sb.append("AAAAAAAAAA");
    }
    sb.append("\"}");
    serveJSON("/.well-known/openid-configuration", sb.toString());

    FetchLimits limits = FetchLimits.builder().maxResponseBytes(64).build();
    try {
      OpenIDConnect.discover(baseURL, limits);
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertNotNull(ex.getMessage());
    }
  }

  @Test
  public void discover_rejects_cross_origin_redirect_by_default() {
    // Use case: discovery endpoint redirects to a different origin → OpenIDConnectException with cross-origin message.
    server.createContext("/.well-known/openid-configuration", ex -> {
      ex.getResponseHeaders().add("Location", "http://evil.example/.well-known/openid-configuration");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });

    try {
      OpenIDConnect.discover(baseURL);
      fail("Expected OpenIDConnectException");
    } catch (OpenIDConnectException ex) {
      assertTrue(ex.getMessage().contains("cross-origin") || ex.getMessage().contains("Refusing"),
          "Expected cross-origin message but got: " + ex.getMessage());
    }
  }

  @Test
  public void discover_with_customizer_invokes_customizer_on_connection() {
    // Use case: Consumer<HttpURLConnection> customizer is called with the prepared connection.
    String body = "{\"issuer\":\"" + baseURL + "\",\"jwks_uri\":\"" + baseURL + "/jwks\"}";
    serveJSON("/.well-known/openid-configuration", body);

    AtomicReference<HttpURLConnection> captured = new AtomicReference<>();
    OpenIDConnect.discover(baseURL, conn -> captured.set(conn));

    assertNotNull(captured.get(), "Customizer should have been called with the connection");
  }
}
