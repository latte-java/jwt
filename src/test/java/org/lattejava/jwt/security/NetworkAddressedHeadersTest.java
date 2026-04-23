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

package org.lattejava.jwt.security;

import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.Header;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Network-addressed headers (jku / x5u / jwk): proves that the decoder never
 * dereferences {@code jku}, {@code x5u}, or inline {@code jwk} header
 * parameters during decode.
 *
 * <p>The strategy is to bind a real {@link ServerSocket} on a chosen
 * {@code 127.0.0.1:PORT} and assert that no inbound TCP connection is ever
 * made by the decoder. The acceptor thread runs in the background and
 * increments a counter on every accepted connection; after decode we assert
 * the counter is still zero.</p>
 *
 * @author The Latte Project
 */
public class NetworkAddressedHeadersTest extends BaseJWTTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private ServerSocket serverSocket;

  private Thread acceptorThread;

  private final AtomicInteger connectionCount = new AtomicInteger();

  @BeforeMethod
  public void startProbeServer() throws IOException {
    // Bind to an ephemeral port; let the OS pick.
    serverSocket = new ServerSocket();
    serverSocket.setReuseAddress(true);
    serverSocket.bind(new InetSocketAddress("127.0.0.1", 0));
    connectionCount.set(0);

    acceptorThread = new Thread(() -> {
      while (!serverSocket.isClosed()) {
        try (Socket s = serverSocket.accept()) {
          connectionCount.incrementAndGet();
        } catch (IOException ignored) {
          // socket closed -- acceptor exits
          return;
        }
      }
    }, "network-probe-acceptor");
    acceptorThread.setDaemon(true);
    acceptorThread.start();
  }

  @AfterMethod
  public void stopProbeServer() throws IOException, InterruptedException {
    if (serverSocket != null) {
      serverSocket.close();
    }
    if (acceptorThread != null) {
      acceptorThread.join(2000);
    }
  }

  private int probePort() {
    return serverSocket.getLocalPort();
  }

  @Test
  public void jkuHeader_notDereferenced() throws Exception {
    // Use case: JWT with jku header referencing localhost:<probe> decodes
    // without issuing any network connection.
    String jkuUrl = "http://127.0.0.1:" + probePort() + "/keys.json";
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(
        jwt,
        HMACSigner.newSHA256Signer(SECRET),
        b -> b.parameter("jku", jkuUrl));

    Verifier hmac = HMACVerifier.newVerifier(SECRET);
    JWT decoded = new JWTDecoder().decode(token, VerifierResolver.of(hmac));
    assertNotNull(decoded);
    assertEquals(connectionCount.get(), 0,
        "Decoder must not dereference jku; observed " + connectionCount.get() + " connections");
  }

  @Test
  public void x5uHeader_notDereferenced() throws Exception {
    // Use case: JWT with x5u header referencing a remote URL decodes without
    // issuing any network connection.
    String x5uUrl = "http://127.0.0.1:" + probePort() + "/cert.pem";
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(
        jwt,
        HMACSigner.newSHA256Signer(SECRET),
        b -> b.parameter("x5u", x5uUrl));

    Verifier hmac = HMACVerifier.newVerifier(SECRET);
    JWT decoded = new JWTDecoder().decode(token, VerifierResolver.of(hmac));
    assertNotNull(decoded);
    assertEquals(connectionCount.get(), 0,
        "Decoder must not dereference x5u; observed " + connectionCount.get() + " connections");
  }

  @Test
  public void inlineJwkHeader_parsedNotConsumed() throws Exception {
    // Use case: JWT with inline jwk header parses the jwk map into
    // Header.parameters() but does not construct a Verifier from it.
    Map<String, Object> jwk = new LinkedHashMap<>();
    jwk.put("kty", "oct");
    jwk.put("k", "wantToBeAVerifier");

    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(
        jwt,
        HMACSigner.newSHA256Signer(SECRET),
        b -> b.parameter("jwk", jwk));

    Verifier hmac = HMACVerifier.newVerifier(SECRET);
    JWT decoded = new JWTDecoder().decode(token, VerifierResolver.of(hmac));
    assertNotNull(decoded);
    Header header = decoded.header();
    Object received = header.get("jwk");
    assertTrue(received instanceof Map, "Inline jwk must be exposed as a Map");
    @SuppressWarnings("unchecked")
    Map<String, Object> receivedMap = (Map<String, Object>) received;
    assertEquals(receivedMap.get("kty"), "oct");
    assertEquals(receivedMap.get("k"), "wantToBeAVerifier");
    assertEquals(connectionCount.get(), 0);
  }

  @Test
  public void inlineJwk_explicitOptInPath_works() throws Exception {
    // Use case: Explicit opt-in -- VerifierResolver.from(h -> ...) lets the
    // caller construct a Verifier from h.get("jwk"). The library does not do
    // this on the caller's behalf; this test shows the supported escape hatch.
    Map<String, Object> jwk = new LinkedHashMap<>();
    jwk.put("kty", "oct");
    jwk.put("alg", "HS256");

    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(
        jwt,
        HMACSigner.newSHA256Signer(SECRET),
        b -> b.parameter("jwk", jwk));

    // Explicit caller-side bridge from header.jwk to a Verifier. The library
    // never does this automatically -- this is the documented opt-in path.
    VerifierResolver resolver = VerifierResolver.from(h -> {
      Object inline = h.get("jwk");
      if (inline == null) {
        return null;
      }
      // For the test we ignore the inline content and use the known shared
      // secret; the point is that the resolver is the explicit bridge.
      return HMACVerifier.newVerifier(SECRET);
    });
    JWT decoded = new JWTDecoder().decode(token, resolver);
    assertNotNull(decoded);
  }
}
