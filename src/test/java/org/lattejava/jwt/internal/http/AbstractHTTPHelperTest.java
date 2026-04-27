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

package org.lattejava.jwt.internal.http;

import java.io.*;
import java.net.*;

import com.sun.net.httpserver.*;
import org.lattejava.jwt.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

public class AbstractHTTPHelperTest extends BaseTest {
  private static String readAll(InputStream is) {
    try {
      return new String(is.readAllBytes());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void get_with_same_origin_only_allows_same_origin_redirects() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int port = server.getAddress().getPort();
    server.createContext("/redirect", ex -> {
      ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + port + "/target");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    server.createContext("/target", ex -> {
      byte[] body = "ok".getBytes();
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.start();
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/redirect").openConnection();
      String body = AbstractHTTPHelper.get(conn, 1024, 3, true,
          (c, is) -> readAll(is),
          IllegalStateException::new);
      assertEquals(body, "ok");
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void get_with_same_origin_only_rejects_cross_origin_redirect() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/redirect", ex -> {
      ex.getResponseHeaders().add("Location", "http://localhost:1/target");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    server.start();
    try {
      int port = server.getAddress().getPort();
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/redirect").openConnection();
      try {
        AbstractHTTPHelper.get(conn, 1024, 3, true,
            (c, is) -> readAll(is),
            IllegalStateException::new);
        fail("Expected IllegalStateException for cross-origin redirect");
      } catch (IllegalStateException ex) {
        assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"),
            "Unexpected message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("127.0.0.1"));
        assertTrue(ex.getMessage().contains("localhost"));
      }
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void get_with_same_origin_only_rejects_same_host_different_port_redirect() throws Exception {
    // Use case: same scheme + host but different port is still cross-origin.
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/redirect", ex -> {
      ex.getResponseHeaders().add("Location", "http://127.0.0.1:1/target");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    server.start();
    try {
      int port = server.getAddress().getPort();
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/redirect").openConnection();
      try {
        AbstractHTTPHelper.get(conn, 1024, 3, true,
            (c, is) -> readAll(is),
            IllegalStateException::new);
        fail("Expected cross-origin redirect rejection");
      } catch (IllegalStateException ex) {
        assertTrue(ex.getMessage().contains("Refusing cross-origin redirect"));
        assertTrue(ex.getMessage().contains(":" + port));
        assertTrue(ex.getMessage().contains(":1"));
      }
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void get_without_same_origin_only_follows_cross_origin_redirect() throws Exception {
    // Use case: confirm the new overload's sameOriginRedirectsOnly=false matches the legacy permissive behavior.
    HttpServer src = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    HttpServer dst = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int srcPort = src.getAddress().getPort();
    int dstPort = dst.getAddress().getPort();
    src.createContext("/r", ex -> {
      ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + dstPort + "/t");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    dst.createContext("/t", ex -> {
      byte[] body = "ok".getBytes();
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    src.start();
    dst.start();
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + srcPort + "/r").openConnection();
      String body = AbstractHTTPHelper.get(conn, 1024, 3, false,
          (c, is) -> readAll(is),
          IllegalStateException::new);
      assertEquals(body, "ok");
    } finally {
      src.stop(0);
      dst.stop(0);
    }
  }
}
