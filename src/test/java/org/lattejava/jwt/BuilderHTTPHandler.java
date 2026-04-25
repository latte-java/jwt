/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt;


import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Daniel DeGroff
 */
public class BuilderHTTPHandler implements HttpHandler {
  public String actualRequestBody;

  public int called = 0;

  public Map<String, ExpectedResponse> responses;

  public BuilderHTTPHandler(Map<String, ExpectedResponse> responses) {
    this.responses = responses;
  }

  @Override
  public void handle(HttpExchange httpExchange) throws IOException {
    called++;

    try (BufferedReader reader = new BufferedReader(new InputStreamReader(httpExchange.getRequestBody(), StandardCharsets.UTF_8))) {
      actualRequestBody = reader.lines().collect(Collectors.joining(System.lineSeparator()));
    }

    String requestedURI = httpExchange.getRequestURI().toString();
    ExpectedResponse expectedResult = responses.get(requestedURI);

    // Bail right away if we have nothing to offer.
    if (expectedResult == null) {
      httpExchange.sendResponseHeaders(200, 0);
      httpExchange.getResponseBody().close();
      return;
    }

    if (expectedResult.delayMillis > 0) {
      try {
        Thread.sleep(expectedResult.delayMillis);
      } catch (InterruptedException ignored) {
        Thread.currentThread().interrupt();
      }
    }

    // Set headers BEFORE sendResponseHeaders (HttpExchange flushes once headers are committed).
    if (expectedResult.contentType != null) {
      httpExchange.getResponseHeaders().add("Content-Type", expectedResult.contentType);
    }
    if (expectedResult.redirectLocation != null) {
      httpExchange.getResponseHeaders().add("Location", expectedResult.redirectLocation);
    }
    if (expectedResult.headers != null) {
      for (Map.Entry<String, String> entry : expectedResult.headers.entrySet()) {
        httpExchange.getResponseHeaders().add(entry.getKey(), entry.getValue());
      }
    }

    if (expectedResult.responseSize > 0) {
      // Stream a synthesized body of exactly responseSize bytes. Content is a
      // wide-padded JSON object so that a JSON parser still parses any prefix
      // up to the cap; the test cares about the size enforcement, not the
      // content semantics.
      int total = expectedResult.responseSize;
      httpExchange.sendResponseHeaders(expectedResult.status, total);
      try (java.io.OutputStream out = httpExchange.getResponseBody()) {
        byte[] chunk = new byte[Math.min(8192, total)];
        java.util.Arrays.fill(chunk, (byte) ' ');
        int written = 0;
        while (written < total) {
          int len = Math.min(chunk.length, total - written);
          out.write(chunk, 0, len);
          written += len;
        }
      }
      return;
    }

    // Else return the expected result body verbatim.
    byte[] bytes = expectedResult.response == null ? new byte[]{} : expectedResult.response.getBytes(StandardCharsets.UTF_8);
    httpExchange.sendResponseHeaders(expectedResult.status, bytes.length);

    if (bytes.length != 0) {
      httpExchange.getResponseBody().write(bytes);
      httpExchange.getResponseBody().flush();
    }

    httpExchange.getResponseBody().close();
  }
}