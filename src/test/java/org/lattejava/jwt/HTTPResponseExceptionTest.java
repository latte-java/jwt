/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;

import org.testng.annotations.*;

import static org.testng.Assert.*;

public class HTTPResponseExceptionTest {
  @Test
  public void carriesStatusAndHeaders() {
    Map<String, List<String>> headers = Map.of(
        "Retry-After", List.of("60"),
        "Cache-Control", List.of("public, max-age=300"));
    HTTPResponseException ex = new HTTPResponseException(429, headers);
    assertEquals(ex.statusCode(), 429);
    assertEquals(ex.headerValue("Retry-After"), "60");
    assertEquals(ex.headerValue("retry-after"), "60");
    assertEquals(ex.headerValue("Cache-Control"), "public, max-age=300");
    assertNull(ex.headerValue("X-Missing"));
  }
}
