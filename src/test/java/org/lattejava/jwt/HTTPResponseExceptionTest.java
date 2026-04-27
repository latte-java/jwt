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
