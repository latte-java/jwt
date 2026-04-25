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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Wrapped as the {@code cause} of an HTTP-call failure when the remote
 * endpoint returned a non-2xx status. Carries the status code and the
 * response headers so callers (notably {@code JWKSource}) can read
 * {@code Retry-After} and {@code Cache-Control} on the failure path.
 *
 * <p>Header lookup is case-insensitive per RFC 9110.</p>
 */
public final class HTTPResponseException extends RuntimeException {
  private final Map<String, List<String>> headers;
  private final int statusCode;

  public HTTPResponseException(int statusCode, Map<String, List<String>> headers) {
    super("HTTP response status [" + statusCode + "]");
    this.statusCode = statusCode;
    Map<String, List<String>> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    if (headers != null) {
      for (Map.Entry<String, List<String>> e : headers.entrySet()) {
        if (e.getKey() != null) {
          ci.put(e.getKey(), e.getValue());
        }
      }
    }
    this.headers = Collections.unmodifiableMap(ci);
  }

  public Map<String, List<String>> headers() {
    return headers;
  }

  /**
   * Returns the first value of the named header, or {@code null} if absent.
   * Lookup is case-insensitive.
   */
  public String headerValue(String name) {
    List<String> values = headers.get(name);
    return (values == null || values.isEmpty()) ? null : values.get(0);
  }

  public int statusCode() {
    return statusCode;
  }
}
