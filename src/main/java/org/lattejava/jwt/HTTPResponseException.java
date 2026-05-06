/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;

/**
 * Wrapped as the {@code cause} of an HTTP-call failure when the remote endpoint returned a non-2xx status. Carries the
 * status code and the response headers so callers (notably {@code JWKS}) can read {@code Retry-After} and
 * {@code Cache-Control} on the failure path.
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

  /**
   * Returns the first value of the named header, or {@code null} if absent. Lookup is case-insensitive.
   */
  public String headerValue(String name) {
    List<String> values = headers.get(name);
    return (values == null || values.isEmpty()) ? null : values.get(0);
  }

  public Map<String, List<String>> headers() {
    return headers;
  }

  public int statusCode() {
    return statusCode;
  }
}
