/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.jwks;

import java.util.*;

/**
 * Package-visible JWKS-fetch result carrying the parsed keys, the HTTP status, and the response headers JWKS is
 * interested in ({@code Cache-Control}, {@code Retry-After}).
 *
 * <p>Header lookup keys are case-insensitive.</p>
 */
record JWKSResponse(List<JSONWebKey> keys, int statusCode, Map<String, String> selectedHeaders) {
  JWKSResponse {
    keys = (keys == null) ? List.of() : List.copyOf(keys);
    Map<String, String> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    if (selectedHeaders != null) {
      ci.putAll(selectedHeaders);
    }
    selectedHeaders = Collections.unmodifiableMap(ci);
  }
}
