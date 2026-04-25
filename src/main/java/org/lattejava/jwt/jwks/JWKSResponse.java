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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Package-visible JWKS-fetch result carrying the parsed keys, the HTTP
 * status, and the response headers JWKSource is interested in
 * ({@code Cache-Control}, {@code Retry-After}).
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
