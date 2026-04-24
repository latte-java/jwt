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

package org.lattejava.jwt.internal;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Internal RFC 7638-compliant JSON writer for JWK thumbprint computation.
 *
 * <p>Produces canonical JSON: keys lex-sorted by Unicode code-point, no
 * whitespace, UTF-8 bytes. Supports only the primitive value types that
 * appear in RFC 7638 §3.2 / RFC 8037 §2 thumbprint inputs:
 * {@link String}, {@link Number} (rendered as the appropriate JSON
 * numeric form), {@link Boolean}, and {@code null}. Any other value type
 * (including nested {@link Map} or {@link java.util.List}) causes
 * {@link IllegalArgumentException}.
 *
 * <p>Package-private. Never exposed via public API so thumbprint canonicalization
 * cannot be influenced by a user-supplied {@link JSONProcessor}.
 *
 * @author Daniel DeGroff
 */
final class CanonicalJSONWriter {

  private CanonicalJSONWriter() {
  }

  /**
   * Writes the canonical JSON byte representation of {@code input}.
   *
   * @param input the map to canonicalize (must not be {@code null})
   * @return canonical UTF-8 JSON bytes
   * @throws IllegalArgumentException if {@code input} is {@code null} or
   *                                  contains an unsupported value type
   */
  static byte[] write(Map<String, Object> input) {
    if (input == null) {
      throw new IllegalArgumentException("Input map is null");
    }
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    List<String> keys = new ArrayList<>(input.keySet());
    // Lex order by Unicode code point. String.compareTo on Java strings
    // compares UTF-16 char-by-char; for any non-supplementary characters
    // this matches code-point ordering. For supplementary code points (which
    // do not appear in the JWK thumbprint key set), surrogate-pair UTF-16
    // ordering coincides with code-point ordering by construction.
    keys.sort(Comparator.naturalOrder());
    boolean first = true;
    for (String key : keys) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      writeString(sb, key);
      sb.append(':');
      writeValue(sb, input.get(key));
    }
    sb.append('}');
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  private static void writeValue(StringBuilder sb, Object v) {
    if (v == null) {
      sb.append("null");
    } else if (v instanceof String s) {
      writeString(sb, s);
    } else if (v instanceof Boolean b) {
      sb.append(b ? "true" : "false");
    } else if (v instanceof BigDecimal bd) {
      sb.append(bd.toPlainString());
    } else if (v instanceof Integer || v instanceof Long || v instanceof Short
        || v instanceof Byte || v instanceof BigInteger) {
      sb.append(v.toString());
    } else if (v instanceof Float || v instanceof Double) {
      double d = ((Number) v).doubleValue();
      if (Double.isNaN(d) || Double.isInfinite(d)) {
        throw new IllegalArgumentException("Non-finite number [" + v + "]");
      }
      sb.append(v.toString());
    } else {
      throw new IllegalArgumentException(
          "Unsupported value type for canonical JSON [" + v.getClass().getName() + "]");
    }
  }

  private static void writeString(StringBuilder sb, String s) {
    sb.append('"');
    int len = s.length();
    for (int i = 0; i < len; i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':  sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b"); break;
        case '\f': sb.append("\\f"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
      }
    }
    sb.append('"');
  }
}
