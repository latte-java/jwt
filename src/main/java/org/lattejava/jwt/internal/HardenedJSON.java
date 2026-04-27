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

import org.lattejava.jwt.FetchLimits;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.LatteJSONProcessor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * Internal hardened JSON parser for JWKS and OIDC discovery responses.
 * The caller supplies an {@link InputStream} that is already wrapped with
 * the per-hop response-byte cap (see {@code AbstractHTTPHelper.LimitedInputStream});
 * this method enforces only the in-memory parse-time caps.
 * {@link JSONProcessingException} is the single failure surface.
 */
public final class HardenedJSON {
  private HardenedJSON() {}

  /**
   * Read {@code is} fully and parse the bytes as a top-level JSON object
   * subject to the parser caps in {@code limits}.
   *
   * @param is     the input stream to drain; the caller retains ownership and is responsible for closing it.
   * @param limits the hardening caps to apply during parsing.
   * @return the parsed top-level JSON object.
   * @throws JSONProcessingException if the bytes do not parse as a JSON object, if any cap is exceeded,
   *     or if the input stream raises an {@link IOException} while being drained.
   */
  public static Map<String, Object> parse(InputStream is, FetchLimits limits) {
    LatteJSONProcessor processor = new LatteJSONProcessor(
        limits.maxNestingDepth(),
        limits.maxNumberLength(),
        limits.maxObjectMembers(),
        limits.maxArrayElements(),
        limits.allowDuplicateJSONKeys());
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int n;
      while ((n = is.read(buffer)) != -1) {
        out.write(buffer, 0, n);
      }
      return processor.deserialize(out.toByteArray());
    } catch (IOException e) {
      throw new JSONProcessingException("Failed to read response stream", e);
    }
  }
}
