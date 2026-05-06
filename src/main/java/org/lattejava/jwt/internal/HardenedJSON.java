/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.internal;

import java.io.*;
import java.util.*;

import org.lattejava.jwt.*;

/**
 * Hardened JSON parser for JWKS and OIDC discovery responses. Not part of the public API; module-system encapsulation
 * prevents access from outside this module (the {@code org.lattejava.jwt.internal} package is not exported in
 * {@code module-info.java}).
 *
 * <p>The caller supplies an {@link InputStream} that is already wrapped with
 * the per-hop response-byte cap; this method enforces only the in-memory parse-time caps from
 * {@link org.lattejava.jwt.FetchLimits}. {@link JSONProcessingException} is the single failure surface.</p>
 */
public final class HardenedJSON {
  private HardenedJSON() {
  }

  /**
   * Read {@code is} fully and parse the bytes as a top-level JSON object subject to the parser caps in {@code limits}.
   *
   * @param is     the input stream to drain; the caller retains ownership and is responsible for closing it.
   * @param limits the hardening caps to apply during parsing.
   * @return the parsed top-level JSON object.
   * @throws JSONProcessingException if the bytes do not parse as a JSON object, if any cap is exceeded, or if the input
   *                                 stream raises an {@link IOException} while being drained.
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
