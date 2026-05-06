/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;

/**
 * Strategy interface for JSON serialization and deserialization.
 *
 * <p>Implementations MUST be stateless and thread-safe: the encoder/decoder
 * may invoke {@link #serialize(Map)} / {@link #deserialize(byte[])} concurrently on a single {@code JSONProcessor}
 * instance.
 *
 * @author Daniel DeGroff
 */
public interface JSONProcessor {
  /**
   * Deserialize UTF-8 JSON bytes into a Map. The top-level JSON value MUST be an object; top-level arrays, strings,
   * numbers, booleans, or null MUST cause {@link JSONProcessingException}. JWT payloads and headers are always JSON
   * objects per RFC 7519 §7.2, so this constraint imposes no real-world limitation on the decoder.
   *
   * @param json UTF-8 JSON bytes
   * @return the parsed map (top-level JSON object)
   * @throws JSONProcessingException on malformed JSON or non-object top-level value
   */
  Map<String, Object> deserialize(byte[] json) throws JSONProcessingException;

  /**
   * Serialize a map to UTF-8 JSON bytes.
   *
   * @param object the map to serialize (must not be {@code null})
   * @return UTF-8 JSON bytes
   * @throws JSONProcessingException on serialization failure
   */
  byte[] serialize(Map<String, Object> object) throws JSONProcessingException;
}
