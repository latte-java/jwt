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

import java.util.Map;

/**
 * Strategy interface for JSON serialization and deserialization.
 *
 * <p>Implementations MUST be stateless and thread-safe: the encoder/decoder
 * may invoke {@link #serialize(Map)} / {@link #deserialize(byte[])}
 * concurrently on a single {@code JSONProcessor} instance.
 *
 * @author Daniel DeGroff
 */
public interface JSONProcessor {
  /**
   * Serialize a map to UTF-8 JSON bytes.
   *
   * @param object the map to serialize (must not be {@code null})
   * @return UTF-8 JSON bytes
   * @throws JSONProcessingException on serialization failure
   */
  byte[] serialize(Map<String, Object> object) throws JSONProcessingException;

  /**
   * Deserialize UTF-8 JSON bytes into a Map. The top-level JSON value MUST
   * be an object; top-level arrays, strings, numbers, booleans, or null MUST
   * cause {@link JSONProcessingException}. JWT payloads and headers are
   * always JSON objects per RFC 7519 §7.2, so this constraint imposes no
   * real-world limitation on the decoder.
   *
   * @param json UTF-8 JSON bytes
   * @return the parsed map (top-level JSON object)
   * @throws JSONProcessingException on malformed JSON or non-object top-level value
   */
  Map<String, Object> deserialize(byte[] json) throws JSONProcessingException;
}
