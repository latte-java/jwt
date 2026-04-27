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

package org.lattejava.jwt.jacksontest;

import java.io.*;
import java.util.*;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.core.type.*;
import com.fasterxml.jackson.databind.*;
import org.lattejava.jwt.*;

/**
 * Test-scope reference {@link JSONProcessor} backed by Jackson. Used by the cross-processor compatibility tests to
 * prove that a JWT encoded with one processor decodes correctly with another, including BigInteger/BigDecimal numeric
 * round-trips.
 *
 * <p>This class lives under {@code src/test/java} on purpose -- the production
 * library is zero-dependency. After CP11 the Jackson dependency moves to test-scope and only this class (and the
 * cross-processor test) depend on it.</p>
 *
 * @author Daniel DeGroff
 */
public class JacksonJSONProcessor implements JSONProcessor {
  private final ObjectMapper mapper;

  public JacksonJSONProcessor() {
    this.mapper = new ObjectMapper();
    // Preserve BigInteger / BigDecimal -- tests assert that values larger than
    // Long.MAX_VALUE round-trip without narrowing.
    this.mapper.enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
    this.mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    this.mapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
  }

  @Override
  public Map<String, Object> deserialize(byte[] json) {
    try {
      return mapper.readValue(json, new TypeReference<>() {
      });
    } catch (IOException e) {
      throw new JSONProcessingException("JSON deserialization failed", e);
    }
  }

  @Override
  public byte[] serialize(Map<String, Object> object) {
    try {
      return mapper.writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new JSONProcessingException("JSON serialization failed", e);
    }
  }
}
