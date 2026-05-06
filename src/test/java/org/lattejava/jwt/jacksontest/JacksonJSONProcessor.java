/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
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
