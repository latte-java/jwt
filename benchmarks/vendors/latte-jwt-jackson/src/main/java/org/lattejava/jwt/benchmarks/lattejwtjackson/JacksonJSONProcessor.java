/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.lattejwtjackson;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.JSONProcessor;

/**
 * Jackson-backed {@link JSONProcessor} for the latte-jwt-jackson benchmark variant.
 * Mirrors the test-scope reference at {@code src/test/java/org/lattejava/jwt/jacksontest/JacksonJSONProcessor.java}.
 */
public final class JacksonJSONProcessor implements JSONProcessor {
  private final ObjectMapper mapper;

  public JacksonJSONProcessor() {
    this.mapper = new ObjectMapper();
    this.mapper.enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
    this.mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    this.mapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
  }

  @Override
  public Map<String, Object> deserialize(byte[] json) {
    try {
      return mapper.readValue(json, new TypeReference<>() {});
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
