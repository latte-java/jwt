/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.lattejava.jwt;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import org.lattejava.jwt.jwks.*;
import org.testng.*;

import static org.testng.Assert.*;

/**
 * @author Daniel DeGroff
 */
public abstract class BaseJWTTest extends BaseTest {
  private static final LatteJSONProcessor JSON = new LatteJSONProcessor();

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static Map<String, Object> deepSort(Map<String, Object> response) {
    Map<String, Object> sorted = new TreeMap<>();
    response.forEach((key, value) -> {
      if (value instanceof Map) {
        sorted.put(key, deepSort((Map) value));
      } else if (value instanceof List) {
        sorted.put(key, deepSort((List) value));
      } else {
        sorted.put(key, value);
      }
    });

    return sorted;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static List<Object> deepSort(List<Object> list) {
    List<Object> sorted = new ArrayList<>();
    list.forEach(value -> {
      if (value instanceof Map) {
        sorted.add(deepSort((Map) value));
      } else if (value instanceof List) {
        sorted.add(deepSort((List) value));
      } else {
        sorted.add(value);
      }
    });

    sorted.sort(Comparator.comparing(BaseJWTTest::sortKey));
    return sorted;
  }

  @SuppressWarnings("unchecked")
  private static String sortKey(Object value) {
    if (value == null) {
      return "";
    }
    if (value instanceof Map) {
      return new String(JSON.serialize((Map<String, Object>) value));
    }
    return String.valueOf(value);
  }

  /**
   * LatteJSONProcessor only deals in {@link Map} structures. Convert the given test fixture object to a Map suitable
   * for round-trip comparison.
   */
  @SuppressWarnings("unchecked")
  private static Map<String, Object> toMap(Object object) {
    if (object instanceof JSONWebKey) {
      return new LinkedHashMap<>(((JSONWebKey) object).toSerializableMap());
    }
    if (object instanceof Map) {
      return (Map<String, Object>) object;
    }
    throw new AssertionError("BaseJWTTest.assertJSONEquals does not know how to serialize " + object.getClass());
  }

  protected void assertJSONEquals(Object object, String jsonFile) throws IOException {
    Map<String, Object> actual = toMap(object);
    Map<String, Object> expected = JSON.deserialize(Files.readAllBytes(Paths.get(jsonFile)));

    actual = deepSort(actual);
    expected = deepSort(expected);

    if (!actual.equals(expected)) {
      String actualString = new String(JSON.serialize(actual));
      String expectedString = new String(JSON.serialize(expected));
      throw new AssertionError("The actual JSON doesn't match the expected JSON output. expected [" + expectedString + "] but found [" + actualString + "]");
    }
  }

  protected void expectException(Class<? extends Exception> expected, ThrowingRunnable runnable) {
    try {
      runnable.run();
      fail("Expected [" + expected.getCanonicalName() + "] to be thrown. No Exception was thrown.");
    } catch (Exception e) {
      if (!expected.isAssignableFrom(e.getClass())) {
        fail("Expected [" + expected.getCanonicalName() + "] to be thrown. Caught this instead [" + e.getClass().getCanonicalName() + "]");
      }
    }
  }

  protected Path getPath(String fileName) {
    return Paths.get("src/test/resources/" + fileName);
  }

  protected String readFile(String fileName) {
    try {
      return new String(Files.readAllBytes(Paths.get("src/test/resources/" + fileName)));
    } catch (IOException e) {
      Assert.fail("Unexpected file I/O exception.", e);
      return null;
    }
  }

  protected interface ThrowingRunnable {
    void run() throws Exception;
  }
}
