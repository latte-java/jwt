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

import java.io.*;
import java.nio.charset.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

public class HardenedJSONTest extends BaseTest {
  @Test
  public void parse_enforces_array_element_cap() {
    // Use case: array cap from FetchLimits is honoured -- too many elements raises JSONProcessingException.
    StringBuilder sb = new StringBuilder("{\"keys\":[");
    for (int i = 0; i < 5; i++) {
      if (i > 0) sb.append(',');
      sb.append("{}");
    }
    sb.append("]}");
    FetchLimits tight = FetchLimits.builder().maxArrayElements(3).build();
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(stream(sb.toString()), tight));
  }

  @Test
  public void parse_enforces_nesting_depth_cap() {
    // Use case: nesting depth cap from FetchLimits is honoured -- too deep raises JSONProcessingException.
    String deep = "{\"a\":{\"b\":{\"c\":{\"d\":{}}}}}";
    FetchLimits tight = FetchLimits.builder().maxNestingDepth(2).build();
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(stream(deep), tight));
  }

  @Test
  public void parse_rejects_duplicate_keys_by_default() {
    // Use case: default FetchLimits disallows duplicate JSON keys.
    String dup = "{\"k\":1,\"k\":2}";
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(stream(dup), FetchLimits.defaults()));
  }

  @Test
  public void parse_returns_top_level_object() {
    // Use case: valid JSON object is parsed and values are accessible by key.
    Map<String, Object> map = HardenedJSON.parse(stream("{\"k\":\"v\",\"n\":3}"), FetchLimits.defaults());
    assertEquals(map.get("k"), "v");
    assertEquals(((Number) map.get("n")).intValue(), 3);
  }

  @Test
  public void parse_wraps_io_exception() {
    // Use case: an IOException thrown by the InputStream during drain is wrapped in JSONProcessingException.
    InputStream broken = new InputStream() {
      @Override
      public int read() throws IOException {
        throw new IOException("simulated");
      }

      @Override
      public int read(byte[] b, int off, int len) throws IOException {
        throw new IOException("simulated");
      }
    };
    assertThrows(JSONProcessingException.class, () -> HardenedJSON.parse(broken, FetchLimits.defaults()));
  }

  private ByteArrayInputStream stream(String s) {
    return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
  }
}
