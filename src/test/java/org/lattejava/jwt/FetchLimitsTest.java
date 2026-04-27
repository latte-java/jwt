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

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;

public class FetchLimitsTest extends BaseTest {
  @Test
  public void builder_allows_zero_redirects() {
    // Use case: zero disables redirect following -- explicitly permitted.
    FetchLimits limits = FetchLimits.builder().maxRedirects(0).build();
    assertEquals(limits.maxRedirects(), 0);
  }

  @Test
  public void builder_is_reusable() {
    FetchLimits.Builder b = FetchLimits.builder().maxResponseBytes(1000);
    FetchLimits a = b.build();
    FetchLimits c = b.maxResponseBytes(2000).build();
    assertEquals(a.maxResponseBytes(), 1000);
    assertEquals(c.maxResponseBytes(), 2000);
  }

  @Test
  public void builder_overrides_each_field() {
    FetchLimits limits = FetchLimits.builder()
        .allowCrossOriginRedirects(true)
        .allowDuplicateJSONKeys(true)
        .maxArrayElements(100)
        .maxNestingDepth(8)
        .maxNumberLength(500)
        .maxObjectMembers(50)
        .maxRedirects(7)
        .maxResponseBytes(2048)
        .build();
    assertEquals(limits.allowCrossOriginRedirects(), true);
    assertEquals(limits.allowDuplicateJSONKeys(), true);
    assertEquals(limits.maxArrayElements(), 100);
    assertEquals(limits.maxNestingDepth(), 8);
    assertEquals(limits.maxNumberLength(), 500);
    assertEquals(limits.maxObjectMembers(), 50);
    assertEquals(limits.maxRedirects(), 7);
    assertEquals(limits.maxResponseBytes(), 2048);
  }

  @Test
  public void builder_rejects_negative_redirects() {
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxRedirects(-1));
  }

  @Test
  public void builder_rejects_zero_or_negative_numeric_limits() {
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxResponseBytes(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxResponseBytes(-1));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxNestingDepth(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxNumberLength(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxObjectMembers(0));
    assertThrows(IllegalArgumentException.class, () -> FetchLimits.builder().maxArrayElements(0));
  }

  @Test
  public void defaults_match_documented_values() {
    FetchLimits d = FetchLimits.defaults();
    assertEquals(d.maxResponseBytes(), 1024 * 1024);
    assertEquals(d.maxRedirects(), 3);
    assertEquals(d.maxNestingDepth(), 16);
    assertEquals(d.maxNumberLength(), 1000);
    assertEquals(d.maxObjectMembers(), 1000);
    assertEquals(d.maxArrayElements(), 10000);
    assertFalse(d.allowDuplicateJSONKeys());
    assertFalse(d.allowCrossOriginRedirects());
  }

  @Test
  public void defaults_returns_singleton() {
    assertSame(FetchLimits.defaults(), FetchLimits.defaults());
  }
}
