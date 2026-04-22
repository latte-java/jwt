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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for {@link Header} per spec §3.
 *
 * @author The Latte Project
 */
public class HeaderTest {
  // -------------------- Builder --------------------

  @Test
  public void builder_typed_setters() {
    Header h = Header.builder().alg(Algorithm.HS256).typ("JWT").kid("k1").build();
    assertEquals(h.alg(), Algorithm.HS256);
    assertEquals(h.typ(), "JWT");
    assertEquals(h.kid(), "k1");
  }

  @Test
  public void builder_default_typ_is_JWT() {
    Header h = Header.builder().alg(Algorithm.HS256).build();
    assertEquals(h.typ(), "JWT");
  }

  @Test
  public void builder_reusable() {
    Header.Builder b = Header.builder().alg(Algorithm.HS256);
    Header h1 = b.kid("k1").build();
    Header h2 = b.kid("k2").build();
    assertEquals(h1.kid(), "k1");
    assertEquals(h2.kid(), "k2");
    assertNotEquals(h1, h2);
  }

  @Test
  public void builder_custom_parameter_accessible_via_get_and_parameters() {
    // Use case: Custom parameters accessible via get() and parameters()
    Header h = Header.builder().alg(Algorithm.HS256).parameter("custom", "value").build();
    assertEquals(h.get("custom"), "value");
    assertEquals(h.parameters().get("custom"), "value");
  }

  @Test
  public void builder_parameter_alg_routes_to_typed_setter() {
    Header h = Header.builder().parameter("alg", Algorithm.RS256).build();
    assertEquals(h.alg(), Algorithm.RS256);
  }

  @Test
  public void builder_parameter_alg_non_algorithm_throws_iae() {
    expectThrows(IllegalArgumentException.class,
        () -> Header.builder().parameter("alg", "RS256"));
  }

  @Test
  public void builder_parameter_typ_routes_to_typed_setter() {
    Header h = Header.builder().alg(Algorithm.HS256).parameter("typ", "at+JWT").build();
    assertEquals(h.typ(), "at+JWT");
  }

  @Test
  public void builder_parameter_typ_non_string_throws_iae() {
    expectThrows(IllegalArgumentException.class,
        () -> Header.builder().alg(Algorithm.HS256).parameter("typ", 42));
  }

  @Test
  public void builder_parameter_kid_routes_to_typed_setter() {
    Header h = Header.builder().alg(Algorithm.HS256).parameter("kid", "k").build();
    assertEquals(h.kid(), "k");
  }

  @Test
  public void parameters_returns_unmodifiable_view() {
    Header h = Header.builder().alg(Algorithm.HS256).build();
    expectThrows(UnsupportedOperationException.class, () -> h.parameters().put("x", "y"));
  }

  // -------------------- fromMap --------------------

  @Test
  public void fromMap_missing_alg_throws() {
    Map<String, Object> map = new LinkedHashMap<>();
    expectThrows(InvalidJWTException.class, () -> Header.fromMap(map));
  }

  @Test
  public void fromMap_alg_non_string_throws() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", 42);
    expectThrows(InvalidJWTException.class, () -> Header.fromMap(map));
  }

  @Test
  public void fromMap_basic_alg_typ_kid() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("typ", "JWT");
    map.put("kid", "k1");
    Header h = Header.fromMap(map);
    assertEquals(h.alg(), Algorithm.HS256);
    assertEquals(h.typ(), "JWT");
    assertEquals(h.kid(), "k1");
  }

  @Test
  public void fromMap_typ_non_string_throws() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("typ", 42);
    expectThrows(InvalidJWTException.class, () -> Header.fromMap(map));
  }

  @Test
  public void fromMap_x5c_non_array_throws() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("x5c", "not-an-array");
    expectThrows(InvalidJWTException.class, () -> Header.fromMap(map));
  }

  @Test
  public void fromMap_x5c_with_non_string_element_throws() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("x5c", Arrays.asList("cert1", 42));
    expectThrows(InvalidJWTException.class, () -> Header.fromMap(map));
  }

  @Test
  public void fromMap_unknown_parameter_passes_through() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("foo", "bar");
    Header h = Header.fromMap(map);
    assertEquals(h.get("foo"), "bar");
  }

  // -------------------- crit structural validation --------------------

  @DataProvider(name = "critMalformed")
  public Object[][] critMalformed() {
    return new Object[][] {
        // Not an array
        {"not-an-array"},
        {42},
        {new LinkedHashMap<>()},
        // Non-string element
        {Arrays.asList("ok", 42)},
        {Arrays.asList((Object) null)},
        // Empty-string element
        {Arrays.asList("ok", "")},
        {Collections.singletonList("")},
        // Duplicate entry
        {Arrays.asList("ext.foo", "ext.foo")},
        // Registered RFC 7515 header parameter names
        {Collections.singletonList("alg")},
        {Collections.singletonList("typ")},
        {Collections.singletonList("kid")},
        {Collections.singletonList("x5c")},
        {Collections.singletonList("crit")},
        {Collections.singletonList("jku")},
        {Collections.singletonList("jwk")},
        {Collections.singletonList("x5u")},
        {Collections.singletonList("x5t")},
        {Collections.singletonList("x5t#S256")},
        {Collections.singletonList("cty")},
    };
  }

  @Test(dataProvider = "critMalformed")
  public void fromMap_crit_malformed_rejected(Object critValue) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("crit", critValue);
    expectThrows(InvalidJWTException.class, () -> Header.fromMap(map));
  }

  @Test
  public void fromMap_crit_empty_array_accepted() {
    // Spec §3 / §16: empty crit accepted.
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("crit", Collections.emptyList());
    Header h = Header.fromMap(map);
    assertEquals(h.get("crit"), Collections.emptyList());
  }

  @Test
  public void fromMap_crit_with_extension_names_accepted_structurally() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("alg", "HS256");
    map.put("crit", Arrays.asList("http://example.com/ext", "exp.foo"));
    Header h = Header.fromMap(map);
    assertEquals(h.get("crit"), Arrays.asList("http://example.com/ext", "exp.foo"));
  }

  // -------------------- equals / hashCode / toString --------------------

  @Test
  public void equals_includes_all_parameters() {
    Header a = Header.builder().alg(Algorithm.HS256).kid("k").parameter("x", "y").build();
    Header b = Header.builder().alg(Algorithm.HS256).kid("k").parameter("x", "y").build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  public void equals_differs_when_custom_parameter_differs() {
    Header a = Header.builder().alg(Algorithm.HS256).parameter("x", "1").build();
    Header b = Header.builder().alg(Algorithm.HS256).parameter("x", "2").build();
    assertNotEquals(a, b);
  }

  @Test
  public void toString_produces_json_via_latte_processor() {
    Header h = Header.builder().alg(Algorithm.HS256).kid("k").build();
    String s = h.toString();
    assertNotNull(s);
    assertTrue(s.contains("\"alg\""));
    assertTrue(s.contains("\"HS256\""));
    assertTrue(s.contains("\"kid\""));
  }

  @Test
  public void toSerializableMap_emits_alg_as_string() {
    Header h = Header.builder().alg(Algorithm.HS256).build();
    assertEquals(h.toSerializableMap().get("alg"), "HS256");
  }

  @Test
  public void getString_on_missing_returns_null() {
    Header h = Header.builder().alg(Algorithm.HS256).build();
    assertNull(h.getString("missing"));
  }
}
