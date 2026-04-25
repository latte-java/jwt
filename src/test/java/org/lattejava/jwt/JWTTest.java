/*
 * Copyright (c) 2016-2026, FusionAuth, All Rights Reserved
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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;
import static org.testng.Assert.fail;

/**
 * Tests for {@link JWT}.
 *
 * @author Daniel DeGroff
 */
public class JWTTest {
  // -------------------- Builder --------------------

  @Test
  public void builder_reusable_produces_independent_instances() {
    // Use case: Builder reusability -- build(), modify, build() again produces independent instances.
    JWT.Builder b = JWT.builder();
    JWT a = b.subject("a").build();
    JWT bee = b.subject("b").build();
    assertEquals(a.subject(), "a");
    assertEquals(bee.subject(), "b");
    assertNotEquals(a, bee);
  }

  @Test
  public void builder_claim_routes_exp_long_to_instant() {
    // Use case: claim("exp", 1700000000L) -> Instant.ofEpochSecond(1700000000)
    JWT jwt = JWT.builder().claim("exp", 1_700_000_000L).build();
    assertEquals(jwt.expiresAt(), Instant.ofEpochSecond(1_700_000_000L));
  }

  @Test
  public void builder_claim_routes_exp_instant_directly() {
    Instant inst = Instant.ofEpochSecond(1_700_000_000L);
    JWT jwt = JWT.builder().claim("exp", inst).build();
    assertEquals(jwt.expiresAt(), inst);
  }

  @Test
  public void builder_claim_routes_exp_zoned_date_time() {
    ZonedDateTime z = ZonedDateTime.of(2030, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
    JWT jwt = JWT.builder().claim("exp", z).build();
    assertEquals(jwt.expiresAt(), z.toInstant());
  }

  @Test
  public void builder_claim_exp_string_throws_iae() {
    // Use case: claim("exp", "not-a-number") -> IllegalArgumentException
    expectThrows(IllegalArgumentException.class, () -> JWT.builder().claim("exp", "not-a-number"));
  }

  @Test
  public void builder_claim_iss_routes_to_iss_field() {
    JWT jwt = JWT.builder().claim("iss", "alice").build();
    assertEquals(jwt.issuer(), "alice");
  }

  @Test
  public void builder_claim_iss_non_string_throws_iae() {
    expectThrows(IllegalArgumentException.class, () -> JWT.builder().claim("iss", 42));
  }

  @Test
  public void builder_claim_custom_stored_in_custom_claims() {
    // Use case: claim("custom", v) -> stored in customClaims, retrievable via getObject
    JWT jwt = JWT.builder().claim("foo", "bar").build();
    assertEquals(jwt.getObject("foo"), "bar");
  }

  @Test
  public void builder_null_claim_value_omitted() {
    // Use case: Null claim values are omitted from build result
    JWT jwt = JWT.builder().claim("foo", null).build();
    assertNull(jwt.getObject("foo"));
    assertFalse(jwt.claims().containsKey("foo"));
  }

  @Test
  public void builder_audience_string_defaults_to_always_array() {
    // Use case: single-audience builder call defaults to ALWAYS_ARRAY so the serialized
    // form does not vary with which audience overload the caller happens to use.
    JWT jwt = JWT.builder().audience("svc").build();
    assertEquals(jwt.audience(), Collections.singletonList("svc"));
    Assert.assertEquals(jwt.audienceSerialization(), AudienceSerialization.ALWAYS_ARRAY);
    assertEquals(jwt.toSerializableMap().get("aud"), Collections.singletonList("svc"));
  }

  @Test
  public void builder_audience_list_defaults_to_always_array() {
    JWT jwt = JWT.builder().audience(Arrays.asList("a", "b")).build();
    assertEquals(jwt.audience(), Arrays.asList("a", "b"));
    assertEquals(jwt.audienceSerialization(), AudienceSerialization.ALWAYS_ARRAY);
  }

  @Test
  public void builder_claim_aud_string_defaults_to_always_array() {
    JWT jwt = JWT.builder().claim("aud", "svc").build();
    assertEquals(jwt.audience(), Collections.singletonList("svc"));
    assertEquals(jwt.audienceSerialization(), AudienceSerialization.ALWAYS_ARRAY);
    assertEquals(jwt.toSerializableMap().get("aud"), Collections.singletonList("svc"));
  }

  @Test
  public void builder_claim_aud_list_defaults_to_always_array() {
    JWT jwt = JWT.builder().claim("aud", Arrays.asList("a", "b")).build();
    assertEquals(jwt.audienceSerialization(), AudienceSerialization.ALWAYS_ARRAY);
  }

  @Test
  public void builder_audience_serialization_opt_in_string_when_single() {
    // Use case: caller explicitly opts in to STRING_WHEN_SINGLE for a peer that expects
    // the single-string form. With a 1-element audience, serialization emits a string.
    JWT jwt = JWT.builder()
        .audience("svc")
        .audienceSerialization(AudienceSerialization.STRING_WHEN_SINGLE)
        .build();
    assertEquals(jwt.audienceSerialization(), AudienceSerialization.STRING_WHEN_SINGLE);
    assertEquals(jwt.toSerializableMap().get("aud"), "svc");
  }

  @Test
  public void builder_audience_serialization_string_when_single_falls_back_to_array_for_many() {
    // Use case: STRING_WHEN_SINGLE with 2+ audiences still emits a JSON array -- the opt-in
    // is "string when the list has one value", not a hard requirement.
    JWT jwt = JWT.builder()
        .audience(Arrays.asList("a", "b"))
        .audienceSerialization(AudienceSerialization.STRING_WHEN_SINGLE)
        .build();
    assertEquals(jwt.toSerializableMap().get("aud"), Arrays.asList("a", "b"));
  }

  @Test
  public void builder_claim_aud_invalid_type_throws_iae() {
    expectThrows(IllegalArgumentException.class, () -> JWT.builder().claim("aud", 42));
  }

  @Test
  public void builder_claim_aud_list_with_non_string_element_throws_iae() {
    expectThrows(IllegalArgumentException.class, () -> JWT.builder().claim("aud", Arrays.asList("a", 42)));
  }

  // -------------------- fromMap shape validation --------------------

  @DataProvider(name = "fromMapMalformed")
  public Object[][] fromMapMalformed() {
    return new Object[][] {
        // Time claim with non-numeric value
        {"exp", "1700000000"},
        {"nbf", "1700000000"},
        {"iat", "abc"},
        // String claims with non-string value
        {"iss", 42},
        {"sub", true},
        {"jti", Arrays.asList("x")},
        // Aud with object
        {"aud", new LinkedHashMap<String, Object>() {{ put("foo", 1); }}},
        // Aud with mixed-type array
        {"aud", Arrays.asList("a", 42)},
        // Aud with number
        {"aud", 42},
    };
  }

  @Test(dataProvider = "fromMapMalformed")
  public void fromMap_malformed_shape_throws(String claim, Object value) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put(claim, value);
    expectThrows(InvalidJWTException.class, () -> JWT.fromMap(map, null));
  }

  @DataProvider(name = "timeClaimBoundsRejected")
  public Object[][] timeClaimBoundsRejected() {
    BigInteger overMax = BigInteger.valueOf(Instant.MAX.getEpochSecond()).add(BigInteger.ONE);
    BigInteger underMin = BigInteger.valueOf(Instant.MIN.getEpochSecond()).subtract(BigInteger.ONE);
    BigDecimal huge = new BigDecimal("1e30");
    return new Object[][] {
        {overMax},
        {underMin},
        {huge},
        {new BigDecimal("-1e30")},
    };
  }

  @Test(dataProvider = "timeClaimBoundsRejected")
  public void fromMap_time_claim_outside_instant_bounds_rejected(Number value) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("exp", value);
    expectThrows(InvalidJWTException.class, () -> JWT.fromMap(map, null));
  }

  @Test
  public void fromMap_time_claim_at_instant_max_boundary_accepted() {
    // Use case: fromMap with exp = Instant.MAX.getEpochSecond() -> accepted (boundary)
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("exp", BigInteger.valueOf(Instant.MAX.getEpochSecond()));
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.expiresAt().getEpochSecond(), Instant.MAX.getEpochSecond());
  }

  @Test
  public void fromMap_time_claim_long_accepted() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("exp", 1_700_000_000L);
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.expiresAt(), Instant.ofEpochSecond(1_700_000_000L));
  }

  @Test
  public void fromMap_time_claim_integer_accepted() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("exp", 1_700_000_000);
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.expiresAt(), Instant.ofEpochSecond(1_700_000_000L));
  }

  @Test
  public void fromMap_time_claim_bigdecimal_truncates_fractional() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("exp", new BigDecimal("1700000000.5"));
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.expiresAt(), Instant.ofEpochSecond(1_700_000_000L));
  }

  @Test
  public void fromMap_aud_string_preserves_wire_form() {
    // Use case: fromMap with aud = "foo" -> audience() == ["foo"], serialization STRING_WHEN_SINGLE
    // so a decode/encode round-trip emits the same single-string form it consumed.
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("aud", "foo");
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.audience(), Collections.singletonList("foo"));
    assertEquals(jwt.audienceSerialization(), AudienceSerialization.STRING_WHEN_SINGLE);
    // Round-trip: serializes back as string
    assertEquals(jwt.toSerializableMap().get("aud"), "foo");
  }

  @Test
  public void fromMap_aud_array_records_always_array() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("aud", Arrays.asList("foo", "bar"));
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.audience(), Arrays.asList("foo", "bar"));
    assertEquals(jwt.audienceSerialization(), AudienceSerialization.ALWAYS_ARRAY);
    Object out = jwt.toSerializableMap().get("aud");
    assertTrue(out instanceof List);
    assertEquals(out, Arrays.asList("foo", "bar"));
  }

  @Test
  public void fromMap_unknown_claims_pass_through() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("nonce", "xyz");
    JWT jwt = JWT.fromMap(map, null);
    assertEquals(jwt.getString("nonce"), "xyz");
  }

  @Test
  public void fromMap_associates_header() {
    Header header = Header.builder().alg(Algorithm.HS256).build();
    JWT jwt = JWT.fromMap(new LinkedHashMap<>(), header);
    assertSame(jwt.header(), header);
  }

  // -------------------- toSerializableMap --------------------

  @Test
  public void toSerializableMap_writes_instants_as_epoch_seconds() {
    JWT jwt = JWT.builder().expiresAt(Instant.ofEpochSecond(1_700_000_000L)).build();
    Object exp = jwt.toSerializableMap().get("exp");
    assertEquals(exp, 1_700_000_000L);
  }

  @Test
  public void toSerializableMap_drops_null_claims() {
    JWT jwt = JWT.builder().subject("sub-only").build();
    Map<String, Object> out = jwt.toSerializableMap();
    assertEquals(out.size(), 1);
    assertEquals(out.get("sub"), "sub-only");
  }

  @Test
  public void toSerializableMap_emits_registered_then_custom() {
    JWT jwt = JWT.builder()
        .issuer("iss-x")
        .claim("custom", "v")
        .subject("sub-x")
        .build();
    List<String> keys = new java.util.ArrayList<>(jwt.toSerializableMap().keySet());
    assertEquals(keys.get(0), "iss");
    assertEquals(keys.get(1), "sub");
    assertEquals(keys.get(2), "custom");
  }

  @Test
  public void toSerializableMap_returns_fresh_mutable_map_per_call() {
    // Use case: contract is a freshly allocated mutable map -- callers MUST NOT mutate it,
    // but mutating it cannot leak back into the JWT and a second call returns a different map.
    JWT jwt = JWT.builder().subject("a").build();
    Map<String, Object> first = jwt.toSerializableMap();
    first.put("x", "y");
    Map<String, Object> second = jwt.toSerializableMap();
    assertNotSame(first, second);
    assertNull(second.get("x"));
    assertEquals(jwt.subject(), "a");
  }

  // -------------------- accessors --------------------

  @Test
  public void getInteger_from_biginteger_narrows() {
    JWT jwt = JWT.builder().claim("n", BigInteger.valueOf(42)).build();
    assertEquals(jwt.getInteger("n"), Integer.valueOf(42));
  }

  @Test
  public void getFloat_from_bigdecimal_narrows() {
    JWT jwt = JWT.builder().claim("n", new BigDecimal("1.5")).build();
    assertEquals(jwt.getFloat("n"), Float.valueOf(1.5f));
  }

  @Test
  public void getNumber_returns_underlying_biginteger() {
    BigInteger big = BigInteger.valueOf(42);
    JWT jwt = JWT.builder().claim("n", big).build();
    assertSame(jwt.getNumber("n"), big);
  }

  @Test
  public void getObject_returns_raw_value() {
    Object payload = new java.util.ArrayList<>();
    JWT jwt = JWT.builder().claim("data", payload).build();
    assertSame(jwt.getObject("data"), payload);
  }

  @Test
  public void getList_typed_returns_typed_list_when_homogeneous() {
    JWT jwt = JWT.builder().claim("items", Arrays.asList("a", "b")).build();
    List<String> typed = jwt.getList("items", String.class);
    assertEquals(typed, Arrays.asList("a", "b"));
  }

  @Test
  public void getList_typed_throws_on_mixed_types() {
    JWT jwt = JWT.builder().claim("items", Arrays.asList("a", 42)).build();
    expectThrows(ClassCastException.class, () -> jwt.getList("items", String.class));
  }

  @Test
  public void getList_untyped_returns_list_object() {
    JWT jwt = JWT.builder().claim("items", Arrays.asList("a", 42)).build();
    List<Object> raw = jwt.getList("items");
    assertEquals(raw.size(), 2);
  }

  @Test
  public void accessor_for_missing_claim_returns_null() {
    JWT jwt = JWT.builder().build();
    assertNull(jwt.getString("nope"));
    assertNull(jwt.getInteger("nope"));
    assertNull(jwt.getList("nope"));
    assertNull(jwt.getList("nope", String.class));
    assertNull(jwt.getObject("nope"));
  }

  // -------------------- audience helpers --------------------

  @Test
  public void hasAudience_true_when_present() {
    JWT jwt = JWT.builder().audience(Arrays.asList("a", "b")).build();
    assertTrue(jwt.hasAudience("a"));
  }

  @Test
  public void hasAudience_false_when_absent() {
    JWT jwt = JWT.builder().audience(Arrays.asList("a", "b")).build();
    assertFalse(jwt.hasAudience("c"));
  }

  @Test
  public void hasAudience_false_when_audience_empty() {
    JWT jwt = JWT.builder().build();
    assertFalse(jwt.hasAudience("a"));
  }

  @Test
  public void hasAudience_null_input_returns_false() {
    JWT jwt = JWT.builder().audience("a").build();
    assertFalse(jwt.hasAudience(null));
  }

  @Test
  public void audience_returns_unmodifiable_list() {
    JWT jwt = JWT.builder().audience(Arrays.asList("a", "b")).build();
    expectThrows(UnsupportedOperationException.class, () -> jwt.audience().add("x"));
  }

  // -------------------- claims map --------------------

  @Test
  public void claims_returns_unmodifiable_map() {
    JWT jwt = JWT.builder().subject("s").build();
    expectThrows(UnsupportedOperationException.class, () -> jwt.claims().put("x", "y"));
  }

  @Test
  public void claims_carries_audience_as_list_regardless_of_wire_form() {
    JWT jwt = JWT.builder().audience("svc").build();
    Object aud = jwt.claims().get("aud");
    assertTrue(aud instanceof List);
    assertEquals(aud, Collections.singletonList("svc"));
  }

  // -------------------- equals / claimsEquals --------------------

  @Test
  public void equals_same_claims_same_header_equal() {
    Header h = Header.builder().alg(Algorithm.HS256).kid("k").build();
    JWT a = new JWTBuilderHack().subject("s").header(h).build();
    JWT b = new JWTBuilderHack().subject("s").header(h).build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  public void equals_same_claims_different_header_NOT_equal() {
    Header h1 = Header.builder().alg(Algorithm.HS256).build();
    Header h2 = Header.builder().alg(Algorithm.RS256).build();
    JWT a = new JWTBuilderHack().subject("s").header(h1).build();
    JWT b = new JWTBuilderHack().subject("s").header(h2).build();
    assertNotEquals(a, b);
  }

  @Test
  public void equals_builder_no_header_vs_decoded_with_header_NOT_equal() {
    Header h = Header.builder().alg(Algorithm.HS256).build();
    JWT a = JWT.builder().subject("s").build();
    JWT b = new JWTBuilderHack().subject("s").header(h).build();
    assertNotEquals(a, b);
  }

  @Test
  public void claimsEquals_ignores_header() {
    // Use case: claimsEquals returns true when claim fields match, regardless of Header
    Header h = Header.builder().alg(Algorithm.HS256).build();
    JWT a = JWT.builder().subject("s").build();
    JWT b = new JWTBuilderHack().subject("s").header(h).build();
    assertTrue(a.claimsEquals(b));
  }

  @Test
  public void claimsEquals_false_when_claim_differs() {
    JWT a = JWT.builder().subject("a").build();
    JWT b = JWT.builder().subject("b").build();
    assertFalse(a.claimsEquals(b));
  }

  @Test
  public void claimsEquals_ignores_audience_serialization() {
    // Use case: claimsEquals with aud=["foo"] STRING_WHEN_SINGLE vs aud=["foo"] ALWAYS_ARRAY -> true.
    // AudienceSerialization mode is intentionally ignored by claimsEquals.
    JWT stringForm = JWT.builder()
        .audience("foo")
        .audienceSerialization(AudienceSerialization.STRING_WHEN_SINGLE)
        .build();
    JWT arrayForm = JWT.builder().audience("foo").build();
    assertTrue(stringForm.claimsEquals(arrayForm));
    // Strict equals DOES still differ on serialization mode:
    assertNotEquals(stringForm, arrayForm);
  }

  // -------------------- toString --------------------

  @Test
  public void toString_produces_json_via_latte_processor() {
    JWT jwt = JWT.builder().subject("alice").issuer("iss-x").build();
    String out = jwt.toString();
    assertNotNull(out);
    assertTrue(out.contains("\"sub\""));
    assertTrue(out.contains("alice"));
    assertTrue(out.contains("\"iss\""));
  }

  // -------------------- isExpired / isUnavailableForProcessing --------------------

  @Test
  public void isExpired_true_when_exp_before_now() {
    JWT jwt = JWT.builder().expiresAt(Instant.ofEpochSecond(1_000)).build();
    assertTrue(jwt.isExpired(Instant.ofEpochSecond(2_000)));
  }

  @Test
  public void isExpired_true_when_exp_equals_now() {
    // RFC 7519 §4.1.4: "on or after which the JWT MUST NOT be accepted" --
    // the boundary is expired.
    JWT jwt = JWT.builder().expiresAt(Instant.ofEpochSecond(1_000)).build();
    assertTrue(jwt.isExpired(Instant.ofEpochSecond(1_000)));
  }

  @Test
  public void isExpired_false_when_now_before_exp() {
    JWT jwt = JWT.builder().expiresAt(Instant.ofEpochSecond(2_000)).build();
    assertFalse(jwt.isExpired(Instant.ofEpochSecond(1_000)));
  }

  @Test
  public void isExpired_false_when_no_exp() {
    JWT jwt = JWT.builder().build();
    assertFalse(jwt.isExpired());
  }

  @Test
  public void isUnavailableForProcessing_true_when_nbf_after_now() {
    JWT jwt = JWT.builder().notBefore(Instant.ofEpochSecond(2_000)).build();
    assertTrue(jwt.isUnavailableForProcessing(Instant.ofEpochSecond(1_000)));
  }

  // -------------------- helper for header injection in tests --------------------

  /**
   * The public Builder does not expose a header() setter (header is populated
   * by the decoder). For equality tests we go through {@link JWT#fromMap} to
   * obtain a JWT with a populated header.
   */
  private static final class JWTBuilderHack {
    private final Map<String, Object> claims = new LinkedHashMap<>();

    private Header header;

    JWTBuilderHack subject(String s) {
      claims.put("sub", s);
      return this;
    }

    JWTBuilderHack header(Header h) {
      this.header = h;
      return this;
    }

    JWT build() {
      return JWT.fromMap(claims, header);
    }
  }

  // Silence unused-import warnings on platforms with strict lint:
  @SuppressWarnings("unused")
  private static void __unused() {
    fail();
  }
}
