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

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.KeyType;
import org.lattejava.jwt.LatteJSONProcessor;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Direct contract tests for {@link JSONWebKey}:
 *
 * <ul>
 *   <li>{@link JSONWebKey#toString()} <em>always</em> redacts d/dp/dq/p/q/qi.</li>
 *   <li>{@link JSONWebKey#toPublicJSONWebKey()} returns a brand-new instance
 *       with private key material removed.</li>
 *   <li>The Java field {@code x5tS256} maps to/from the wire-form key
 *       {@code "x5t#S256"} (RFC 7517 §4.9).</li>
 *   <li>{@code fromMap} understands {@code key_ops} (array of strings) and
 *       {@code x5u} as typed parameters.</li>
 *   <li>{@code Builder.parameter(name, value)} rejects registered parameter names.</li>
 *   <li>JWKS-style mixed-type lists round-trip through {@code fromMap}.</li>
 * </ul>
 *
 * @author Daniel DeGroff
 */
public class JSONWebKeyTest {
  // ---------- toString redaction ----------

  @Test
  public void toString_redacts_populated_private_fields() {
    // Use case: toString redacts populated private fields to "***"
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .kid("rsa-1")
        .n("AQAB")
        .e("AQAB")
        .d("SECRET-D")
        .dp("SECRET-DP")
        .dq("SECRET-DQ")
        .p("SECRET-P")
        .q("SECRET-Q")
        .qi("SECRET-QI")
        .build();

    String s = k.toString();
    for (String secret : new String[] {"SECRET-D", "SECRET-DP", "SECRET-DQ", "SECRET-P", "SECRET-Q", "SECRET-QI"}) {
      assertFalse(s.contains(secret), "toString leaked private material: " + secret + " in: " + s);
    }
    // Each redacted field must appear as "***" in the rendered map.
    assertTrue(s.contains("\"d\":\"***\""), s);
    assertTrue(s.contains("\"dp\":\"***\""), s);
    assertTrue(s.contains("\"dq\":\"***\""), s);
    assertTrue(s.contains("\"p\":\"***\""), s);
    assertTrue(s.contains("\"q\":\"***\""), s);
    assertTrue(s.contains("\"qi\":\"***\""), s);
    // Public fields are still present verbatim.
    assertTrue(s.contains("\"n\":\"AQAB\""), s);
    assertTrue(s.contains("\"e\":\"AQAB\""), s);
    assertTrue(s.contains("\"kid\":\"rsa-1\""), s);
  }

  @Test
  public void toString_does_not_materialize_absent_private_fields() {
    // Use case: toString only redacts private fields that are actually present;
    // absent private fields stay absent rather than appearing as "***".
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("AQAB")
        .e("AQAB")
        .build();
    // d, dp, dq, p, q, qi all null

    String s = k.toString();
    assertFalse(s.contains("\"d\""), s);
    assertFalse(s.contains("\"dp\""), s);
    assertFalse(s.contains("\"dq\""), s);
    assertFalse(s.contains("\"p\""), s);
    assertFalse(s.contains("\"q\""), s);
    assertFalse(s.contains("\"qi\""), s);
    assertFalse(s.contains("***"), s);
  }

  @Test
  public void toJSON_does_not_redact_private_fields() {
    // Use case: toJSON returns the full content (no redaction)
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("AQAB")
        .e("AQAB")
        .d("PRIVATE-D")
        .p("PRIVATE-P")
        .build();

    String j = k.toJSON();
    assertTrue(j.contains("\"d\":\"PRIVATE-D\""), j);
    assertTrue(j.contains("\"p\":\"PRIVATE-P\""), j);
    assertFalse(j.contains("***"), j);
  }

  // ---------- toPublicJSONWebKey ----------

  @Test
  public void toPublicJSONWebKey_rsa_strips_private_material() {
    // Use case: toPublicJSONWebKey for RSA strips d, dp, dq, p, q, qi
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .alg(Algorithm.RS256)
        .kid("rsa-1")
        .use("sig")
        .n("AQAB")
        .e("AQAB")
        .d("D")
        .dp("DP")
        .dq("DQ")
        .p("P")
        .q("Q")
        .qi("QI")
        .build();

    JSONWebKey pub = k.toPublicJSONWebKey();
    assertNotSame(pub, k);
    assertNull(pub.d());
    assertNull(pub.dp());
    assertNull(pub.dq());
    assertNull(pub.p());
    assertNull(pub.q());
    assertNull(pub.qi());
    // Public material preserved.
    assertEquals(pub.kty(), KeyType.RSA);
    assertEquals(pub.alg(), Algorithm.RS256);
    assertEquals(pub.kid(), "rsa-1");
    assertEquals(pub.use(), "sig");
    assertEquals(pub.n(), "AQAB");
    assertEquals(pub.e(), "AQAB");

    // Source unchanged.
    assertEquals(k.d(), "D");
    assertEquals(k.p(), "P");
  }

  @Test
  public void toPublicJSONWebKey_ec_strips_d_keeps_xy() {
    // Use case: toPublicJSONWebKey for EC strips d but keeps x, y, crv
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.EC)
        .alg(Algorithm.ES256)
        .crv("P-256")
        .x("X-COORD")
        .y("Y-COORD")
        .d("EC-PRIVATE")
        .build();

    JSONWebKey pub = k.toPublicJSONWebKey();
    assertNull(pub.d());
    assertEquals(pub.x(), "X-COORD");
    assertEquals(pub.y(), "Y-COORD");
    assertEquals(pub.crv(), "P-256");
    assertEquals(pub.kty(), KeyType.EC);
  }

  @Test
  public void toPublicJSONWebKey_okp_strips_d_keeps_x() {
    // Use case: toPublicJSONWebKey for OKP (Ed25519) strips d keeps x, crv
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.OKP)
        .alg(Algorithm.Ed25519)
        .crv("Ed25519")
        .x("OKP-X")
        .d("OKP-PRIVATE")
        .build();

    JSONWebKey pub = k.toPublicJSONWebKey();
    assertNull(pub.d());
    assertEquals(pub.x(), "OKP-X");
    assertEquals(pub.crv(), "Ed25519");
    assertEquals(pub.kty(), KeyType.OKP);
  }

  @Test
  public void toPublicJSONWebKey_public_only_returns_distinct_copy() {
    // Use case: toPublicJSONWebKey on an already-public key is a no-op (still returns a new instance)
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("AQAB")
        .e("AQAB")
        .build();

    JSONWebKey pub = k.toPublicJSONWebKey();
    assertNotSame(pub, k);
    assertEquals(pub, k);
  }

  @Test
  public void toPublicJSONWebKey_preserves_metadata_fields() {
    // Use case: toPublicJSONWebKey carries x5c, x5t, x5t#S256, x5u, key_ops, use
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("AQAB")
        .e("AQAB")
        .use("sig")
        .keyOps(Arrays.asList("verify"))
        .x5u("https://example.test/cert")
        .x5c(Arrays.asList("MIIB..."))
        .x5t("thumb-sha1")
        .x5tS256("thumb-sha256")
        .build();

    JSONWebKey pub = k.toPublicJSONWebKey();
    assertEquals(pub.use(), "sig");
    assertEquals(pub.key_ops(), Arrays.asList("verify"));
    assertEquals(pub.x5u(), "https://example.test/cert");
    assertEquals(pub.x5c(), Arrays.asList("MIIB..."));
    assertEquals(pub.x5t(), "thumb-sha1");
    assertEquals(pub.x5tS256(), "thumb-sha256");
  }

  // ---------- x5t#S256 wire-form mapping ----------

  @Test
  public void fromMap_reads_x5t_S256_wire_key() {
    // Use case: fromMap reads "x5t#S256" into the x5tS256 field
    Map<String, Object> wire = new LinkedHashMap<>();
    wire.put("kty", "RSA");
    wire.put("n", "AQAB");
    wire.put("e", "AQAB");
    wire.put("x5t#S256", "abc123");

    JSONWebKey k = JSONWebKey.fromMap(wire);
    assertEquals(k.x5tS256(), "abc123");
    // Must not leak into the custom-parameters bag.
    assertFalse(k.other().containsKey("x5t#S256"));
  }

  @Test
  public void toJSON_emits_x5t_S256_wire_key() {
    // Use case: toJSON emits x5tS256 under the wire-form "x5t#S256" key
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("AQAB")
        .e("AQAB")
        .x5tS256("thumb")
        .build();

    String j = k.toJSON();
    assertTrue(j.contains("\"x5t#S256\":\"thumb\""), j);
    // Must not also emit the Java-form "x5tS256".
    assertFalse(j.contains("x5tS256"), j);
  }

  @Test
  public void x5t_S256_round_trips() {
    // Use case: fromMap → toJSON round-trip preserves x5t#S256 key form
    String json = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"X\",\"y\":\"Y\",\"x5t#S256\":\"thumb\"}";
    Map<String, Object> map = new LatteJSONProcessor().deserialize(json.getBytes());
    JSONWebKey k = JSONWebKey.fromMap(map);
    assertEquals(k.x5tS256(), "thumb");
    String back = k.toJSON();
    assertTrue(back.contains("\"x5t#S256\":\"thumb\""), back);
  }

  // ---------- key_ops / x5u typed parsing ----------

  @Test
  public void fromMap_parses_key_ops_as_typed_list() {
    // Use case: fromMap parses key_ops as a List<String> on the typed field
    Map<String, Object> wire = new LinkedHashMap<>();
    wire.put("kty", "RSA");
    wire.put("n", "AQAB");
    wire.put("e", "AQAB");
    wire.put("key_ops", Arrays.asList("sign", "verify"));

    JSONWebKey k = JSONWebKey.fromMap(wire);
    assertEquals(k.key_ops(), Arrays.asList("sign", "verify"));
    assertFalse(k.other().containsKey("key_ops"));
  }

  @Test
  public void fromMap_rejects_non_array_key_ops() {
    // Use case: fromMap rejects key_ops when not a List
    Map<String, Object> wire = new LinkedHashMap<>();
    wire.put("kty", "RSA");
    wire.put("key_ops", "sign"); // wrong: should be array
    try {
      JSONWebKey.fromMap(wire);
      fail("Expected IllegalArgumentException for non-array key_ops.");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("key_ops"), expected.getMessage());
    }
  }

  @Test
  public void fromMap_parses_x5u_as_typed_field() {
    // Use case: fromMap parses x5u as a typed String field
    Map<String, Object> wire = new LinkedHashMap<>();
    wire.put("kty", "RSA");
    wire.put("x5u", "https://example.test/keys");

    JSONWebKey k = JSONWebKey.fromMap(wire);
    assertEquals(k.x5u(), "https://example.test/keys");
    assertFalse(k.other().containsKey("x5u"));
  }

  // ---------- Custom parameter handling ----------

  @DataProvider(name = "registeredParamNames")
  public Object[][] registeredParamNames() {
    // Use case: Builder.parameter() rejects registered parameter names
    return new Object[][] {
        {"alg"}, {"crv"}, {"kid"}, {"kty"}, {"use"}, {"key_ops"}, {"x5u"},
        {"d"}, {"dp"}, {"dq"}, {"e"}, {"n"}, {"p"}, {"q"}, {"qi"},
        {"x"}, {"y"}, {"x5c"}, {"x5t"}, {"x5t#S256"}
    };
  }

  @Test(dataProvider = "registeredParamNames")
  public void builder_parameter_rejects_registered_parameter_name(String name) {
    try {
      JSONWebKey.builder().parameter(name, "value");
      fail("Expected JSONWebKeyException for registered name [" + name + "].");
    } catch (JSONWebKeyException expected) {
      assertTrue(expected.getMessage().contains(name));
    }
  }

  @Test
  public void builder_parameter_accepts_custom_parameter_and_round_trips() {
    // Use case: Builder.parameter() accepts a non-registered parameter; round-trips through toJSON
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("AQAB")
        .e("AQAB")
        .parameter("custom_field", "custom-value")
        .build();

    assertEquals(k.get("custom_field"), "custom-value");
    String j = k.toJSON();
    assertTrue(j.contains("\"custom_field\":\"custom-value\""), j);

    Map<String, Object> back = new LatteJSONProcessor().deserialize(j.getBytes());
    JSONWebKey k2 = JSONWebKey.fromMap(back);
    assertEquals(k2.get("custom_field"), "custom-value");
  }

  // ---------- Builder ----------

  @Test
  public void builder_produces_new_instance_with_fields() {
    // Use case: builder produces a new instance with the configured fields
    JSONWebKey k = JSONWebKey.builder()
        .kty(KeyType.EC)
        .alg(Algorithm.ES256)
        .crv("P-256")
        .x("X")
        .y("Y")
        .kid("ec-1")
        .x5tS256("thumb")
        .build();

    assertEquals(k.kty(), KeyType.EC);
    assertEquals(k.alg(), Algorithm.ES256);
    assertEquals(k.crv(), "P-256");
    assertEquals(k.x(), "X");
    assertEquals(k.y(), "Y");
    assertEquals(k.kid(), "ec-1");
    assertEquals(k.x5tS256(), "thumb");
  }

  @Test
  public void builder_build_returns_distinct_instance_each_call() {
    // Use case: builder().build() returns a distinct instance each call
    JSONWebKey.Builder b = JSONWebKey.builder().kty(KeyType.RSA).n("AQAB").e("AQAB");
    JSONWebKey a = b.build();
    JSONWebKey c = b.build();
    assertNotSame(a, c);
    assertEquals(a, c);
  }

  // ---------- JWKS-style mixed-type list ----------

  @Test
  @SuppressWarnings("unchecked")
  public void jwks_keys_array_mixed_kty_round_trips_via_fromMap() {
    // Use case: parse a JWKS-style "keys" array of mixed RSA / EC / OKP / OCT objects
    String json = "{\"keys\":["
        + "{\"kty\":\"RSA\",\"kid\":\"r1\",\"n\":\"AQAB\",\"e\":\"AQAB\"},"
        + "{\"kty\":\"EC\",\"kid\":\"e1\",\"crv\":\"P-256\",\"x\":\"X\",\"y\":\"Y\"},"
        + "{\"kty\":\"OKP\",\"kid\":\"o1\",\"crv\":\"Ed25519\",\"x\":\"OKPX\"},"
        + "{\"kty\":\"oct\",\"kid\":\"oct1\",\"k\":\"SOMEKEY\"}"
        + "]}";
    Map<String, Object> wire = new LatteJSONProcessor().deserialize(json.getBytes());
    List<Object> keys = (List<Object>) wire.get("keys");
    assertNotNull(keys);
    assertEquals(keys.size(), 4);

    JSONWebKey rsa = JSONWebKey.fromMap((Map<String, Object>) keys.get(0));
    JSONWebKey ec = JSONWebKey.fromMap((Map<String, Object>) keys.get(1));
    JSONWebKey okp = JSONWebKey.fromMap((Map<String, Object>) keys.get(2));
    JSONWebKey oct = JSONWebKey.fromMap((Map<String, Object>) keys.get(3));

    assertEquals(rsa.kty(), KeyType.RSA);
    assertEquals(rsa.kid(), "r1");
    assertEquals(rsa.n(), "AQAB");

    assertEquals(ec.kty(), KeyType.EC);
    assertEquals(ec.kid(), "e1");
    assertEquals(ec.crv(), "P-256");

    assertEquals(okp.kty(), KeyType.OKP);
    assertEquals(okp.crv(), "Ed25519");
    assertEquals(okp.x(), "OKPX");

    // OCT does not have a typed "k" field; it lands in the custom-parameters bag.
    assertEquals(oct.kty(), KeyType.OCT);
    assertEquals(oct.get("k"), "SOMEKEY");
  }

  // ---------- equals / hashCode ----------

  @Test
  public void equals_compares_alg_and_kty_by_name() {
    // Use case: equals compares typed enums by name (Algorithm.RS256 vs RS256)
    JSONWebKey a = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .alg(Algorithm.RS256)
        .build();

    JSONWebKey b = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .alg(Algorithm.RS256)
        .build();

    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  public void equals_distinguishes_on_private_field_diff() {
    // Use case: differing private material breaks equality
    JSONWebKey a = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .d("AAA")
        .build();

    JSONWebKey b = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .d("BBB")
        .build();

    assertNotEquals(a, b);
  }

  // ---------- Local helpers ----------

  private static void assertNotSame(Object a, Object b) {
    assertFalse(a == b, "expected distinct instances");
  }
}
