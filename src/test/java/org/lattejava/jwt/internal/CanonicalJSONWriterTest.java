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

import java.math.*;
import java.nio.charset.*;
import java.util.*;

import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Tests for {@link CanonicalJSONWriter}.
 *
 * @author Daniel DeGroff
 */
public class CanonicalJSONWriterTest {

  @Test
  public void emptyObject() {
    // Use case: Empty object writes "{}"
    String out = new String(CanonicalJSONWriter.write(new LinkedHashMap<>()),
        StandardCharsets.UTF_8);
    assertEquals(out, "{}");
  }

  @Test
  public void lexOrderingByCodePoint() {
    // Use case: Lex ordering by Unicode code point (NOT Unicode collation)
    // ASCII lowercase 'a' (0x61) sorts before 'b' (0x62), and 'b' sorts before
    // 'z' (0x7A). Uppercase letters (0x41-0x5A) sort before lowercase. Test with
    // a non-ASCII key to confirm code-point semantics.
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("z", "z");
    input.put("a", "a");
    input.put("B", "B");          // uppercase 0x42 < lowercase 'a' 0x61
    input.put("\u00e9", "eacute"); // U+00E9 0xE9 -- after ASCII
    input.put("\u00e0", "agrave"); // U+00E0 0xE0 -- before eacute

    String out = new String(CanonicalJSONWriter.write(input), StandardCharsets.UTF_8);
    String expected = "{\"B\":\"B\",\"a\":\"a\",\"z\":\"z\",\"\u00e0\":\"agrave\",\"\u00e9\":\"eacute\"}";
    assertEquals(out, expected);
  }

  @Test
  public void noWhitespace() {
    // Use case: Whitespace is absent in canonical output
    Map<String, Object> jwk = new LinkedHashMap<>();
    jwk.put("kty", "oct");
    jwk.put("k", "secret");

    String out = new String(CanonicalJSONWriter.write(jwk), StandardCharsets.UTF_8);
    assertFalse(out.contains(" "), "no spaces");
    assertFalse(out.contains("\t"), "no tabs");
    assertFalse(out.contains("\n"), "no newlines");
    assertFalse(out.contains("\r"), "no CR");
  }

  @Test
  public void primitiveValueTypes() {
    // Use case: Numbers, booleans, and null serialize as JSON primitives
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("a", BigInteger.valueOf(1));
    input.put("b", Boolean.TRUE);
    input.put("c", Boolean.FALSE);
    input.put("d", null);

    String out = new String(CanonicalJSONWriter.write(input), StandardCharsets.UTF_8);
    assertEquals(out, "{\"a\":1,\"b\":true,\"c\":false,\"d\":null}");
  }

  @Test
  public void rejectsArbitraryObject() {
    // Use case: Unsupported value type (arbitrary Object) throws IllegalArgumentException
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("a", new Object());
    expectThrows(IllegalArgumentException.class, () -> CanonicalJSONWriter.write(input));
  }

  @Test
  public void rejectsListValue() {
    // Use case: Unsupported value type (List value) throws IllegalArgumentException
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("a", java.util.Arrays.asList(1, 2, 3));
    expectThrows(IllegalArgumentException.class, () -> CanonicalJSONWriter.write(input));
  }

  @Test
  public void rejectsNestedMapValue() {
    // Use case: Unsupported value type (Map nested value) throws IllegalArgumentException
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("a", new LinkedHashMap<String, Object>());
    expectThrows(IllegalArgumentException.class, () -> CanonicalJSONWriter.write(input));
  }

  @Test
  public void rejectsNullInput() {
    // Use case: null input throws IllegalArgumentException
    expectThrows(IllegalArgumentException.class, () -> CanonicalJSONWriter.write(null));
  }

  @Test
  public void rfc7638RSAExample() {
    // Use case: RFC 7638 §3.1 RSA example produces the documented canonical bytes
    // even when the input map is in a non-lex insertion order.
    Map<String, Object> jwk = new LinkedHashMap<>();
    // Insertion order intentionally NOT lex order:
    jwk.put("kty", "RSA");
    jwk.put("n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
        + "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiF"
        + "V4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C"
        + "f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9"
        + "c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTW"
        + "hAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1"
        + "jF44-csFCur-kEgU8awapJzKnqDKgw");
    jwk.put("e", "AQAB");

    String expected = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

    byte[] out = CanonicalJSONWriter.write(jwk);
    assertEquals(new String(out, StandardCharsets.UTF_8), expected);
    // Confirm bytes are pure ASCII (UTF-8 == ASCII for this input)
    assertEquals(out, expected.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  public void rfc8037OKPExample() {
    // Use case: RFC 8037 §A.3 OKP (Ed25519) example produces the documented bytes
    Map<String, Object> jwk = new LinkedHashMap<>();
    // Insertion order intentionally NOT lex order:
    jwk.put("kty", "OKP");
    jwk.put("crv", "Ed25519");
    jwk.put("x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

    String expected = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

    byte[] out = CanonicalJSONWriter.write(jwk);
    assertEquals(new String(out, StandardCharsets.UTF_8), expected);
  }

  @Test
  public void stringEscaping() {
    // Use case: String values with special chars are escaped per RFC 8259
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("k", "a\"b\\c\nd");
    String out = new String(CanonicalJSONWriter.write(input), StandardCharsets.UTF_8);
    assertEquals(out, "{\"k\":\"a\\\"b\\\\c\\nd\"}");
  }
}
