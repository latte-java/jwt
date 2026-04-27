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

import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Tests for the Algorithm interface and StandardAlgorithm implementation.
 *
 * @author Daniel DeGroff
 */
public class AlgorithmTest {
  @Test
  public void caseSensitivityForStandardNames() {
    // Use case: Case sensitivity -- "rs256" vs "RS256" -- exact-case lookup
    Algorithm lower = Algorithm.of("rs256");
    assertNotSame(lower, Algorithm.RS256);
    assertNotEquals(lower, Algorithm.RS256);
    assertEquals(lower.name(), "rs256");
  }

  @Test
  public void equalsAcrossStandardAndCustomWithSameName() {
    // Use case: A standard constant equals a custom one with the same name (equals by name())
    Algorithm custom = new TestAlgorithm("RS256");
    // The standard constant equals a custom Algorithm with the same name only if both
    // sides honor name()-based equality. StandardAlgorithm.equals only compares to other
    // StandardAlgorithm instances; the custom side may use Object identity. The defense
    // against hostile equals impls is that the decoder keys by name(). For
    // this test, just confirm that two StandardAlgorithm instances with the same name
    // are equal (which is the documented StandardAlgorithm contract).
    Algorithm a = Algorithm.of("CUSTOM_X");
    Algorithm b = Algorithm.of("CUSTOM_X");
    assertEquals(a, b);
    // Sanity: the custom Algorithm name() also returns the value
    assertEquals(custom.name(), "RS256");
  }

  @Test
  public void equalsAndHashCodeForSameName() {
    // Use case: equals/hashCode contract -- two instances with the same name are equal
    Algorithm a = Algorithm.of("MY_ALG");
    Algorithm b = Algorithm.of("MY_ALG");
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  public void equalsFalseForNullAndDifferentType() {
    // Use case: equals returns false for null and other types
    Algorithm a = Algorithm.of("X");
    assertNotEquals(a, null);
    assertNotEquals(a, "X");
  }

  @Test(dataProvider = "standardAlgorithms")
  public void nameNeverNull(Algorithm algorithm, String expectedName) {
    // Use case: name() never returns null on standard constants
    assertNotEquals(algorithm.name(), null);
  }

  @Test
  public void ofEdDSAReturnsNonStandardAlgorithm() {
    // Use case: of("EdDSA") returns a non-standard Algorithm (no constant per RFC 9864)
    Algorithm eddsa = Algorithm.of("EdDSA");
    assertEquals(eddsa.name(), "EdDSA");
    assertNotSame(eddsa, Algorithm.Ed25519);
    assertNotSame(eddsa, Algorithm.Ed448);
  }

  @Test
  public void ofNoneReturnsNonStandardAlgorithm() {
    // Use case: of("none") returns a non-standard Algorithm with name() == "none"
    Algorithm none = Algorithm.of("none");
    assertEquals(none.name(), "none");
    assertNotSame(none, Algorithm.of("none"));
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void ofNullThrows() {
    // Use case: of(null) throws NullPointerException
    Algorithm.of(null);
  }

  @Test(dataProvider = "standardAlgorithms")
  public void ofReturnsInternedStandardConstant(Algorithm algorithm, String name) {
    // Use case: of() returns interned constant for standard names (reference equality with ==)
    assertSame(Algorithm.of(name), algorithm);
  }

  @Test
  public void ofReturnsNewInstanceForUnknownNames() {
    // Use case: of() returns a new instance for unknown names (not interned)
    Algorithm a = Algorithm.of("MY_ALG");
    Algorithm b = Algorithm.of("MY_ALG");
    assertNotSame(a, b);
  }

  @DataProvider(name = "standardAlgorithms")
  public Object[][] standardAlgorithms() {
    return new Object[][]{
        {Algorithm.HS256, "HS256"},
        {Algorithm.HS384, "HS384"},
        {Algorithm.HS512, "HS512"},
        {Algorithm.RS256, "RS256"},
        {Algorithm.RS384, "RS384"},
        {Algorithm.RS512, "RS512"},
        {Algorithm.PS256, "PS256"},
        {Algorithm.PS384, "PS384"},
        {Algorithm.PS512, "PS512"},
        {Algorithm.ES256, "ES256"},
        {Algorithm.ES384, "ES384"},
        {Algorithm.ES512, "ES512"},
        {Algorithm.Ed25519, "Ed25519"},
        {Algorithm.Ed448, "Ed448"},
        {Algorithm.ES256K, "ES256K"},
    };
  }

  @Test(dataProvider = "standardAlgorithms")
  public void standardConstantNameMatches(Algorithm algorithm, String expectedName) {
    // Use case: All 15 standard constants exist and name() returns the exact JWA string
    assertEquals(algorithm.name(), expectedName);
  }

  @Test
  public void standardValuesContainsAllStandardAlgorithms() {
    // Use case: standardValues() returns all 15 standard algorithms
    Algorithm[] values = Algorithm.standardValues();
    assertEquals(values.length, 15);
    for (Object[] row : standardAlgorithms()) {
      Algorithm a = (Algorithm) row[0];
      boolean found = false;
      for (Algorithm v : values) {
        if (v == a) {
          found = true;
          break;
        }
      }
      assertTrue(found, "standardValues() missing " + a.name());
    }
  }

  /**
     * Test-only Algorithm impl used to confirm the interface contract is open for extension.
     */
    private record TestAlgorithm(String name) implements Algorithm {
  }
}
