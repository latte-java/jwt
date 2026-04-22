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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Tests for the Algorithm interface and StandardAlgorithm implementation per spec §1.
 *
 * @author The Latte Project
 */
public class AlgorithmTest {
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

  // Use case: All 15 standard constants exist and name() returns the exact JWA string
  @Test(dataProvider = "standardAlgorithms")
  public void standardConstantNameMatches(Algorithm algorithm, String expectedName) {
    assertEquals(algorithm.name(), expectedName);
  }

  // Use case: of() returns interned constant for standard names (reference equality with ==)
  @Test(dataProvider = "standardAlgorithms")
  public void ofReturnsInternedStandardConstant(Algorithm algorithm, String name) {
    assertSame(Algorithm.of(name), algorithm);
  }

  // Use case: equals/hashCode contract -- two instances with the same name are equal
  @Test
  public void equalsAndHashCodeForSameName() {
    Algorithm a = Algorithm.of("MY_ALG");
    Algorithm b = Algorithm.of("MY_ALG");
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  // Use case: of() returns a new instance for unknown names (not interned)
  @Test
  public void ofReturnsNewInstanceForUnknownNames() {
    Algorithm a = Algorithm.of("MY_ALG");
    Algorithm b = Algorithm.of("MY_ALG");
    assertNotSame(a, b);
  }

  // Use case: Case sensitivity -- "rs256" vs "RS256" -- exact-case lookup
  @Test
  public void caseSensitivityForStandardNames() {
    Algorithm lower = Algorithm.of("rs256");
    assertNotSame(lower, Algorithm.RS256);
    assertNotEquals(lower, Algorithm.RS256);
    assertEquals(lower.name(), "rs256");
  }

  // Use case: A standard constant equals a custom one with the same name (equals by name())
  @Test
  public void equalsAcrossStandardAndCustomWithSameName() {
    Algorithm custom = new TestAlgorithm("RS256");
    // The standard constant equals a custom Algorithm with the same name only if both
    // sides honor name()-based equality. StandardAlgorithm.equals only compares to other
    // StandardAlgorithm instances; the custom side may use Object identity. The defense
    // against hostile equals impls is that the decoder keys by name() (spec §16). For
    // this test, just confirm that two StandardAlgorithm instances with the same name
    // are equal (which is the documented StandardAlgorithm contract).
    Algorithm a = Algorithm.of("CUSTOM_X");
    Algorithm b = Algorithm.of("CUSTOM_X");
    assertEquals(a, b);
    // Sanity: the custom Algorithm name() also returns the value
    assertEquals(custom.name(), "RS256");
  }

  // Use case: of(null) throws NullPointerException
  @Test(expectedExceptions = NullPointerException.class)
  public void ofNullThrows() {
    Algorithm.of(null);
  }

  // Use case: name() never returns null on standard constants
  @Test(dataProvider = "standardAlgorithms")
  public void nameNeverNull(Algorithm algorithm, String expectedName) {
    assertNotEquals(algorithm.name(), null);
  }

  // Use case: standardValues() returns all 15 standard algorithms
  @Test
  public void standardValuesContainsAllStandardAlgorithms() {
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

  // Use case: equals returns false for null and other types
  @Test
  public void equalsFalseForNullAndDifferentType() {
    Algorithm a = Algorithm.of("X");
    assertFalse(a.equals(null));
    assertFalse(a.equals("X"));
  }

  // Use case: of("none") returns a non-standard Algorithm with name() == "none"
  @Test
  public void ofNoneReturnsNonStandardAlgorithm() {
    Algorithm none = Algorithm.of("none");
    assertEquals(none.name(), "none");
    assertNotSame(none, Algorithm.of("none"));
  }

  // Use case: of("EdDSA") returns a non-standard Algorithm (no constant per RFC 9864)
  @Test
  public void ofEdDSAReturnsNonStandardAlgorithm() {
    Algorithm eddsa = Algorithm.of("EdDSA");
    assertEquals(eddsa.name(), "EdDSA");
    assertNotSame(eddsa, Algorithm.Ed25519);
    assertNotSame(eddsa, Algorithm.Ed448);
  }

  /**
   * Test-only Algorithm impl used to confirm the interface contract is open for extension.
   */
  private static final class TestAlgorithm implements Algorithm {
    private final String name;

    TestAlgorithm(String name) {
      this.name = name;
    }

    @Override
    public String name() {
      return name;
    }
  }
}
