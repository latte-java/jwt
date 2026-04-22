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
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Tests for the KeyType interface and StandardKeyType implementation per spec §7.
 *
 * @author The Latte Project
 */
public class KeyTypeTest {
  @DataProvider(name = "standardKeyTypes")
  public Object[][] standardKeyTypes() {
    return new Object[][]{
        {KeyType.RSA, "RSA"},
        {KeyType.EC, "EC"},
        {KeyType.OKP, "OKP"},
        {KeyType.OCT, "oct"},
    };
  }

  @Test(dataProvider = "standardKeyTypes")
  public void standardConstantNameMatches(KeyType keyType, String expectedName) {
    // Use case: All 4 standard constants exist and name() returns the exact kty value
    assertEquals(keyType.name(), expectedName);
  }

  @Test(dataProvider = "standardKeyTypes")
  public void ofReturnsInternedStandardConstant(KeyType keyType, String name) {
    // Use case: of() returns interned constant for standard names (reference equality with ==)
    assertSame(KeyType.of(name), keyType);
  }

  @Test
  public void equalsAndHashCodeForSameName() {
    // Use case: equals/hashCode contract -- two instances with the same name are equal
    KeyType a = KeyType.of("MY_KTY");
    KeyType b = KeyType.of("MY_KTY");
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  public void ofReturnsNewInstanceForUnknownNames() {
    // Use case: of() returns a new instance for unknown names
    KeyType a = KeyType.of("MY_KTY");
    KeyType b = KeyType.of("MY_KTY");
    assertNotSame(a, b);
  }

  @Test
  public void caseSensitivityForStandardNames() {
    // Use case: Case sensitivity -- "rsa" vs "RSA" -- exact-case lookup
    KeyType lower = KeyType.of("rsa");
    assertNotSame(lower, KeyType.RSA);
    assertNotEquals(lower, KeyType.RSA);
    assertEquals(lower.name(), "rsa");
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void ofNullThrows() {
    // Use case: of(null) throws NullPointerException
    KeyType.of(null);
  }

  @Test
  public void standardValuesContainsAllStandardKeyTypes() {
    // Use case: standardValues() returns all 4 standard key types
    KeyType[] values = KeyType.standardValues();
    assertEquals(values.length, 4);
    for (Object[] row : standardKeyTypes()) {
      KeyType k = (KeyType) row[0];
      boolean found = false;
      for (KeyType v : values) {
        if (v == k) {
          found = true;
          break;
        }
      }
      assertTrue(found, "standardValues() missing " + k.name());
    }
  }

  @Test
  public void equalsFalseForNullAndDifferentType() {
    // Use case: equals returns false for null and other types
    KeyType a = KeyType.of("X");
    assertFalse(a.equals(null));
    assertFalse(a.equals("X"));
  }

  @Test
  public void octIsLowercase() {
    // Use case: KeyType.OCT name() returns the lowercase "oct" per RFC 7517 §6.4
    assertEquals(KeyType.OCT.name(), "oct");
  }
}
