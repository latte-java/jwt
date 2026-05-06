/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Tests for the KeyType interface and StandardKeyType implementation.
 *
 * @author Daniel DeGroff
 */
public class KeyTypeTest {
  @Test
  public void caseSensitivityForStandardNames() {
    // Use case: Case sensitivity -- "rsa" vs "RSA" -- exact-case lookup
    KeyType lower = KeyType.of("rsa");
    assertNotSame(lower, KeyType.RSA);
    assertNotEquals(lower, KeyType.RSA);
    assertEquals(lower.name(), "rsa");
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
  public void equalsFalseForNullAndDifferentType() {
    // Use case: equals returns false for null and other types
    KeyType a = KeyType.of("X");
    assertNotEquals(a, null);
    assertNotEquals(a, "X");
  }

  @Test
  public void octIsLowercase() {
    // Use case: KeyType.OCT name() returns the lowercase "oct" per RFC 7517 §6.4
    assertEquals(KeyType.OCT.name(), "oct");
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void ofNullThrows() {
    // Use case: of(null) throws NullPointerException
    KeyType.of(null);
  }

  @Test(dataProvider = "standardKeyTypes")
  public void ofReturnsInternedStandardConstant(KeyType keyType, String name) {
    // Use case: of() returns interned constant for standard names (reference equality with ==)
    assertSame(KeyType.of(name), keyType);
  }

  @Test
  public void ofReturnsNewInstanceForUnknownNames() {
    // Use case: of() returns a new instance for unknown names
    KeyType a = KeyType.of("MY_KTY");
    KeyType b = KeyType.of("MY_KTY");
    assertNotSame(a, b);
  }

  @Test(dataProvider = "standardKeyTypes")
  public void standardConstantNameMatches(KeyType keyType, String expectedName) {
    // Use case: All 4 standard constants exist and name() returns the exact kty value
    assertEquals(keyType.name(), expectedName);
  }

  @DataProvider(name = "standardKeyTypes")
  public Object[][] standardKeyTypes() {
    return new Object[][]{
        {KeyType.RSA, "RSA"},
        {KeyType.EC, "EC"},
        {KeyType.OKP, "OKP"},
        {KeyType.OCT, "oct"},
    };
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
}
