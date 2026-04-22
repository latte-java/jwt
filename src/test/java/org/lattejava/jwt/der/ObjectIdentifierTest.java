/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.der;

import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.der.DerDecodingException;
import org.lattejava.jwt.der.ObjectIdentifier;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;

/**
 * @author Daniel DeGroff
 */
public class ObjectIdentifierTest extends BaseJWTTest {
  @Test
  public void decode() throws Exception {
    // EC
    assertEquals(decode(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01), "1.2.840.10045.2.1");

    // EC SHA-256, SHA-384, SHA-512
    assertEquals(decode(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07), "1.2.840.10045.3.1.7");
    assertEquals(decode(0x2B, 0x81, 0x04, 0x00, 0x22), "1.3.132.0.34");
    assertEquals(decode(0x2B, 0x81, 0x04, 0x00, 0x23), "1.3.132.0.35");

    // EdDSA Ed25519
    assertEquals(decode(0x2B, 0x65, 0x70), "1.3.101.112");
    // EdDSA Ed448
    assertEquals(decode(0x2B, 0x65, 0x71), "1.3.101.113");

    // RSA
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01), "1.2.840.113549.1.1.1");

    // RSA SHA-256, SHA-384, SHA-512
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B), "1.2.840.113549.1.1.11");
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C), "1.2.840.113549.1.1.12");
    assertEquals(decode(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D), "1.2.840.113549.1.1.13");

    // Other OIDs that we should be able to decode
    assertEquals(decode(0x51, 0x01), "2.1.1");
    assertEquals(decode(0x51, 0x03, 0x00, 0x01), "2.1.3.0.1");
    assertEquals(decode(0x2B, 0x06, 0x01, 0x04, 0x01, 0xAE, 0x23, 0x01, 0x03, 0x01), "1.3.6.1.4.1.5923.1.3.1");
    assertEquals(decode(0x2B, 0x06, 0x01, 0x04, 0x01, 0x9A, 0x2F, 0x02, 0x01, 0x02, 0x04, 0x01, 0x02, 0x01, 0x11), "1.3.6.1.4.1.3375.2.1.2.4.1.2.1.17");

    // Made up OID to test
    assertEquals(decode(0x53, 0x06, 0x01, 0x04, 0x01, 0xAE, 0x23, 0x01, 0x03, 0x01), "2.3.6.1.4.1.5923.1.3.1");
    assertEquals(decode(0x53, 0x06, 0x86, 0xF4, 0x61, 0x86, 0xE7, 0x3D, 0x01, 0x87, 0xA5, 0x7D, 0x01, 0x03, 0x01), "2.3.6.113249.111549.1.119549.1.3.1");

    // Test max INT - 2,147,483,647
    // - We are not supporting this configuration currently. Expect an exception.
    expectException(DerDecodingException.class, ()
        -> assertEquals(decode(0x51, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x01), "2.1.2147483647.1"));
  }

  @DataProvider(name = "encodeOIDs")
  public Object[][] encodeOIDs() {
    return new Object[][]{
        // Single-byte arc
        {"1.2.3", new int[]{0x2A, 0x03}},
        // Two-byte arc (113549 requires 3 bytes; 840 is 2 bytes)
        {"1.2.840", new int[]{0x2A, 0x86, 0x48}},
        // RSA PKCS#1 (mix of 1, 2, 3-byte arcs)
        {"1.2.840.113549.1.1.11", new int[]{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}},
        // Three-byte arc: 16384 -> 0x81 0x80 0x00
        {"1.2.16384", new int[]{0x2A, 0x81, 0x80, 0x00}},
        // EC P-256
        {"1.2.840.10045.3.1.7", new int[]{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}},
        // EdDSA Ed25519
        {"1.3.101.112", new int[]{0x2B, 0x65, 0x70}},
        // X.520 commonName
        {"2.5.4.3", new int[]{0x55, 0x04, 0x03}},
        // X.520 country
        {"2.5.4.6", new int[]{0x55, 0x04, 0x06}},
        // First arc 2 with arc2 > 39 (legal): 2.100 -> 40*2 + 100 = 180 -> 0x81 0x34
        {"2.100", new int[]{0x81, 0x34}}
    };
  }

  // Use case: encode produces the expected DER value bytes for single/two/three-byte arcs and DN OIDs.
  @Test(dataProvider = "encodeOIDs")
  public void encode_matches_expected(String oid, int[] expected) {
    byte[] bytes = ObjectIdentifier.encode(oid);
    byte[] exp = new byte[expected.length];
    for (int i = 0; i < expected.length; i++) {
      exp[i] = (byte) expected[i];
    }
    assertEquals(bytes, exp, "encoding mismatch for " + oid);
  }

  // Use case: encode then decode round-trips for every entry in the data provider.
  @Test(dataProvider = "encodeOIDs")
  public void encode_decode_roundtrip(String oid, int[] expected) throws DerDecodingException {
    byte[] encoded = ObjectIdentifier.encode(oid);
    String decoded = new ObjectIdentifier(encoded).decode();
    assertEquals(decoded, oid);
  }

  // Use case: malformed OID strings throw IllegalArgumentException.
  @Test
  public void encode_rejects_malformed() {
    assertThrows(IllegalArgumentException.class, () -> ObjectIdentifier.encode(""));
    assertThrows(IllegalArgumentException.class, () -> ObjectIdentifier.encode("1"));
    assertThrows(IllegalArgumentException.class, () -> ObjectIdentifier.encode("3.0.1"));
    assertThrows(IllegalArgumentException.class, () -> ObjectIdentifier.encode("1.40"));
    assertThrows(IllegalArgumentException.class, () -> ObjectIdentifier.encode("a.b.c"));
  }

  // Use case: DN-attribute OID constants exist and have the expected values.
  @Test
  public void dn_attribute_constants() {
    assertEquals(ObjectIdentifier.X_520_DN_COMMON_NAME, "2.5.4.3");
    assertEquals(ObjectIdentifier.X_520_DN_COUNTRY, "2.5.4.6");
    assertEquals(ObjectIdentifier.X_520_DN_LOCALITY, "2.5.4.7");
    assertEquals(ObjectIdentifier.X_520_DN_STATE, "2.5.4.8");
    assertEquals(ObjectIdentifier.X_520_DN_ORGANIZATION, "2.5.4.10");
    assertEquals(ObjectIdentifier.X_520_DN_ORGANIZATIONAL_UNIT, "2.5.4.11");
  }

  private String decode(int... array) throws DerDecodingException {
    byte[] bytes = new byte[array.length];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) array[i];
    }

    return new ObjectIdentifier(bytes).decode();
  }
}
