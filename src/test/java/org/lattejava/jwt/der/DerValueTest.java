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

package org.lattejava.jwt.der;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Tests for the new {@link DerValue} factory methods introduced in Checkpoint 9.
 *
 * @author The Latte Project
 */
public class DerValueTest {
  @Test
  public void bitString_round_trip() {
    // Use case: newBitString prepends a zero pad byte and getBitStringBytes round-trips it back.
    byte[] payload = new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
    DerValue v = DerValue.newBitString(payload);
    assertEquals(v.tag.value, Tag.BitString);
    // Internally the value bytes are pad + payload
    byte[] raw = v.toByteArray();
    assertEquals(raw.length, payload.length + 1);
    assertEquals(raw[0], (byte) 0x00);

    byte[] round = v.getBitStringBytes();
    assertEquals(round, payload);
  }

  @Test
  public void bitString_nonZeroPad_rejected() {
    // Use case: getBitStringBytes rejects non-zero pad byte.
    DerValue v = new DerValue(Tag.BitString, new byte[]{0x03, 0x06});
    assertThrows(IllegalArgumentException.class, v::getBitStringBytes);
  }

  @Test
  public void bitString_wrongTag_rejected() {
    // Use case: getBitStringBytes errors when called on a non-BitString value.
    DerValue v = new DerValue(Tag.OctetString, new byte[]{1, 2, 3});
    assertThrows(IllegalStateException.class, v::getBitStringBytes);
  }

  @Test
  public void nullValue_zeroLengthBody() {
    // Use case: newNull produces a NULL tag with zero-length body.
    DerValue v = DerValue.newNull();
    assertEquals(v.tag.value, Tag.Null);
    assertEquals(v.getLength(), 0);
    assertEquals(v.toByteArray().length, 0);
  }

  @Test
  public void asciiString_round_trip() {
    // Use case: newASCIIString uses PrintableString tag (19 / 0x13) with US-ASCII body.
    DerValue v = DerValue.newASCIIString("Latte");
    assertEquals(v.tag.value, Tag.PrintableString);
    assertEquals(v.toByteArray(), "Latte".getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  public void utf8String_round_trip() {
    // Use case: newUTF8String uses tag 12 (0x0C) with UTF-8 bytes.
    DerValue v = DerValue.newUTF8String("naïve\u4e2d");
    assertEquals(v.tag.value, Tag.UTFString);
    assertEquals(v.toByteArray(), "naïve\u4e2d".getBytes(StandardCharsets.UTF_8));
  }

  @Test
  public void utcTime_format() {
    // Use case: newUTCTime formats as yyMMddHHmmssZ and emits tag 23.
    Instant t = Instant.parse("2024-04-22T10:30:45Z");
    DerValue v = DerValue.newUTCTime(t);
    assertEquals(v.tag.value, Tag.UTCTime);
    assertEquals(new String(v.toByteArray(), StandardCharsets.US_ASCII), "240422103045Z");
  }

  @Test
  public void generalizedTime_format() {
    // Use case: newGeneralizedTime formats as yyyyMMddHHmmssZ and emits tag 24.
    Instant t = Instant.parse("2050-04-22T10:30:45Z");
    DerValue v = DerValue.newGeneralizedTime(t);
    assertEquals(v.tag.value, Tag.GeneralizedTime);
    assertEquals(new String(v.toByteArray(), StandardCharsets.US_ASCII), "20500422103045Z");
  }

  @DataProvider(name = "timeBoundary")
  public Object[][] timeBoundary() {
    return new Object[][]{
        // Strictly before 2050-01-01: UTCTime
        {Instant.parse("2049-12-31T23:59:59Z"), Tag.UTCTime},
        // Exactly the boundary: GeneralizedTime
        {Instant.parse("2050-01-01T00:00:00Z"), Tag.GeneralizedTime},
        // After: GeneralizedTime
        {Instant.parse("2050-01-01T00:00:01Z"), Tag.GeneralizedTime},
        // Far past (still UTC range): UTCTime
        {Instant.parse("1970-01-01T00:00:00Z"), Tag.UTCTime}
    };
  }

  @Test(dataProvider = "timeBoundary")
  public void chooseTimeEncoding_boundary(Instant t, int expectedTag) {
    // Use case: 2050-01-01 boundary — strictly before -> UTCTime, on/after -> GeneralizedTime (RFC 5280 §4.1.2.5).
    DerValue v = t.isBefore(DerValue.TIME_ENCODING_BOUNDARY)
        ? DerValue.newUTCTime(t)
        : DerValue.newGeneralizedTime(t);
    assertEquals(v.tag.value, expectedTag);
  }

  @Test
  public void constructorFromStream_wrapsBytes() throws Exception {
    // Use case: DerValue(Tag, DerOutputStream) wraps the inner stream's bytes as the value.
    DerOutputStream inner = new DerOutputStream();
    inner.writeValue(new DerValue(Tag.Integer, new byte[]{0x01}));
    DerValue v = new DerValue(new Tag(Tag.Sequence), inner);
    assertEquals(v.tag.value, Tag.Sequence & 0x1F);
    assertTrue(v.tag.isConstructed());
    // Should contain the encoded inner integer: [02 01 01]
    assertEquals(v.toByteArray(), new byte[]{0x02, 0x01, 0x01});
  }
}
