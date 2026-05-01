/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
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

package org.lattejava.jwt.algorithm.hmac;

import java.nio.charset.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * @author Daniel DeGroff
 */
public class HMACSignerTest extends BaseJWTTest {
  private static final String SECRET_32 = "super-secret-key-that-is-at-least";
  private static final String SECRET_48 = "super-secret-key-that-is-at-least-48-bytes-long!";
  private static final String SECRET_64 = "super-secret-key-that-is-at-least-64-bytes-long-for-sha512-algo!";

  @Test
  public void test_algorithmAndKid() {
    assertEquals(HMACSigner.newSHA256Signer(SECRET_32).algorithm(), Algorithm.HS256);
    assertEquals(HMACSigner.newSHA384Signer(SECRET_48).algorithm(), Algorithm.HS384);
    assertEquals(HMACSigner.newSHA512Signer(SECRET_64).algorithm(), Algorithm.HS512);

    assertEquals(HMACSigner.newSHA256Signer(SECRET_32, "kid-a").kid(), "kid-a");
    assertEquals(HMACSigner.newSHA384Signer(SECRET_48, "kid-b").kid(), "kid-b");
    assertEquals(HMACSigner.newSHA512Signer(SECRET_64, "kid-c").kid(), "kid-c");
  }

  @Test
  public void test_byteAndStringOverloadsProduceIdenticalSignatures() {
    byte[] message = "a.b".getBytes(StandardCharsets.UTF_8);

    byte[] fromString = HMACSigner.newSHA256Signer(SECRET_32).sign(message);
    byte[] fromBytes = HMACSigner.newSHA256Signer(SECRET_32.getBytes(StandardCharsets.UTF_8)).sign(message);
    assertEquals(fromBytes, fromString);

    fromString = HMACSigner.newSHA384Signer(SECRET_48).sign(message);
    fromBytes = HMACSigner.newSHA384Signer(SECRET_48.getBytes(StandardCharsets.UTF_8)).sign(message);
    assertEquals(fromBytes, fromString);

    fromString = HMACSigner.newSHA512Signer(SECRET_64).sign(message);
    fromBytes = HMACSigner.newSHA512Signer(SECRET_64.getBytes(StandardCharsets.UTF_8)).sign(message);
    assertEquals(fromBytes, fromString);
  }

  @Test
  public void test_byteConstructorFactories_produceSigner() {
    assertNotNull(HMACSigner.newSHA256Signer(SECRET_32.getBytes(StandardCharsets.UTF_8)));
    assertNotNull(HMACSigner.newSHA384Signer(SECRET_48.getBytes(StandardCharsets.UTF_8)));
    assertNotNull(HMACSigner.newSHA512Signer(SECRET_64.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void test_exactlyMinimumLengthIsAccepted() {
    // Use case: RFC 7518 §3.2 requires a key at least the size of the hash output — exactly the minimum (32/48/64 bytes) must be accepted, not rejected as a boundary off-by-one.
    byte[] hs256Min = new byte[32];
    byte[] hs384Min = new byte[48];
    byte[] hs512Min = new byte[64];
    assertNotNull(HMACSigner.newSHA256Signer(hs256Min));
    assertNotNull(HMACSigner.newSHA384Signer(hs384Min));
    assertNotNull(HMACSigner.newSHA512Signer(hs512Min));
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void test_nullByteSecret_throwsNpe() {
    HMACSigner.newSHA256Signer((byte[]) null);
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void test_nullMessage_throwsNpe() {
    HMACSigner.newSHA256Signer(SECRET_32).sign((byte[]) null);
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void test_nullStringSecret_throwsNpe() {
    HMACSigner.newSHA256Signer((String) null);
  }

  @Test
  public void test_secretIsDefensivelyCopied() {
    // Use case: mutating the original secret array after constructing a signer must not
    // affect the signer's behavior -- the signer retains its own copy of the secret.
    byte[] original = SECRET_32.getBytes(StandardCharsets.UTF_8);
    HMACSigner signer = HMACSigner.newSHA256Signer(original);
    byte[] message = "m".getBytes(StandardCharsets.UTF_8);
    byte[] before = signer.sign(message);

    // Scribble over every byte of the original
    Arrays.fill(original, (byte) 0);

    byte[] after = signer.sign(message);
    assertEquals(after, before);
  }

  @Test
  public void test_secretTooShort_HS256() {
    expectException(InvalidKeyLengthException.class, () ->
        HMACSigner.newSHA256Signer("too-short"));
    expectException(InvalidKeyLengthException.class, () ->
        HMACSigner.newSHA256Signer("too-short".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void test_secretTooShort_HS384() {
    // 32 bytes is valid for HS256 but too short for HS384 (needs 48)
    expectException(InvalidKeyLengthException.class, () ->
        HMACSigner.newSHA384Signer(SECRET_32));
  }

  @Test
  public void test_secretTooShort_HS512() {
    // 48 bytes is valid for HS384 but too short for HS512 (needs 64)
    expectException(InvalidKeyLengthException.class, () ->
        HMACSigner.newSHA512Signer(SECRET_48));
  }

  @Test
  public void test_signatureIsDeterministic() {
    byte[] message = "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    byte[] first = HMACSigner.newSHA256Signer(SECRET_32).sign(message);
    byte[] second = HMACSigner.newSHA256Signer(SECRET_32).sign(message);
    assertEquals(second, first);
  }

  @Test
  public void test_stringConstructorFactories_produceSigner() {
    assertNotNull(HMACSigner.newSHA256Signer(SECRET_32));
    assertNotNull(HMACSigner.newSHA384Signer(SECRET_48));
    assertNotNull(HMACSigner.newSHA512Signer(SECRET_64));
  }

  @Test
  public void test_varargsSign_emptySegmentsProduceConstantSignature() {
    // Use case: sign() with no arguments is equivalent to signing a zero-length message — should produce a stable signature, not throw.
    HMACSigner signer = HMACSigner.newSHA256Signer(SECRET_32);
    byte[] empty = signer.sign();
    byte[] singleEmpty = signer.sign(new byte[0]);
    assertEquals(singleEmpty, empty);
  }

  @Test
  public void test_varargsSign_segmentBoundariesDoNotChangeResult() {
    // Use case: every grouping of the same bytes must produce the same signature — proves the signer treats segments as a contiguous byte stream with no implicit separator.
    HMACSigner signer = HMACSigner.newSHA256Signer(SECRET_32);
    byte[] header = "eyJhbGciOiJIUzI1NiJ9".getBytes(StandardCharsets.UTF_8);
    byte[] dot = { (byte) '.' };
    byte[] payload = "eyJzdWIiOiJ4In0".getBytes(StandardCharsets.UTF_8);
    byte[] combined = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0".getBytes(StandardCharsets.UTF_8);

    byte[] expected = signer.sign(combined);
    assertEquals(signer.sign(header, dot, payload), expected);
    assertEquals(signer.sign(header, new byte[]{(byte) '.'}, payload), expected);
    // First segment empty
    assertEquals(signer.sign(new byte[0], header, dot, payload), expected);
    // Empty segment in the middle
    assertEquals(signer.sign(header, new byte[0], dot, payload), expected);
    // Trailing empty segment
    assertEquals(signer.sign(header, dot, payload, new byte[0]), expected);
  }

  @Test
  public void test_varargsSign_threadSafetyUnderConcurrentCallers() throws InterruptedException {
    // Use case: chunked update + doFinal must be atomic — interleaved updates from a second thread would splice bytes into the MAC and produce a wrong signature with no exception.
    HMACSigner signer = HMACSigner.newSHA256Signer(SECRET_32);
    byte[] header = "header-segment-bytes".getBytes(StandardCharsets.UTF_8);
    byte[] dot = { (byte) '.' };
    byte[] payload = "payload-segment-bytes".getBytes(StandardCharsets.UTF_8);
    byte[] expected = signer.sign(header, dot, payload);

    int threadCount = 16;
    int iterations = 200;
    Thread[] threads = new Thread[threadCount];
    boolean[] mismatched = new boolean[threadCount];
    for (int t = 0; t < threadCount; t++) {
      final int idx = t;
      threads[t] = new Thread(() -> {
        for (int i = 0; i < iterations; i++) {
          byte[] sig = signer.sign(header, dot, payload);
          if (!java.util.Arrays.equals(sig, expected)) {
            mismatched[idx] = true;
            return;
          }
        }
      });
    }
    for (Thread th : threads) th.start();
    for (Thread th : threads) th.join();
    for (int t = 0; t < threadCount; t++) {
      assertFalse(mismatched[t], "Thread [" + t + "] observed a spliced signature under concurrent sign() calls");
    }
  }

  @Test(expectedExceptions = NullPointerException.class)
  public void test_varargsSign_nullSegmentArray_throwsNpe() {
    HMACSigner.newSHA256Signer(SECRET_32).sign((byte[][]) null);
  }
}
