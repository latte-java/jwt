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

import java.nio.charset.*;
import java.time.*;
import java.util.*;

import org.lattejava.jwt.algorithm.hmac.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Validates which defenses still run on {@link JWTDecoder#decodeUnsecured(String)}. For every defense we assert either
 * that it fires (when applicable to unsecured) or that it does NOT fire (when explicitly skipped because the token is
 * not authenticated).
 *
 * @author Daniel DeGroff
 */
public class DecodeUnsecuredTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static String b64(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  // ---- defenses that DO run ----

  @Test
  public void base64UrlStrictness_fires() {
    // Use case: base64URL strictness still enforced under decodeUnsecured.
    String header = b64("{\"alg\":\"none\"}") + "+";
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";
    try {
      new JWTDecoder().decodeUnsecured(token);
      fail("Expected InvalidJWTException for '+' in segment");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void crit_doesNotRun() {
    // Use case: crit understood-parameters check is NOT applied under decodeUnsecured
    // (decodeUnsecured returns successfully even when crit lists an unknown name).
    String header = b64("{\"alg\":\"none\",\"crit\":[\"unknown-ext\"],\"unknown-ext\":1}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";

    JWT jwt = new JWTDecoder().decodeUnsecured(token);
    assertNotNull(jwt);
  }

  @Test
  public void duplicateJsonKeys_defaultRejection_fires() {
    // Use case: duplicate JSON keys rejected by default under decodeUnsecured.
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\",\"sub\":\"def\"}");
    String token = header + "." + payload + ".";
    try {
      new JWTDecoder().decodeUnsecured(token);
      fail("Expected JSONProcessingException for duplicate JSON key");
    } catch (JSONProcessingException expected) {
      // good
    }
  }

  @Test
  public void expectedAlgorithms_doesNotRun() {
    // Use case: expectedAlgorithms whitelist is NOT applied under decodeUnsecured.
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";

    JWTDecoder decoder = JWTDecoder.builder()
                                   .expectedAlgorithms(new HashSet<>(Collections.singletonList(Algorithm.RS256)))
                                   .build();
    JWT jwt = decoder.decodeUnsecured(token);
    assertNotNull(jwt);
  }

  @Test
  public void expectedType_notEnforcedOnUnsecured() {
    // Use case: decodeUnsecured intentionally skips configured policy checks (typ, alg, crit, time). A typ mismatch on the configured expectedType MUST NOT prevent the unsecured path from returning the parsed JWT — callers opted out of authenticated decoding and own whatever inspection follows.
    String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";

    JWTDecoder decoder = JWTDecoder.builder().expectedType("at+jwt").build();
    JWT jwt = decoder.decodeUnsecured(token);
    assertEquals(jwt.subject(), "abc");
    assertEquals(jwt.header().typ(), "JWT");
  }

  @Test
  public void headerShapeValidation_fires() {
    // Use case: Header.fromMap shape validation still runs (e.g. crit not an array).
    String header = b64("{\"alg\":\"none\",\"crit\":\"notAnArray\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";
    try {
      new JWTDecoder().decodeUnsecured(token);
      fail("Expected InvalidJWTException for malformed crit");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void maxInputBytes_fires() {
    // Use case: maxInputBytes still enforced under decodeUnsecured.
    String header = b64("{\"alg\":\"none\"}");
    StringBuilder big = new StringBuilder();
    while (big.length() < 1024) big.append("aaaaaaaaaa");
    String payload = b64("{\"sub\":\"" + big + "\"}");
    String token = header + "." + payload + ".";

    JWTDecoder decoder = JWTDecoder.builder().maxInputBytes(64).build();
    try {
      decoder.decodeUnsecured(token);
      fail("Expected InvalidJWTException for oversize token");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void maxNestingDepth_fires() {
    // Use case: maxNestingDepth still enforced under decodeUnsecured.
    StringBuilder nested = new StringBuilder();
    for (int i = 0; i < 30; i++) nested.append("{\"a\":");
    nested.append("1");
    for (int i = 0; i < 30; i++) nested.append("}");

    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\",\"deep\":" + nested + "}");
    String token = header + "." + payload + ".";

    JWTDecoder decoder = JWTDecoder.builder().maxNestingDepth(8).build();
    try {
      decoder.decodeUnsecured(token);
      fail("Expected JSONProcessingException for excessive depth");
    } catch (JSONProcessingException expected) {
      // good
    }
  }

  @Test
  public void maxNumberLength_fires() {
    // Use case: maxNumberLength still enforced under decodeUnsecured.
    StringBuilder digits = new StringBuilder();
    for (int i = 0; i < 1500; i++) digits.append('1');
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\",\"big\":" + digits + "}");
    String token = header + "." + payload + ".";

    JWTDecoder decoder = JWTDecoder.builder().maxNumberLength(100).build();
    try {
      decoder.decodeUnsecured(token);
      fail("Expected JSONProcessingException for over-long number");
    } catch (JSONProcessingException expected) {
      // good
    }
  }

  @Test
  public void segmentCount_emptyThirdSegment_accepted() {
    // Use case: 3-segment "header.payload." (empty signature) is accepted.
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";
    JWT jwt = new JWTDecoder().decodeUnsecured(token);
    assertNotNull(jwt);
    assertEquals(jwt.subject(), "abc");
  }

  // ---- defenses that DO NOT run ----

  @Test
  public void segmentCount_fourSegments_invalid() {
    // Use case: 4+-segment input -> InvalidJWTException.
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".s.x";
    try {
      new JWTDecoder().decodeUnsecured(token);
      fail("Expected InvalidJWTException for 4-segment input");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void segmentCount_twoSegments_missingSignature() {
    // Use case: 3-segment split still enforced; 2-segment input -> MissingSignatureException.
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload;
    try {
      new JWTDecoder().decodeUnsecured(token);
      fail("Expected MissingSignatureException for 2-segment input");
    } catch (MissingSignatureException expected) {
      // good
    }
  }

  @Test
  public void signatureVerification_doesNotRun() {
    // Use case: signature verification is skipped -- a real signed token with
    // a tampered signature still parses under decodeUnsecured.
    JWT jwt = JWT.builder().subject("abc").build();
    String real = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(SECRET));
    String tampered = real.substring(0, real.lastIndexOf('.') + 1) + "Zm9vYmFy"; // bogus sig

    JWT decoded = new JWTDecoder().decodeUnsecured(tampered);
    assertNotNull(decoded);
    assertEquals(decoded.subject(), "abc");
  }

  @Test
  public void timeValidation_doesNotRun() {
    // Use case: time validation does NOT run -- an expired token still parses.
    long pastEpoch = Instant.parse("2000-01-01T00:00:00Z").getEpochSecond();
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"abc\",\"exp\":" + pastEpoch + "}");
    String token = header + "." + payload + ".";

    JWT jwt = new JWTDecoder().decodeUnsecured(token);
    assertNotNull(jwt);
    assertEquals(jwt.expiresAt(), Instant.ofEpochSecond(pastEpoch));
  }

  @Test
  public void verifierResolution_doesNotRun() {
    // Use case: verifier resolution does NOT run -- decodeUnsecured needs no resolver.
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(SECRET));
    JWT decoded = new JWTDecoder().decodeUnsecured(token);
    // Header is populated; no verifier was consulted.
    assertNotNull(decoded.header());
    assertNull(decoded.header().kid());
  }
}
