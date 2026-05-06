/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.nio.charset.*;
import java.util.*;

import org.lattejava.jwt.algorithm.hmac.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Confirms that methods producing a fully-formed {@link JWT} reject inputs whose header carries the JWE-only [enc]
 * parameter (RFC 8725 §3.10 JOSE token classification), and that the inspection-only helpers remain liberal so callers
 * can examine such inputs themselves.
 *
 * @author Daniel DeGroff
 */
public class JWSClassificationTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static String b64(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * A 3-segment token with [enc] set in the header. Signature is bogus -- the classification check runs before
   * signature verification, so we never reach the verifier.
   */
  private static String tokenWithEncHeader() {
    String header = b64("{\"alg\":\"HS256\",\"enc\":\"A256GCM\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    return header + "." + payload + ".bogusbutvalidb64";
  }

  @Test
  public void decode_rejectsHeaderWithEnc() {
    // Use case: an encrypted-token-shaped header on a 3-segment input MUST be rejected before signature verification.
    // The library does not support JWE; producing a JWT from this input would silently treat a JWE as a JWS.
    Verifier verifier = HMACVerifier.newVerifier(Algorithm.HS256, SECRET);
    try {
      new JWTDecoder().decode(tokenWithEncHeader(), VerifierResolver.of(verifier));
      fail("Expected InvalidJWTException for [enc] in JWS header");
    } catch (InvalidJWTException expected) {
      assertTrue(expected.getMessage().contains("enc"), "exception message should mention [enc]");
    }
  }

  @Test
  public void decodeClaimsUnsecured_acceptsHeaderWithEnc_doesNotInspectHeader() {
    // Use case: decodeClaimsUnsecured deliberately skips header parsing for the kid-lookup hot path. A JWE-shaped
    // header in a 3-segment token does not affect the payload's claims; this method returns them unchanged.
    Map<String, Object> claims = new JWTDecoder().decodeClaimsUnsecured(tokenWithEncHeader());
    assertNotNull(claims);
    assertEquals(claims.get("sub"), "abc");
  }

  @Test
  public void decodeHeaderUnsecured_acceptsHeaderWithEnc_inspectionMethod() {
    // Use case: decodeHeaderUnsecured is an inspection helper -- callers may legitimately use it to peek at unknown
    // tokens (including JWE-shaped headers) and decide what to do. It must not be opinionated about [enc].
    Header header = new JWTDecoder().decodeHeaderUnsecured(tokenWithEncHeader());
    assertNotNull(header);
    assertEquals(header.get("enc"), "A256GCM");
  }

  @Test
  public void decodeUnsecured_rejectsHeaderWithEnc() {
    // Use case: decodeUnsecured produces a fully-formed JWT, so structural classification must hold even though
    // signature verification is skipped. A JWE-shaped header must be rejected.
    try {
      new JWTDecoder().decodeUnsecured(tokenWithEncHeader());
      fail("Expected InvalidJWTException for [enc] in JWS header");
    } catch (InvalidJWTException expected) {
      assertTrue(expected.getMessage().contains("enc"), "exception message should mention [enc]");
    }
  }
}
