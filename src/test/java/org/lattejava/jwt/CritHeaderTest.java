/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;

import org.lattejava.jwt.algorithm.hmac.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * {@code crit} understood-parameters check. Structural shape validation of the {@code crit} array itself is covered in
 * {@link HeaderTest}; this class tests the decoder's runtime understanding set.
 *
 * @author Daniel DeGroff
 */
public class CritHeaderTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  @Test
  public void crit_emptyArray_accepted() {
    // Use case: crit is an empty array -> accepted (no required critical parameters).
    String token = encodeWithCrit(Collections.emptyList());
    JWT jwt = new JWTDecoder().decode(token, VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
    assertNotNull(jwt);
  }

  @Test
  public void crit_listedInCriticalHeaders_accepted() {
    // Use case: crit listing "b64"; decoder configured with "b64" in criticalHeaders -> accepted.
    String token = encodeWithCrit(Collections.singletonList("b64"));
    JWTDecoder decoder = JWTDecoder.builder()
                                   .criticalHeaders(new HashSet<>(Collections.singletonList("b64")))
                                   .build();
    JWT jwt = decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
    assertNotNull(jwt);
  }

  @Test
  public void crit_multipleNames_partialUnknown_rejected() {
    // Use case: crit listing multiple values; one unknown -> InvalidJWTException.
    String token = encodeWithCrit(Arrays.asList("b64", "unknown-ext"));
    JWTDecoder decoder = JWTDecoder.builder()
                                   .criticalHeaders(new HashSet<>(Collections.singletonList("b64")))
                                   .build();
    try {
      decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
      fail("Expected InvalidJWTException when any crit entry is unrecognized");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void crit_unrecognized_rejected() {
    // Use case: crit listing an unknown parameter name -> InvalidJWTException.
    String token = encodeWithCrit(Collections.singletonList("unknown-ext"));
    JWTDecoder decoder = JWTDecoder.builder()
                                   .criticalHeaders(new HashSet<>(Collections.singletonList("b64")))
                                   .build();
    try {
      decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
      fail("Expected InvalidJWTException for unrecognized crit");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  private String encodeWithCrit(Object critValue) {
    JWT jwt = JWT.builder().subject("abc").build();
    return new JWTEncoder().encode(jwt,
        HMACSigner.newSHA256Signer(SECRET),
        b -> b.parameter("crit", critValue).parameter("b64", Boolean.FALSE));
  }
}
