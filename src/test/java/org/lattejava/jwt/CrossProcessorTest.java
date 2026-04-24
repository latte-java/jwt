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

import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.jacksontest.JacksonJSONProcessor;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Cross-processor compatibility: encode with one JSONProcessor, decode with
 * another, in both directions. Custom claims with BigInteger and BigDecimal
 * must survive the round trip without numeric narrowing.
 *
 * @author Daniel DeGroff
 */
public class CrossProcessorTest extends BaseJWTTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  @DataProvider(name = "processorPairs")
  public Object[][] processorPairs() {
    LatteJSONProcessor latte = new LatteJSONProcessor();
    JacksonJSONProcessor jackson = new JacksonJSONProcessor();
    return new Object[][] {
        {"Latte->Jackson", latte, jackson},
        {"Jackson->Latte", jackson, latte},
        {"Latte->Latte", latte, latte},
        {"Jackson->Jackson", jackson, jackson},
    };
  }

  @Test(dataProvider = "processorPairs")
  public void crossProcessorRoundTrip(String label, JSONProcessor encodeProc, JSONProcessor decodeProc) {
    // Use case: encode with one processor, decode with another -- claims match.
    Instant exp = Instant.ofEpochSecond(Instant.now().getEpochSecond() + 3600);
    JWT jwt = JWT.builder()
        .subject("abc")
        .issuer("https://issuer.example")
        .audience(Arrays.asList("svc-a", "svc-b"))
        .expiresAt(exp)
        .claim("custom", "value")
        .claim("count", 42)
        .build();
    String token = new JWTEncoder(encodeProc).encode(jwt, HMACSigner.newSHA256Signer(SECRET));
    JWT decoded = new JWTDecoder(decodeProc).decode(token,
        VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
    assertEquals(decoded.subject(), "abc", label);
    assertEquals(decoded.issuer(), "https://issuer.example", label);
    assertEquals(decoded.audience(), Arrays.asList("svc-a", "svc-b"), label);
    assertEquals(decoded.expiresAt(), exp, label);
    assertEquals(decoded.getString("custom"), "value", label);
    // count may surface as Integer / BigInteger depending on processor; both are valid.
    Number countN = (Number) decoded.getObject("count");
    assertEquals(countN.longValue(), 42L, label);
  }

  @Test(dataProvider = "processorPairs")
  public void crossProcessor_bigIntegerOverLongMax(String label, JSONProcessor encodeProc, JSONProcessor decodeProc) {
    // Use case: BigInteger beyond Long.MAX_VALUE survives round-trip across processors.
    BigInteger huge = BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.TEN.pow(20));
    JWT jwt = JWT.builder().subject("abc").claim("huge", huge).build();
    String token = new JWTEncoder(encodeProc).encode(jwt, HMACSigner.newSHA256Signer(SECRET));
    JWT decoded = new JWTDecoder(decodeProc).decode(token,
        VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
    Number n = (Number) decoded.getObject("huge");
    BigInteger asBigInt = (n instanceof BigInteger)
        ? (BigInteger) n
        : (n instanceof BigDecimal ? ((BigDecimal) n).toBigInteger() : BigInteger.valueOf(n.longValue()));
    assertEquals(asBigInt, huge, label);
  }

  @Test(dataProvider = "processorPairs")
  public void crossProcessor_bigDecimalHighPrecision(String label, JSONProcessor encodeProc, JSONProcessor decodeProc) {
    // Use case: BigDecimal with high precision survives round-trip across processors.
    BigDecimal precise = new BigDecimal("3.14159265358979323846264338327950288419716939937510");
    JWT jwt = JWT.builder().subject("abc").claim("pi", precise).build();
    String token = new JWTEncoder(encodeProc).encode(jwt, HMACSigner.newSHA256Signer(SECRET));
    JWT decoded = new JWTDecoder(decodeProc).decode(token,
        VerifierResolver.of(HMACVerifier.newVerifier(Algorithm.HS256, SECRET)));
    Number n = (Number) decoded.getObject("pi");
    BigDecimal asBigDec = (n instanceof BigDecimal)
        ? (BigDecimal) n
        : new BigDecimal(n.toString());
    // Compare via compareTo to ignore scale -- the digits must match.
    assertTrue(asBigDec.compareTo(precise) == 0,
        label + ": expected " + precise + " got " + asBigDec);
  }
}
