/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.jose4j;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.HmacKey;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class Jose4jAdapter implements JwtBenchmarkAdapter {

  private JwtClaims claims;
  private java.security.PrivateKey ecPrivate;
  private java.security.PublicKey ecPublic;
  private JwtConsumer es256Consumer;
  private HmacKey hmacKey;
  private JwtConsumer hs256Consumer;
  private java.security.PrivateKey rsaPrivate;
  private java.security.PublicKey rsaPublic;
  private JwtConsumer rs256Consumer;
  private JwtConsumer unsafeConsumer;

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    hmacKey = new HmacKey(fixtures.hmacKey);
    rsaPrivate = fixtures.rsaPrivate;
    rsaPublic = fixtures.rsaPublic;
    ecPrivate = fixtures.ecPrivate;
    ecPublic = fixtures.ecPublic;

    claims = new JwtClaims();
    claims.setIssuer("https://benchmarks.lattejava.org");
    claims.setSubject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f");
    claims.setAudience("benchmark-audience");
    claims.setIssuedAt(NumericDate.fromSeconds(1761408000L));
    claims.setNotBefore(NumericDate.fromSeconds(1761408000L));
    claims.setExpirationTime(NumericDate.fromSeconds(1761411600L));
    claims.setJwtId("01JK6V2N5W3YE4XJ5Y7Z8A9BC0");
    claims.setStringClaim("scope", "openid profile email");
    claims.setStringClaim("email", "test@example.com");
    claims.setClaim("email_verified", Boolean.TRUE);

    NumericDate fixedNow = NumericDate.fromSeconds(1761408000L + 1800L);
    hs256Consumer = newConsumer(hmacKey, fixedNow);
    rs256Consumer = newConsumer(rsaPublic, fixedNow);
    es256Consumer = newConsumer(ecPublic, fixedNow);
    unsafeConsumer = new JwtConsumerBuilder()
        .setSkipAllValidators()
        .setDisableRequireSignature()
        .setSkipSignatureVerification()
        .build();
  }

  private static JwtConsumer newConsumer(java.security.Key verificationKey, NumericDate fixedNow) {
    return new JwtConsumerBuilder()
        .setVerificationKey(verificationKey)
        .setExpectedIssuer("https://benchmarks.lattejava.org")
        .setExpectedAudience("benchmark-audience")
        .setEvaluationTime(fixedNow)
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) throws Exception {
    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(claims.toJson());
    switch (alg) {
      case ES256 -> {
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKey(ecPrivate);
      }
      case HS256 -> {
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKey(hmacKey);
      }
      case RS256 -> {
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(rsaPrivate);
      }
    }
    return jws.getCompactSerialization();
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    return switch (alg) {
      case ES256 -> es256Consumer.processToClaims(token);
      case HS256 -> hs256Consumer.processToClaims(token);
      case RS256 -> rs256Consumer.processToClaims(token);
    };
  }

  @Override
  public Object unsafeDecodeClaims(String token) throws Exception {
    // jose4j's JwtConsumer.process always parses the full JWT structure (header + claims),
    // even when configured to skip signature verification. There's no payload-only API.
    throw new UnsupportedOperationException("jose4j has no payload-only no-verify API");
  }

  @Override
  public Object unsafeDecodeFull(String token) throws Exception {
    JwtContext ctx = unsafeConsumer.process(token);
    return ctx.getJwtClaims();
  }
}
