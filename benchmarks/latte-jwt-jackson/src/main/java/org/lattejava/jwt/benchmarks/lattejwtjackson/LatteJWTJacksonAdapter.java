/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.lattejwtjackson;

import java.time.Instant;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.JSONProcessor;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.lattejava.jwt.Signer;
import org.lattejava.jwt.Signers;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.Verifiers;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

/**
 * latte-jwt benchmark adapter that swaps the bundled LatteJSONProcessor for a Jackson-backed
 * JSONProcessor. Otherwise identical to {@code LatteJWTAdapter}: same Signer/Verifier wiring,
 * same canonical claims, same fixed-time decoder. Lets us isolate the cost of the JSON layer
 * by holding the JWT pipeline constant.
 */
public final class LatteJWTJacksonAdapter implements JwtBenchmarkAdapter {

  private JWT canonicalJWT;
  private JWTDecoder es256Decoder;
  private Signer es256Signer;
  private Verifier es256Verifier;
  private JWTEncoder encoder;
  private JWTDecoder hs256Decoder;
  private Signer hs256Signer;
  private Verifier hs256Verifier;
  private JWTDecoder rs256Decoder;
  private Signer rs256Signer;
  private Verifier rs256Verifier;
  private JWTDecoder unsafeDecoder;

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    JSONProcessor json = new JacksonJSONProcessor();

    es256Signer = Signers.forAsymmetric(Algorithm.of("ES256"), fixtures.ecPrivate);
    hs256Signer = Signers.forHMAC(Algorithm.of("HS256"), fixtures.hmacKey);
    rs256Signer = Signers.forAsymmetric(Algorithm.of("RS256"), fixtures.rsaPrivate);

    es256Verifier = Verifiers.forAsymmetric(Algorithm.of("ES256"), fixtures.ecPublic);
    hs256Verifier = Verifiers.forHMAC(Algorithm.of("HS256"), fixtures.hmacKey);
    rs256Verifier = Verifiers.forAsymmetric(Algorithm.of("RS256"), fixtures.rsaPublic);

    encoder = new JWTEncoder(json);

    Instant fixedNow = Instant.ofEpochSecond(1761408000L + 1800L);
    es256Decoder = JWTDecoder.builder().fixedTime(fixedNow).jsonProcessor(json).build();
    hs256Decoder = JWTDecoder.builder().fixedTime(fixedNow).jsonProcessor(json).build();
    rs256Decoder = JWTDecoder.builder().fixedTime(fixedNow).jsonProcessor(json).build();
    unsafeDecoder = JWTDecoder.builder().jsonProcessor(json).build();

    canonicalJWT = JWT.builder()
        .issuer("https://benchmarks.lattejava.org")
        .subject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .audience("benchmark-audience")
        .issuedAt(Instant.ofEpochSecond(1761408000L))
        .notBefore(Instant.ofEpochSecond(1761408000L))
        .expiresAt(Instant.ofEpochSecond(1761411600L))
        .id("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .claim("scope", "openid profile email")
        .claim("email", "test@example.com")
        .claim("email_verified", Boolean.TRUE)
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    return switch (alg) {
      case ES256 -> encoder.encode(canonicalJWT, es256Signer);
      case HS256 -> encoder.encode(canonicalJWT, hs256Signer);
      case RS256 -> encoder.encode(canonicalJWT, rs256Signer);
    };
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    return switch (alg) {
      case ES256 -> es256Decoder.decode(token, VerifierResolver.of(es256Verifier));
      case HS256 -> hs256Decoder.decode(token, VerifierResolver.of(hs256Verifier));
      case RS256 -> rs256Decoder.decode(token, VerifierResolver.of(rs256Verifier));
    };
  }

  @Override
  public Object unsafeDecode(String token) {
    return unsafeDecoder.decodeUnsecured(token);
  }
}
