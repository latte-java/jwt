/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.auth0;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

/**
 * auth0/java-jwt adapter. The library does not support externally-fixed time on the verifier,
 * so the adapter regenerates iat/exp at prepare() time relative to System.currentTimeMillis,
 * keeping the token stable for the duration of the trial.
 */
public final class Auth0Adapter implements JwtBenchmarkAdapter {

  private Algorithm es256Alg;
  private JWTVerifier es256Verifier;
  private long expMs;
  private Algorithm hs256Alg;
  private JWTVerifier hs256Verifier;
  private long iatMs;
  private Algorithm rs256Alg;
  private JWTVerifier rs256Verifier;

  @Override
  public void prepare(Fixtures fixtures) {
    hs256Alg = Algorithm.HMAC256(fixtures.hmacKey);
    rs256Alg = Algorithm.RSA256((RSAPublicKey) fixtures.rsaPublic, (RSAPrivateKey) fixtures.rsaPrivate);
    es256Alg = Algorithm.ECDSA256((ECPublicKey) fixtures.ecPublic, (ECPrivateKey) fixtures.ecPrivate);

    long now = System.currentTimeMillis();
    iatMs = now;
    expMs = now + 3_600_000L;

    hs256Verifier = JWT.require(hs256Alg)
        .withIssuer("https://benchmarks.lattejava.org")
        .withAudience("benchmark-audience")
        .build();
    rs256Verifier = JWT.require(rs256Alg)
        .withIssuer("https://benchmarks.lattejava.org")
        .withAudience("benchmark-audience")
        .build();
    es256Verifier = JWT.require(es256Alg)
        .withIssuer("https://benchmarks.lattejava.org")
        .withAudience("benchmark-audience")
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    Algorithm algo = switch (alg) {
      case ES256 -> es256Alg;
      case HS256 -> hs256Alg;
      case RS256 -> rs256Alg;
    };
    return JWT.create()
        .withIssuer("https://benchmarks.lattejava.org")
        .withSubject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .withAudience("benchmark-audience")
        .withIssuedAt(new Date(iatMs))
        .withNotBefore(new Date(iatMs))
        .withExpiresAt(new Date(expMs))
        .withJWTId("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .withClaim("scope", "openid profile email")
        .withClaim("email", "test@example.com")
        .withClaim("email_verified", true)
        .sign(algo);
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    return switch (alg) {
      case ES256 -> es256Verifier.verify(token);
      case HS256 -> hs256Verifier.verify(token);
      case RS256 -> rs256Verifier.verify(token);
    };
  }

  @Override
  public Object unsafeDecodeClaims(String token) {
    // auth0/java-jwt has no payload-only decode API: JWT.decode() always builds a full
    // DecodedJWT. Reported N/A here so we don't double-count this library on the "full" shape.
    throw new UnsupportedOperationException("auth0/java-jwt has no payload-only no-verify API");
  }

  @Override
  public Object unsafeDecodeFull(String token) {
    return JWT.decode(token);
  }
}
