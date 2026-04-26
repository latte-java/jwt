/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.jjwt;

import java.security.Key;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class JjwtAdapter implements JwtBenchmarkAdapter {

  private Key ecPrivate;
  private Key ecPublic;
  private JwtParser es256Parser;
  private final long expMs = 1761411600_000L;
  private final Clock fixedClock = Clock.fixed(
      Instant.ofEpochSecond(1761408000L + 1800L), ZoneOffset.UTC);
  private Key hmacKey;
  private JwtParser hs256Parser;
  private final long iatMs = 1761408000_000L;
  private Key rsaPrivate;
  private Key rsaPublic;
  private JwtParser rs256Parser;

  @Override
  public void prepare(Fixtures fixtures) {
    hmacKey    = new SecretKeySpec(fixtures.hmacKey, "HmacSHA256");
    rsaPrivate = fixtures.rsaPrivate;
    rsaPublic  = fixtures.rsaPublic;
    ecPrivate  = fixtures.ecPrivate;
    ecPublic   = fixtures.ecPublic;

    hs256Parser = parserFor((javax.crypto.SecretKey) hmacKey);
    rs256Parser = parserFor((java.security.PublicKey) rsaPublic);
    es256Parser = parserFor((java.security.PublicKey) ecPublic);
  }

  private JwtParser parserFor(javax.crypto.SecretKey key) {
    return Jwts.parser()
        .verifyWith(key)
        .clock(() -> Date.from(fixedClock.instant()))
        .requireIssuer("https://benchmarks.lattejava.org")
        .requireAudience("benchmark-audience")
        .build();
  }

  private JwtParser parserFor(java.security.PublicKey key) {
    return Jwts.parser()
        .verifyWith(key)
        .clock(() -> Date.from(fixedClock.instant()))
        .requireIssuer("https://benchmarks.lattejava.org")
        .requireAudience("benchmark-audience")
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    return Jwts.builder()
        .issuer("https://benchmarks.lattejava.org")
        .subject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .audience().add("benchmark-audience").and()
        .issuedAt(new Date(iatMs))
        .notBefore(new Date(iatMs))
        .expiration(new Date(expMs))
        .id("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .claim("scope", "openid profile email")
        .claim("email", "test@example.com")
        .claim("email_verified", true)
        .signWith(switch (alg) {
          case ES256 -> ecPrivate;
          case HS256 -> hmacKey;
          case RS256 -> rsaPrivate;
        })
        .compact();
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    Jws<Claims> jws = switch (alg) {
      case ES256 -> es256Parser.parseSignedClaims(token);
      case HS256 -> hs256Parser.parseSignedClaims(token);
      case RS256 -> rs256Parser.parseSignedClaims(token);
    };
    return jws;
  }

  @Override
  public Object unsafeDecode(String token) {
    // jjwt 0.12+ does not expose a clean public API for parsing a signed token without
    // verifying the signature. The unsecured() builder method only accepts alg=none tokens,
    // not signed tokens with signature stripped. Reaching into impl internals is out of
    // scope. Return N/A.
    throw new UnsupportedOperationException("jjwt 0.12+ has no public API for parse-signed-without-verify");
  }
}
