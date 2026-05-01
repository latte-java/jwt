/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.fusionauth;

import java.security.Key;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;

import io.fusionauth.jwt.JWTUtils;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.ec.ECVerifier;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class FusionAuthAdapter implements JwtBenchmarkAdapter {

  private Signer es256Signer;
  private Verifier es256Verifier;
  private final ZonedDateTime fixedNow = ZonedDateTime.ofInstant(
      Instant.ofEpochSecond(1761408000L + 1800L), ZoneOffset.UTC);
  private Signer hs256Signer;
  private Verifier hs256Verifier;
  private Signer rs256Signer;
  private Verifier rs256Verifier;

  @Override
  public void prepare(Fixtures fixtures) {
    hs256Signer = HMACSigner.newSHA256Signer(fixtures.hmacKey);
    rs256Signer = RSASigner.newSHA256Signer(toPEM(fixtures.rsaPrivate, "PRIVATE KEY"));
    es256Signer = ECSigner.newSHA256Signer(toPEM(fixtures.ecPrivate, "PRIVATE KEY"));

    hs256Verifier = HMACVerifier.newVerifier(fixtures.hmacKey);
    rs256Verifier = RSAVerifier.newVerifier(toPEM(fixtures.rsaPublic, "PUBLIC KEY"));
    es256Verifier = ECVerifier.newVerifier(toPEM(fixtures.ecPublic, "PUBLIC KEY"));
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    JWT jwt = new JWT()
        .setIssuer("https://benchmarks.lattejava.org")
        .setSubject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .setAudience("benchmark-audience")
        .setIssuedAt(ZonedDateTime.ofInstant(Instant.ofEpochSecond(1761408000L), ZoneOffset.UTC))
        .setNotBefore(ZonedDateTime.ofInstant(Instant.ofEpochSecond(1761408000L), ZoneOffset.UTC))
        .setExpiration(ZonedDateTime.ofInstant(Instant.ofEpochSecond(1761411600L), ZoneOffset.UTC))
        .setUniqueId("01JK6V2N5W3YE4XJ5Y7Z8A9BC0");
    jwt.addClaim("scope", "openid profile email");
    jwt.addClaim("email", "test@example.com");
    jwt.addClaim("email_verified", true);
    return JWT.getEncoder().encode(jwt, switch (alg) {
      case ES256 -> es256Signer;
      case HS256 -> hs256Signer;
      case RS256 -> rs256Signer;
    });
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) {
    Verifier v = switch (alg) {
      case ES256 -> es256Verifier;
      case HS256 -> hs256Verifier;
      case RS256 -> rs256Verifier;
    };
    JWT decoded = JWT.getTimeMachineDecoder(fixedNow).decode(token, v);
    if (!"https://benchmarks.lattejava.org".equals(decoded.issuer)) throw new IllegalStateException("iss");
    if (!audienceContains(decoded.audience, "benchmark-audience")) throw new IllegalStateException("aud");
    return decoded;
  }

  @Override
  public Object unsafeDecodeClaims(String token) {
    return JWTUtils.decodePayload(token);
  }

  @Override
  public Object unsafeDecodeFull(String token) {
    // fusionauth-jwt exposes only claims-only (decodePayload) for no-verify access; the
    // full JWT.getDecoder().decode path requires a Verifier.
    throw new UnsupportedOperationException("fusionauth-jwt has no full-JWT no-verify API");
  }

  @SuppressWarnings("unchecked")
  private static boolean audienceContains(Object audience, String value) {
    if (audience instanceof String s) return s.equals(value);
    if (audience instanceof java.util.List<?> list) return list.contains(value);
    return false;
  }

  private static String toPEM(Key key, String label) {
    String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
    return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
  }
}
