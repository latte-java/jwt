/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.nimbus;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

public final class NimbusAdapter implements JwtBenchmarkAdapter {

  private JWTClaimsSet canonicalClaims;
  private JWSSigner es256Signer;
  private JWSVerifier es256Verifier;
  private final Date fixedNow = new Date(1761408000_000L + 1_800_000L);
  private JWSSigner hs256Signer;
  private JWSVerifier hs256Verifier;
  private JWSSigner rs256Signer;
  private JWSVerifier rs256Verifier;

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    es256Signer   = new ECDSASigner((ECPrivateKey) fixtures.ecPrivate);
    es256Verifier = new ECDSAVerifier((ECPublicKey) fixtures.ecPublic);
    hs256Signer   = new MACSigner(fixtures.hmacKey);
    hs256Verifier = new MACVerifier(fixtures.hmacKey);
    rs256Signer   = new RSASSASigner((RSAPrivateKey) fixtures.rsaPrivate);
    rs256Verifier = new RSASSAVerifier((RSAPublicKey) fixtures.rsaPublic);

    canonicalClaims = new JWTClaimsSet.Builder()
        .audience("benchmark-audience")
        .claim("email", "test@example.com")
        .claim("email_verified", true)
        .claim("scope", "openid profile email")
        .expirationTime(new Date(1761411600_000L))
        .issueTime(new Date(1761408000_000L))
        .issuer("https://benchmarks.lattejava.org")
        .jwtID("01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .notBeforeTime(new Date(1761408000_000L))
        .subject("5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .build();
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) throws Exception {
    SignedJWT jwt = new SignedJWT(headerFor(alg), canonicalClaims);
    jwt.sign(switch (alg) {
      case ES256 -> es256Signer;
      case HS256 -> hs256Signer;
      case RS256 -> rs256Signer;
    });
    return jwt.serialize();
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    SignedJWT jwt = SignedJWT.parse(token);
    JWSVerifier v = switch (alg) {
      case ES256 -> es256Verifier;
      case HS256 -> hs256Verifier;
      case RS256 -> rs256Verifier;
    };
    if (!jwt.verify(v)) throw new SecurityException("nimbus verify failed");
    JWTClaimsSet cs = jwt.getJWTClaimsSet();
    Date exp = cs.getExpirationTime();
    Date nbf = cs.getNotBeforeTime();
    if (exp != null && fixedNow.after(exp)) throw new IllegalStateException("expired");
    if (nbf != null && fixedNow.before(nbf)) throw new IllegalStateException("nbf");
    if (!"https://benchmarks.lattejava.org".equals(cs.getIssuer())) throw new IllegalStateException("iss");
    if (cs.getAudience() == null || !cs.getAudience().contains("benchmark-audience")) throw new IllegalStateException("aud");
    return cs;
  }

  @Override
  public Object unsafeDecodeClaims(String token) throws Exception {
    // SignedJWT.parse parses both the header and the claims (typed JWTClaimsSet) without
    // verifying the signature. The matching shape is "claims-only" semantically — the
    // header's parsed but discarded by the caller below.
    com.nimbusds.jwt.SignedJWT jwt = com.nimbusds.jwt.SignedJWT.parse(token);
    return jwt.getJWTClaimsSet();
  }

  @Override
  public Object unsafeDecodeFull(String token) throws Exception {
    // JWSObject.parse parses the header into a typed JWSHeader; the payload is left as
    // raw bytes (no JSON parse). That's nimbus's natural "full structure, no claims
    // typing" no-verify path.
    return JWSObject.parse(token);
  }

  private static JWSHeader headerFor(BenchmarkAlgorithm alg) {
    return new JWSHeader(switch (alg) {
      case ES256 -> JWSAlgorithm.ES256;
      case HS256 -> JWSAlgorithm.HS256;
      case RS256 -> JWSAlgorithm.RS256;
    });
  }
}
