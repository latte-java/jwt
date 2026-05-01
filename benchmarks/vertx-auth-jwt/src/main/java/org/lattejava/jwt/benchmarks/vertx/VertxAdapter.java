/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.vertx;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

/**
 * vertx-auth-jwt 4.5.14 adapter.
 *
 * <p>The Vert.x JWT auth API is async: {@code JWTAuth.authenticate(JsonObject)} returns a
 * {@code Future<User>}. The adapter unwraps synchronously via
 * {@code .toCompletionStage().toCompletableFuture().get()}, capturing the Future overhead in the
 * measured result.
 *
 * <p>vertx-auth-jwt validates {@code exp} against the system clock, so the canonical fixture
 * claims (which use a fixed past timestamp) cannot be used as-is. This adapter regenerates
 * {@code iat}/{@code nbf}/{@code exp} at {@code prepare()} time relative to
 * {@code System.currentTimeMillis()}, keeping them stable for the duration of each JMH trial.
 *
 * <p>There is no public unsafe-decode API in vertx-auth-jwt; {@link #unsafeDecode(String)}
 * throws {@link UnsupportedOperationException}.
 */
public final class VertxAdapter implements JwtBenchmarkAdapter {

  private JsonObject canonicalClaims;
  private JWTAuth es256Auth;
  private JWTAuth hs256Auth;
  private JWTAuth rs256Auth;
  private Vertx vertx;

  @Override
  public void prepare(Fixtures fixtures) throws Exception {
    vertx = Vertx.vertx();

    hs256Auth = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("HS256")
            .setBuffer(new String(fixtures.hmacKey))));

    rs256Auth = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("RS256")
            .setBuffer(toPEM(fixtures.rsaPrivate, "PRIVATE KEY")))
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("RS256")
            .setBuffer(toPEM(fixtures.rsaPublic, "PUBLIC KEY"))));

    es256Auth = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("ES256")
            .setBuffer(toPEM(fixtures.ecPrivate, "PRIVATE KEY")))
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("ES256")
            .setBuffer(toPEM(fixtures.ecPublic, "PUBLIC KEY"))));

    // Regenerate time claims relative to now — vertx-auth-jwt validates exp against the clock.
    long now = System.currentTimeMillis() / 1000L;
    canonicalClaims = new JsonObject()
        .put("iss", "https://benchmarks.lattejava.org")
        .put("sub", "5d4f7c8e-3b2a-4d1c-8e9f-1a2b3c4d5e6f")
        .put("aud", "benchmark-audience")
        .put("iat", now)
        .put("nbf", now)
        .put("exp", now + 3600)
        .put("jti", "01JK6V2N5W3YE4XJ5Y7Z8A9BC0")
        .put("scope", "openid profile email")
        .put("email", "test@example.com")
        .put("email_verified", true);
  }

  private static String toPEM(java.security.Key key, String label) {
    String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
    return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) {
    JWTAuth auth = switch (alg) {
      case ES256 -> es256Auth;
      case HS256 -> hs256Auth;
      case RS256 -> rs256Auth;
    };
    return auth.generateToken(canonicalClaims, new JWTOptions().setAlgorithm(alg.name()));
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    JWTAuth auth = switch (alg) {
      case ES256 -> es256Auth;
      case HS256 -> hs256Auth;
      case RS256 -> rs256Auth;
    };
    Future<User> fut = auth.authenticate(new JsonObject().put("token", token));
    return fut.toCompletionStage().toCompletableFuture().get();
  }

  @Override
  public Object unsafeDecodeClaims(String token) {
    throw new UnsupportedOperationException("vertx-auth-jwt has no public no-verify API");
  }

  @Override
  public Object unsafeDecodeFull(String token) {
    throw new UnsupportedOperationException("vertx-auth-jwt has no public no-verify API");
  }
}
