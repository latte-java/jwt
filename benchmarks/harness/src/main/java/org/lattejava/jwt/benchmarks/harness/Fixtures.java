/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.harness;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Fixture material shared across all adapters. Construct via {@link #load(Path)} pointing
 * at the {@code benchmarks/fixtures/} directory; instances are immutable and thread-safe.
 *
 * The canonical claims JSON is exposed as both raw bytes and a UTF-8 string — adapters choose
 * whichever shape their JSON layer prefers.
 */
public final class Fixtures {
  public final byte[] hmacKey;
  public final PrivateKey rsaPrivate;
  public final PublicKey rsaPublic;
  public final PrivateKey ecPrivate;
  public final PublicKey ecPublic;
  public final byte[] claimsJsonBytes;
  public final String claimsJson;

  private Fixtures(byte[] hmacKey, PrivateKey rsaPrivate, PublicKey rsaPublic,
                   PrivateKey ecPrivate, PublicKey ecPublic, byte[] claimsJsonBytes) {
    this.hmacKey = hmacKey;
    this.rsaPrivate = rsaPrivate;
    this.rsaPublic = rsaPublic;
    this.ecPrivate = ecPrivate;
    this.ecPublic = ecPublic;
    this.claimsJsonBytes = claimsJsonBytes;
    this.claimsJson = new String(claimsJsonBytes, StandardCharsets.UTF_8);
  }

  public static Fixtures load(Path fixturesDir) throws Exception {
    byte[] hmacKey = Files.readAllBytes(fixturesDir.resolve("hmac-256.key"));
    PrivateKey rsaPriv = readPrivateKey(fixturesDir.resolve("rsa-2048-private.pem"), "RSA");
    PublicKey  rsaPub  = readPublicKey (fixturesDir.resolve("rsa-2048-public.pem"),  "RSA");
    PrivateKey ecPriv  = readPrivateKey(fixturesDir.resolve("ec-p256-private.pem"),  "EC");
    PublicKey  ecPub   = readPublicKey (fixturesDir.resolve("ec-p256-public.pem"),   "EC");
    byte[] claims = Files.readAllBytes(fixturesDir.resolve("claims.json"));
    return new Fixtures(hmacKey, rsaPriv, rsaPub, ecPriv, ecPub, claims);
  }

  /**
   * Resolve the fixtures directory from the {@code BENCHMARK_FIXTURES} environment variable,
   * falling back to {@code ./benchmarks/fixtures} relative to the current working directory.
   * The orchestrator sets the env var to an absolute path.
   */
  public static Fixtures loadDefault() throws Exception {
    String envPath = System.getenv("BENCHMARK_FIXTURES");
    Path dir = envPath != null ? Path.of(envPath) : Path.of("benchmarks", "fixtures");
    return load(dir);
  }

  private static PrivateKey readPrivateKey(Path path, String algorithm) throws Exception {
    byte[] der = pemToDer(Files.readString(path));
    return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
  }

  private static PublicKey readPublicKey(Path path, String algorithm) throws Exception {
    byte[] der = pemToDer(Files.readString(path));
    return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
  }

  private static byte[] pemToDer(String pem) throws IOException {
    String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                     .replaceAll("-----END [^-]+-----", "")
                     .replaceAll("\\s+", "");
    return Base64.getDecoder().decode(body);
  }
}
