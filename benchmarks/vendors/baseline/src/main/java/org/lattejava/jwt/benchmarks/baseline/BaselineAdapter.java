/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.baseline;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.lattejava.jwt.benchmarks.harness.BenchmarkAlgorithm;
import org.lattejava.jwt.benchmarks.harness.Fixtures;
import org.lattejava.jwt.benchmarks.harness.JwtBenchmarkAdapter;

/**
 * Theoretical-floor reference: the minimum honest JWT path on top of plain JCA.
 * Uses precomputed header bytes per algorithm and hand-rolls base64URL + a one-shot
 * sign call. No external dependencies.
 *
 * Validation is simplified: presence-only checks on iss/aud, numeric exp/nbf windowing
 * against a fixed "now" — enough to be honest, not enough to be a real library.
 */
public final class BaselineAdapter implements JwtBenchmarkAdapter {

  private static final Base64.Decoder B64D = Base64.getUrlDecoder();
  private static final Base64.Encoder B64E = Base64.getUrlEncoder().withoutPadding();

  private byte[] claimsJson;
  private PrivateKey ecPrivate;
  private PublicKey ecPublic;
  // Pre-built header.payload pairs keyed by algorithm.
  private byte[] es256HeaderPayload;
  // Fixed "now" = iat + 30 minutes, in epoch seconds.
  private long fixedNowEpochSeconds;
  private byte[] hmacKey;
  private byte[] hs256HeaderPayload;
  private PrivateKey rsaPrivate;
  private PublicKey rsaPublic;
  private byte[] rs256HeaderPayload;

  @Override
  public void prepare(Fixtures fixtures) {
    this.hmacKey = fixtures.hmacKey;
    this.rsaPrivate = fixtures.rsaPrivate;
    this.rsaPublic = fixtures.rsaPublic;
    this.ecPrivate = fixtures.ecPrivate;
    this.ecPublic = fixtures.ecPublic;
    this.claimsJson = fixtures.claimsJsonBytes;
    this.fixedNowEpochSeconds = 1761408000L + 1800L;

    this.es256HeaderPayload = headerPayload("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
    this.hs256HeaderPayload = headerPayload("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    this.rs256HeaderPayload = headerPayload("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
  }

  @Override
  public String encode(BenchmarkAlgorithm alg) throws Exception {
    return switch (alg) {
      case ES256 -> encodeAsymmetric(es256HeaderPayload, "SHA256withECDSA", ecPrivate, true);
      case HS256 -> encodeHMAC();
      case RS256 -> encodeAsymmetric(rs256HeaderPayload, "SHA256withRSA", rsaPrivate, false);
    };
  }

  @Override
  public Object decodeVerifyValidate(BenchmarkAlgorithm alg, String token) throws Exception {
    int firstDot = token.indexOf('.');
    int secondDot = token.indexOf('.', firstDot + 1);
    if (firstDot < 0 || secondDot < 0) throw new IllegalArgumentException("malformed token");
    String headerPayload = token.substring(0, secondDot);
    byte[] signature = B64D.decode(token.substring(secondDot + 1));
    byte[] payload = B64D.decode(token.substring(firstDot + 1, secondDot));

    switch (alg) {
      case ES256 -> {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(ecPublic);
        sig.update(headerPayload.getBytes(StandardCharsets.US_ASCII));
        byte[] der = EcdsaSigConverter.joseToDer(signature, 32);
        if (!sig.verify(der)) throw new SecurityException("ECDSA verify failed");
      }
      case HS256 -> {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        byte[] expected = mac.doFinal(headerPayload.getBytes(StandardCharsets.US_ASCII));
        if (!MessageDigest.isEqual(expected, signature)) throw new SecurityException("HMAC mismatch");
      }
      case RS256 -> {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(rsaPublic);
        sig.update(headerPayload.getBytes(StandardCharsets.US_ASCII));
        if (!sig.verify(signature)) throw new SecurityException("RSA verify failed");
      }
    }
    validate(payload);
    return payload;
  }

  @Override
  public Object unsafeDecodeClaims(String token) {
    // Claims-only: base64-decode the payload segment to bytes. No JSON parse, no header.
    int firstDot = token.indexOf('.');
    int secondDot = token.indexOf('.', firstDot + 1);
    return B64D.decode(token.substring(firstDot + 1, secondDot));
  }

  @Override
  public Object unsafeDecodeFull(String token) {
    // Full: decode header + payload to two byte arrays; aggregate is the work being measured.
    int firstDot = token.indexOf('.');
    int secondDot = token.indexOf('.', firstDot + 1);
    byte[] header = B64D.decode(token.substring(0, firstDot));
    byte[] payload = B64D.decode(token.substring(firstDot + 1, secondDot));
    return new byte[][]{header, payload};
  }

  private String encodeAsymmetric(byte[] headerPayload, String jcaAlg, PrivateKey key, boolean derToJOSE) throws Exception {
    Signature sig = Signature.getInstance(jcaAlg);
    sig.initSign(key);
    sig.update(headerPayload);
    byte[] raw = sig.sign();
    byte[] out = derToJOSE ? EcdsaSigConverter.derToJOSE(raw, 32) : raw;
    return new String(headerPayload, StandardCharsets.US_ASCII) + "." + B64E.encodeToString(out);
  }

  private String encodeHMAC() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
    byte[] sig = mac.doFinal(hs256HeaderPayload);
    return new String(hs256HeaderPayload, StandardCharsets.US_ASCII) + "." + B64E.encodeToString(sig);
  }

  private byte[] headerPayload(String headerJSON) {
    String header = B64E.encodeToString(headerJSON.getBytes(StandardCharsets.UTF_8));
    String payload = B64E.encodeToString(claimsJson);
    return (header + "." + payload).getBytes(StandardCharsets.US_ASCII);
  }

  private void validate(byte[] payload) {
    String body = new String(payload, StandardCharsets.UTF_8);
    long exp = readEpochSeconds(body, "\"exp\":");
    long nbf = readEpochSeconds(body, "\"nbf\":");
    if (fixedNowEpochSeconds < nbf) throw new IllegalStateException("nbf in future");
    if (fixedNowEpochSeconds >= exp) throw new IllegalStateException("expired");
    if (!body.contains("\"iss\": \"https://benchmarks.lattejava.org\"")) throw new IllegalStateException("iss missing or invalid");
    if (!body.contains("\"aud\": \"benchmark-audience\"")) throw new IllegalStateException("aud missing or invalid");
  }

  private static long readEpochSeconds(String body, String fieldKey) {
    int idx = body.indexOf(fieldKey);
    if (idx < 0) throw new IllegalStateException("missing [" + fieldKey + "]");
    int start = idx + fieldKey.length();
    while (start < body.length() && body.charAt(start) == ' ') start++;
    int end = start;
    while (end < body.length() && Character.isDigit(body.charAt(end))) end++;
    return Long.parseLong(body, start, end, 10);
  }
}
