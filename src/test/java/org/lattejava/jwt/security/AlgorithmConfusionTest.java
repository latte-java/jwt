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

package org.lattejava.jwt.security;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.InvalidJWTException;
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.lattejava.jwt.MissingVerifierException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.algorithm.ec.ECSigner;
import org.lattejava.jwt.algorithm.ec.ECVerifier;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSASigner;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Algorithm confusion and {@code none}: security suite that proves the
 * decoder rejects every documented algorithm-confusion path.
 *
 * @author Daniel DeGroff
 */
public class AlgorithmConfusionTest extends BaseJWTTest {
  private static final String HMAC_SECRET_32 = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static final String HMAC_SECRET_64 = "super-secret-key-that-is-at-least-64-bytes-long-for-sha512-algorithm-compat-requirement!!";

  private static String b64(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  // ---------------------------------------------------------------------
  // "none" attacks (DataProvider over case variants)
  // ---------------------------------------------------------------------

  @DataProvider(name = "noneCaseVariants")
  public Object[][] noneCaseVariants() {
    return new Object[][] {
        {"none"},
        {"None"},
        {"NONE"},
        {"nOnE"},
    };
  }

  @Test(dataProvider = "noneCaseVariants")
  public void noneAlgorithm_alwaysRejected(String alg) {
    // Use case: Algorithm "none" attack -- DataProvider over case variants -- each
    // produces a non-standard Algorithm whose name does not match any built-in
    // verifier; all rejected with MissingVerifierException.
    String header = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String signature = b64("anything");
    String token = header + "." + payload + "." + signature;

    Verifier hmac = HMACVerifier.newVerifier(Algorithm.HS256, HMAC_SECRET_32);
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(hmac)));
  }

  // ---------------------------------------------------------------------
  // RSA public key abused as HMAC secret (ports 6.x test_vulnerability_HMAC_forgery)
  // ---------------------------------------------------------------------

  @Test
  public void hmacForgeryWithRsaPublicKey_singleRsaVerifierRejects() throws Exception {
    // Use case: Algorithm confusion -- RSA public key material used as an HMAC
    // secret; a single RSA verifier rejects (canVerify returns false for HS*).
    JWT jwt = JWT.builder().subject("123456789").build();
    String rsaPub = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem")));
    // Forge an HMAC-signed token using the RSA public key bytes as the "shared secret".
    String forged = new JWTEncoder().encode(jwt, HMACSigner.newSHA512Signer(rsaPub), b -> b.kid("abc"));

    Verifier rsaVerifier = RSAVerifier.newVerifier(Algorithm.RS256, rsaPub);
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(forged, VerifierResolver.of(rsaVerifier)));
  }

  @Test
  public void hmacForgery_kidMap_realSecretVerifier_rejects() throws Exception {
    // Use case: Algorithm confusion -- forged HMAC token routed via
    // Map<String, Verifier> with the kid pointing at a real-shared-secret
    // HMAC verifier. The verifier rejects because the forged signature was
    // produced with the RSA public-key bytes, not the real secret.
    JWT jwt = JWT.builder().subject("123456789").build();
    String rsaPub = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem")));
    String forged = new JWTEncoder().encode(jwt, HMACSigner.newSHA512Signer(rsaPub), b -> b.kid("hmac"));

    Map<String, Verifier> verifiers = new HashMap<>();
    verifiers.put("hmac", HMACVerifier.newVerifier(Algorithm.HS512, HMAC_SECRET_64));

    expectException(InvalidJWTSignatureException.class, () ->
        new JWTDecoder().decode(forged, VerifierResolver.byKid(verifiers)));
  }

  // ---------------------------------------------------------------------
  // Cross-algorithm rejection
  // ---------------------------------------------------------------------

  @Test
  public void crossAlgorithm_ecToken_rsaVerifier_rejected() throws Exception {
    // Use case: Cross-algorithm -- EC-signed token presented to RSA verifier.
    // RSA verifier's canVerify returns false for ES* -> MissingVerifierException.
    JWT jwt = JWT.builder().subject("123").build();
    String encoded = new JWTEncoder().encode(jwt, ECSigner.newSHA256Signer(readFile("ec_private_key_p_256.pem")));

    Verifier rsaVerifier = RSAVerifier.newVerifier(Algorithm.RS256,
        new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(encoded, VerifierResolver.of(rsaVerifier)));
  }

  @Test
  public void crossAlgorithm_rsaToken_ecVerifier_rejected() throws Exception {
    // Use case: Cross-algorithm -- RSA-signed token presented to EC verifier.
    JWT jwt = JWT.builder().subject("123").build();
    String rsaPriv = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_private_key_2048.pem")));
    String encoded = new JWTEncoder().encode(jwt, RSASigner.newSHA256Signer(rsaPriv));

    Verifier ecVerifier = ECVerifier.newVerifier(readFile("ec_public_key_p_256.pem"));
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(encoded, VerifierResolver.of(ecVerifier)));
  }

  // ---------------------------------------------------------------------
  // Algorithm-name tampering (header [alg] value mutated from the standard)
  // ---------------------------------------------------------------------

  @DataProvider(name = "tamperedAlgNames")
  public Object[][] tamperedAlgNames() {
    // Each variant mutates the JWA name so the decoder must NOT resolve it
    // to the HS256 constant (exact string match per RFC 7515 §4.1.1).
    return new Object[][] {
        {""},                 // empty string
        {" HS256"},           // leading whitespace
        {"HS256 "},           // trailing whitespace
        {"HS257"},            // typo - not a real JWA name
        {"hs256"},            // wrong case (JWA names are case-sensitive)
        {"HS256\u200B"},      // trailing zero-width space
    };
  }

  @Test(dataProvider = "tamperedAlgNames")
  public void tamperedAlgName_rejected(String alg) {
    // Use case: Header [alg] name is mutated from the exact JWA string
    // "HS256"; the decoder must treat the tampered value as a non-standard
    // algorithm that no verifier can handle, producing
    // MissingVerifierException rather than silently accepting an HS256
    // verifier for a mismatched header.
    String header = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String signature = b64("anything");
    String token = header + "." + payload + "." + signature;

    Verifier hmac = HMACVerifier.newVerifier(Algorithm.HS256, HMAC_SECRET_32);
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(hmac)));
  }

  @Test
  public void missingAlgHeader_rejected() {
    // Use case: Header with no [alg] member is rejected at parse time -- the
    // decoder never reaches verifier selection for an unsigned header.
    String header = b64("{\"typ\":\"JWT\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String signature = b64("anything");
    String token = header + "." + payload + "." + signature;

    Verifier hmac = HMACVerifier.newVerifier(Algorithm.HS256, HMAC_SECRET_32);
    expectException(InvalidJWTException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(hmac)));
  }

  @Test
  public void headerAlgMismatch_hs512HeaderOverHs256Signature_rejected() {
    // Use case: Header claims [alg=HS512] but the signature bytes were
    // produced by HS256. The HS512 verifier runs HS512-MAC over the signing
    // input and compares against the attacker-supplied signature -- the
    // comparison must fail with InvalidJWTSignatureException, never succeed
    // by accidentally accepting the shorter HS256 MAC.
    JWT jwt = JWT.builder().subject("123").build();
    // Sign with HS256 -> 32-byte MAC.
    String hs256Encoded = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_64));
    // Strip the HS256 header and prepend a fake HS512 header over the same
    // payload+signature. The HS256 signature bytes are now presented under
    // alg=HS512.
    String payload = hs256Encoded.split("\\.")[1];
    String sig256 = hs256Encoded.split("\\.")[2];
    String fakeHeader = b64("{\"alg\":\"HS512\",\"typ\":\"JWT\"}");
    String forged = fakeHeader + "." + payload + "." + sig256;

    Verifier hs512 = HMACVerifier.newVerifier(Algorithm.HS512, HMAC_SECRET_64);
    expectException(InvalidJWTSignatureException.class, () ->
        new JWTDecoder().decode(forged, VerifierResolver.of(hs512)));
  }
}
