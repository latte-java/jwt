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
import org.lattejava.jwt.InvalidKeyLengthException;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.JWT;
import org.lattejava.jwt.JWTDecoder;
import org.lattejava.jwt.JWTEncoder;
import org.lattejava.jwt.LatteJSONProcessor;
import org.lattejava.jwt.MissingSignatureException;
import org.lattejava.jwt.MissingVerifierException;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.VerifierResolver;
import org.lattejava.jwt.algorithm.ec.ECSigner;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.testng.annotations.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.function.Consumer;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * RFC 8725 (BCP 225) compliance suite. Each test method maps directly to one
 * row of the spec §15 compliance matrix and documents the BCP item it
 * validates with a {@code // RFC 8725 §X.Y - <item>} comment.
 *
 * @author The Latte Project
 */
public class RFC8725ComplianceTest extends BaseJWTTest {
  private static final String HMAC_SECRET_32 = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static String b64(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  // RFC 8725 §2.1 - "none" alg attack rejected
  @Test
  public void rfc8725_section_2_1_noneAlgAttackRejected() {
    String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
    String payload = b64("{\"sub\":\"abc\"}");
    String token = header + "." + payload + ".";
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(hmac)));
  }

  // RFC 8725 §2.1 - HMAC-with-RSA-public-key (cross-algorithm) attack rejected
  @Test
  public void rfc8725_section_2_1_hmacWithRsaPublicKeyAttackRejected() throws Exception {
    JWT jwt = JWT.builder().subject("abc").build();
    String rsaPub = new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem")));
    String forged = new JWTEncoder().encode(jwt, HMACSigner.newSHA512Signer(rsaPub));

    Verifier rsaVerifier = RSAVerifier.newVerifier(rsaPub);
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(forged, VerifierResolver.of(rsaVerifier)));
  }

  // RFC 8725 §2.1 - signature stripping rejected (MissingSignatureException)
  @Test
  public void rfc8725_section_2_1_signatureStrippingRejected() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    String stripped = token.substring(0, token.lastIndexOf('.'));

    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    expectException(MissingSignatureException.class, () ->
        new JWTDecoder().decode(stripped, VerifierResolver.of(hmac)));
  }

  // RFC 8725 §3.1 - algorithm verification: header alg must match verifier's canVerify
  @Test
  public void rfc8725_section_3_1_algorithmVerificationViaCanVerify() throws Exception {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, ECSigner.newSHA256Signer(readFile("ec_private_key_p_256.pem")));
    Verifier rsaVerifier = RSAVerifier.newVerifier(
        new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(rsaVerifier)));
  }

  // RFC 8725 §3.1 - expectedAlgorithms whitelist rejects out-of-set alg before verifier selection
  @Test
  public void rfc8725_section_3_1_expectedAlgorithmsWhitelistRejectsOutOfSet() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));

    JWTDecoder decoder = new JWTDecoder.Builder()
        .expectedAlgorithms(new HashSet<>(Collections.singletonList(Algorithm.RS256)))
        .build();
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    expectException(InvalidJWTException.class, () ->
        decoder.decode(token, VerifierResolver.of(hmac)));
  }

  // RFC 8725 §2.2 - HS256 with 31-byte secret rejected (InvalidKeyLengthException) -- weak symmetric key
  @Test
  public void rfc8725_section_2_2_weakSymmetricKeyRejected() {
    byte[] tooShort = new byte[31];
    Verifier verifier = HMACVerifier.newVerifier(tooShort);

    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt,
        HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    expectException(InvalidKeyLengthException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(verifier)));
  }

  // RFC 8725 §3.5 - RSA 1024-bit key rejected (InvalidKeyLengthException) -- insufficient entropy
  @Test
  public void rfc8725_section_3_5_rsa1024BitKeyRejected() {
    String pem = readFile("rsa_public_key_1024.pem");
    expectException(InvalidKeyLengthException.class, () -> RSAVerifier.newVerifier(pem));
  }

  // RFC 8725 §3.11 - expectedType accepts matching typ
  @Test
  public void rfc8725_section_3_11_expectedTypeAcceptsMatchingTyp() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt,
        HMACSigner.newSHA256Signer(HMAC_SECRET_32),
        b -> b.typ("at+jwt"));

    JWTDecoder decoder = new JWTDecoder.Builder().expectedType("at+jwt").build();
    JWT decoded = decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    assertEquals(decoded.subject(), "abc");
  }

  // RFC 8725 §3.11 - expectedType rejects mismatched typ
  @Test
  public void rfc8725_section_3_11_expectedTypeRejectsMismatchedTyp() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt,
        HMACSigner.newSHA256Signer(HMAC_SECRET_32),
        b -> b.typ("dpop+jwt"));

    JWTDecoder decoder = new JWTDecoder.Builder().expectedType("at+jwt").build();
    expectException(InvalidJWTException.class, () ->
        decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32))));
  }

  // RFC 8725 §3.12 - verifier per algorithm family (binding enforced via canVerify)
  @Test
  public void rfc8725_section_3_12_verifierPerAlgorithmFamilyBoundViaCanVerify() throws Exception {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));

    Verifier rsaVerifier = RSAVerifier.newVerifier(
        new String(Files.readAllBytes(Paths.get("src/test/resources/rsa_public_key_2048.pem"))));
    expectException(MissingVerifierException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(rsaVerifier)));
  }

  // RFC 8725 §2.6 - Multiplicity of JSON encodings (base64url strictness)
  @Test
  public void rfc8725_section_2_6_base64UrlStrictDecoding() {
    // Header encoded with standard base64 ("+", "/", padding) is rejected.
    String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9+." + b64("{\"sub\":\"abc\"}") + ".sig";
    expectException(InvalidJWTException.class, () ->
        new JWTDecoder().decode(token, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32))));
  }

  // RFC 8725 §2.6 - LatteJSONProcessor rejects duplicate JSON keys by default
  @Test
  public void rfc8725_section_2_6_duplicateJsonKeysRejected() {
    LatteJSONProcessor proc = new LatteJSONProcessor();
    byte[] dup = "{\"a\":1,\"a\":2}".getBytes(StandardCharsets.UTF_8);
    expectException(JSONProcessingException.class, () -> proc.deserialize(dup));
  }

  // RFC 8725 §2.8 - Cross-JWT confusion -- expectedType + expectedAlgorithms enforce mutual exclusivity
  @Test
  public void rfc8725_section_2_8_crossJwtConfusionViaTypAndAlg() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt,
        HMACSigner.newSHA256Signer(HMAC_SECRET_32),
        b -> b.typ("at+jwt"));

    // Decoder configured for ID tokens (typ=id+jwt) rejects an at+jwt token.
    JWTDecoder idTokenDecoder = new JWTDecoder.Builder()
        .expectedType("id+jwt")
        .expectedAlgorithms(new HashSet<>(Collections.singletonList(Algorithm.HS256)))
        .build();
    expectException(InvalidJWTException.class, () ->
        idTokenDecoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32))));
  }

  // RFC 8725 §3.2 - Use appropriate algorithms (no Algorithm.NONE constant)
  @Test
  public void rfc8725_section_3_2_noNoneAlgorithmConstant() throws Exception {
    for (java.lang.reflect.Field f : Algorithm.class.getFields()) {
      if (Modifier.isStatic(f.getModifiers()) && f.getType() == Algorithm.class) {
        Algorithm a = (Algorithm) f.get(null);
        if (a == null) continue;
        assertTrue(!"none".equalsIgnoreCase(a.name()),
            "Library must not expose a public 'none' Algorithm constant; found " + f.getName());
      }
    }
  }

  // RFC 8725 §3.3 - Validate all cryptographic operations: verifier failure throws
  @Test
  public void rfc8725_section_3_3_verifierFailureThrows() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    char last = token.charAt(token.length() - 1);
    String tampered = token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');

    expectException(InvalidJWTSignatureException.class, () ->
        new JWTDecoder().decode(tampered, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32))));
  }

  // RFC 8725 §3.4 - Validate cryptographic inputs (maxInputBytes / maxNestingDepth)
  @Test
  public void rfc8725_section_3_4_inputSizeCapped() {
    JWTDecoder decoder = new JWTDecoder.Builder().maxInputBytes(100).build();
    String header = b64("{\"alg\":\"HS256\"}");
    String payload = b64("{\"sub\":\"" + "a".repeat(200) + "\"}");
    String token = header + "." + payload + ".sig";
    expectException(InvalidJWTException.class, () ->
        decoder.decode(token, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32))));
  }

  // RFC 8725 §3.7 - UTF-8 used for all JSON and base64url decoding (round-trip non-ASCII)
  @Test
  public void rfc8725_section_3_7_utf8UsedThroughout() {
    JWT jwt = JWT.builder().subject("résumé—\u00e9").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    JWT decoded = new JWTDecoder().decode(token,
        VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    assertEquals(decoded.subject(), "résumé—\u00e9");
  }

  // RFC 8725 §3.8 - Validate issuer and subject (Caller responsibility)
  // Verifies that the documented Consumer<JWT> validator hook exists and
  // propagates exceptions thrown from the validator.
  @Test
  public void rfc8725_section_3_8_validatorHookPropagatesIssuerCheck() {
    JWT jwt = JWT.builder().subject("abc").issuer("evil-issuer").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));

    Consumer<JWT> issuerCheck = decoded -> {
      if (!"good-issuer".equals(decoded.issuer())) {
        throw new InvalidJWTException("issuer not allowed: " + decoded.issuer());
      }
    };
    expectException(InvalidJWTException.class, () ->
        new JWTDecoder().decode(token,
            VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)),
            issuerCheck));
  }

  // RFC 8725 §3.9 - Use and validate audience (Caller responsibility);
  // jwt.audience() always returns a List<String> and hasAudience(String) is provided.
  @Test
  public void rfc8725_section_3_9_audienceListAndHasAudienceHelper() {
    JWT jwt = JWT.builder().subject("abc")
        .audience(java.util.Arrays.asList("svc-a", "svc-b")).build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    JWT decoded = new JWTDecoder().decode(token,
        VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    assertNotNull(decoded.audience());
    assertTrue(decoded.hasAudience("svc-a"));
    assertTrue(decoded.hasAudience("svc-b"));
    assertTrue(!decoded.hasAudience("svc-c"));
  }

  // RFC 8725 §3.10 - Do not trust received claims: signature verified BEFORE payload parsing.
  // (Defense-in-depth: a tampered/garbage payload fails signature verification before the
  // payload is ever surfaced through a JWT object.)
  @Test
  public void rfc8725_section_3_10_signatureVerifiedBeforePayloadParse() {
    JWT jwt = JWT.builder().subject("abc").build();
    String token = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    String[] parts = token.split("\\.");
    // Replace payload with valid base64url that decodes to a non-object JSON
    // value, leaving the original signature in place. Signature verification
    // must fail before payload parsing is attempted.
    String tampered = parts[0] + "." + b64("\"not-an-object\"") + "." + parts[2];
    expectException(InvalidJWTSignatureException.class, () ->
        new JWTDecoder().decode(tampered, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32))));
  }

  // RFC 8725 §3.10 - Caller-supplied Consumer<JWT> validator runs AFTER signature/time validation.
  // This test confirms the documented hook exists with the expected signature.
  @Test
  public void rfc8725_section_3_10_validatorHookSignatureExists() throws Exception {
    Method m = JWTDecoder.class.getMethod("decode", String.class, VerifierResolver.class, Consumer.class);
    assertNotNull(m, "JWTDecoder.decode(String, VerifierResolver, Consumer<JWT>) must exist");
  }
}
