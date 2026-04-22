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

package org.lattejava.jwt;

// HeaderCustomizer compiles without .alg() -- type-system enforcement that
// the encoded header's algorithm always matches the Signer's algorithm.

import org.lattejava.jwt.algorithm.ec.ECSigner;
import org.lattejava.jwt.algorithm.ec.ECVerifier;
import org.lattejava.jwt.algorithm.ed.EdDSASigner;
import org.lattejava.jwt.algorithm.ed.EdDSAVerifier;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAPSSSigner;
import org.lattejava.jwt.algorithm.rsa.RSAPSSVerifier;
import org.lattejava.jwt.algorithm.rsa.RSASigner;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.function.Supplier;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Round-trip {@link JWTEncoder} coverage. Sweeps every algorithm family via
 * a DataProvider over (algorithm, signer-supplier, verifier-supplier) and
 * exercises the {@link HeaderCustomizer} surface.
 *
 * @author The Latte Project
 */
public class JWTEncoderTest {
  private static final String HMAC_SECRET_32 = "super-secret-key-that-is-at-least-32-bytes-long!!";
  private static final String HMAC_SECRET_64 =
      "super-secret-key-that-is-at-least-64-bytes-long-for-sha512-algorithm-compat-requirement!!";

  private static String readFile(String name) {
    try {
      return new String(Files.readAllBytes(Paths.get("src/test/resources/" + name)));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static Path getPath(String name) {
    return Paths.get("src/test/resources/" + name);
  }

  @DataProvider(name = "algorithms")
  public Object[][] algorithms() {
    return new Object[][] {
        {Algorithm.HS256,
            (Supplier<Signer>) () -> HMACSigner.newSHA256Signer(HMAC_SECRET_32),
            (Supplier<Verifier>) () -> HMACVerifier.newVerifier(HMAC_SECRET_32)},
        {Algorithm.HS384,
            (Supplier<Signer>) () -> HMACSigner.newSHA384Signer(HMAC_SECRET_64),
            (Supplier<Verifier>) () -> HMACVerifier.newVerifier(HMAC_SECRET_64)},
        {Algorithm.HS512,
            (Supplier<Signer>) () -> HMACSigner.newSHA512Signer(HMAC_SECRET_64),
            (Supplier<Verifier>) () -> HMACVerifier.newVerifier(HMAC_SECRET_64)},
        {Algorithm.RS256,
            (Supplier<Signer>) () -> RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"))},
        {Algorithm.RS384,
            (Supplier<Signer>) () -> RSASigner.newSHA384Signer(readFile("rsa_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"))},
        {Algorithm.RS512,
            (Supplier<Signer>) () -> RSASigner.newSHA512Signer(readFile("rsa_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"))},
        {Algorithm.PS256,
            (Supplier<Signer>) () -> RSAPSSSigner.newSHA256Signer(readFile("rsa_pss_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAPSSVerifier.newVerifier(readFile("rsa_pss_public_key_2048.pem"))},
        {Algorithm.ES256,
            (Supplier<Signer>) () -> ECSigner.newSHA256Signer(readFile("ec_private_key_p_256.pem")),
            (Supplier<Verifier>) () -> ECVerifier.newVerifier(readFile("ec_public_key_p_256.pem"))},
        {Algorithm.ES384,
            (Supplier<Signer>) () -> ECSigner.newSHA384Signer(readFile("ec_private_key_p_384.pem")),
            (Supplier<Verifier>) () -> ECVerifier.newVerifier(readFile("ec_public_key_p_384.pem"))},
        {Algorithm.ES512,
            (Supplier<Signer>) () -> ECSigner.newSHA512Signer(readFile("ec_private_key_p_521.pem")),
            (Supplier<Verifier>) () -> ECVerifier.newVerifier(readFile("ec_public_key_p_521.pem"))},
        {Algorithm.Ed25519,
            (Supplier<Signer>) () -> EdDSASigner.newSigner(readFile("ed_dsa_ed25519_private_key.pem")),
            (Supplier<Verifier>) () -> EdDSAVerifier.newVerifier(getPath("ed_dsa_ed25519_public_key.pem"))},
        {Algorithm.Ed448,
            (Supplier<Signer>) () -> EdDSASigner.newSigner(readFile("ed_dsa_ed448_private_key.pem")),
            (Supplier<Verifier>) () -> EdDSAVerifier.newVerifier(getPath("ed_dsa_ed448_public_key.pem"))},
    };
  }

  @Test(dataProvider = "algorithms")
  public void roundTrip(Algorithm alg, Supplier<Signer> signerFactory, Supplier<Verifier> verifierFactory) {
    // Use case: every supported algorithm round-trips encode -> decode and preserves all claims.
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    JWT original = JWT.builder()
        .subject("subject-" + alg.name())
        .issuer("issuer")
        .audience("aud-1")
        .issuedAt(now)
        .expiresAt(now.plus(1, ChronoUnit.HOURS))
        .id("jwt-id")
        .claim("custom", "value")
        .build();

    String encoded = new JWTEncoder().encode(original, signerFactory.get());
    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(verifierFactory.get()));

    assertEquals(decoded.header().alg().name(), alg.name(),
        "encoded header.alg must equal signer.algorithm()");
    assertTrue(original.claimsEquals(decoded),
        "round-trip claims should match: original=" + original + " decoded=" + decoded);
  }

  @Test
  public void customizer_setsTypAndParameter_butNotAlg() {
    // Use case: HeaderCustomizer can set typ and arbitrary parameters; the encoded header's
    // alg still equals signer.algorithm() (both as a runtime check and because HeaderCustomizer
    // has no .alg() method -- compile-time guarantee).
    JWT jwt = JWT.builder().subject("abc").build();
    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32);

    String encoded = new JWTEncoder().encode(jwt, signer, b -> {
      b.typ("at+jwt");
      b.parameter("cty", "application/json");
    });

    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    Header h = decoded.header();
    assertEquals(h.typ(), "at+jwt");
    assertEquals(h.get("cty"), "application/json");
    // Spec invariant: header.alg().name() == signer.algorithm().name()
    assertEquals(h.alg().name(), signer.algorithm().name());
  }

  @Test
  public void customizer_parameterAlg_rejected() {
    // Use case: HeaderCustomizer.parameter("alg", x) is rejected at runtime as
    // defense-in-depth (the type system already prevents .alg(...) calls).
    JWT jwt = JWT.builder().subject("abc").build();
    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32);
    try {
      new JWTEncoder().encode(jwt, signer, b -> b.parameter("alg", "none"));
      fail("Expected IllegalArgumentException for parameter(\"alg\", ...)");
    } catch (IllegalArgumentException expected) {
      // good
    }
  }

  @Test
  public void encoder_preserves_signerKid() {
    // Use case: encoder pre-populates kid from signer.kid() when the signer has one.
    JWT jwt = JWT.builder().subject("abc").build();
    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32.getBytes(), "key-1");
    String encoded = new JWTEncoder().encode(jwt, signer);

    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    assertEquals(decoded.header().kid(), "key-1");
  }

  @Test
  public void customizer_kidNull_clears() {
    // Use case: HeaderCustomizer.kid(null) clears the signer-derived kid.
    JWT jwt = JWT.builder().subject("abc").build();
    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32.getBytes(), "key-1");
    String encoded = new JWTEncoder().encode(jwt, signer, b -> b.kid(null));

    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    assertEquals(decoded.header().kid(), null);
  }

  @Test
  public void customizer_kidOverride() {
    // Use case: HeaderCustomizer.kid("override") replaces signer-derived kid.
    JWT jwt = JWT.builder().subject("abc").build();
    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32.getBytes(), "key-1");
    String encoded = new JWTEncoder().encode(jwt, signer, b -> b.kid("override"));

    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(HMACVerifier.newVerifier(HMAC_SECRET_32)));
    assertEquals(decoded.header().kid(), "override");
  }

  @Test
  public void encoded_threeSegments() {
    // Use case: the encoded JWT is exactly three '.'-separated segments.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, HMACSigner.newSHA256Signer(HMAC_SECRET_32));
    assertNotNull(encoded);
    long dots = encoded.chars().filter(c -> c == '.').count();
    assertEquals(dots, 2L);
  }
}
