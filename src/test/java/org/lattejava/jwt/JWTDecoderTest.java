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

import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Comprehensive {@link JWTDecoder} coverage: time validation, expectedType,
 * expectedAlgorithms (incl. broken-equals Algorithm),
 * maxInputBytes/maxNestingDepth/maxNumberLength boundaries,
 * allowDuplicateJSONKeys, tampered payload, custom validator, signature-
 * before-parse ordering, and crit understood-parameters check.
 *
 * @author Daniel DeGroff
 */
public class JWTDecoderTest {
  private static final String SECRET = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static String b64(String raw) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  private static Verifier verifier() {
    return HMACVerifier.newVerifier(SECRET);
  }

  private static Signer signer() {
    return HMACSigner.newSHA256Signer(SECRET);
  }

  // ---------------------------------------------------------------------
  // Time validation: expired, not-yet-valid, clock skew matrix
  // ---------------------------------------------------------------------

  @DataProvider(name = "timeCases")
  public Object[][] timeCases() {
    Instant base = Instant.parse("2026-04-22T12:00:00Z");
    return new Object[][] {
        // (subject, exp offset sec, nbf offset sec, clockSkewSec, decoder Now, expected exception or null)
        // Strict default: exp at -1 -> expired
        {"expired-strict", -1L, null, 0L, base, JWTExpiredException.class},
        // Strict default: nbf at +1 -> not yet
        {"nbf-future-strict", 3600L, 1L, 0L, base, JWTUnavailableForProcessingException.class},
        // Skew: exp at -5, skew 10s -> still valid
        {"expired-but-skew-rescues", -5L, null, 10L, base, null},
        // Skew: nbf at +5, skew 10s -> valid
        {"nbf-but-skew-rescues", 3600L, 5L, 10L, base, null},
        // Skew is symmetric: exp at -11, skew 10s -> still expired
        {"expired-beyond-skew", -11L, null, 10L, base, JWTExpiredException.class},
        // Plenty of validity, skew 0
        {"valid-no-skew", 3600L, -3600L, 0L, base, null},
    };
  }

  @Test(dataProvider = "timeCases")
  public void timeValidation(String subject, Long expOffset, Long nbfOffset, long skewSec,
                             Instant fakeNow, Class<? extends Exception> expectedException) {
    // Use case: time validation matrix (exp/nbf x clock skew).
    JWT.Builder b = JWT.builder().subject(subject).issuedAt(fakeNow);
    if (expOffset != null) b.expiresAt(fakeNow.plusSeconds(expOffset));
    if (nbfOffset != null) b.notBefore(fakeNow.plusSeconds(nbfOffset));
    JWT jwt = b.build();

    String encoded = new JWTEncoder().encode(jwt, signer());

    JWTDecoder decoder = JWTDecoder.builder()
        .clock(Clock.fixed(fakeNow, ZoneOffset.UTC))
        .clockSkew(Duration.ofSeconds(skewSec))
        .build();
    try {
      JWT decoded = decoder.decode(encoded, VerifierResolver.of(verifier()));
      if (expectedException != null) {
        fail("Expected [" + expectedException.getSimpleName() + "] for [" + subject + "]");
      }
      assertNotNull(decoded);
    } catch (Exception e) {
      if (expectedException == null || !expectedException.isAssignableFrom(e.getClass())) {
        throw new AssertionError("Mismatch for [" + subject + "]: expected="
            + (expectedException == null ? "no exception" : expectedException.getSimpleName())
            + " got=" + e.getClass().getSimpleName(), e);
      }
    }
  }

  // ---------------------------------------------------------------------
  // expectedType
  // ---------------------------------------------------------------------

  @DataProvider(name = "expectedTypeCases")
  public Object[][] expectedTypeCases() {
    return new Object[][] {
        // expected, headerTyp, shouldThrow
        {"JWT", "JWT", false},
        {"JWT", "jwt", false},  // case-insensitive
        {"jwt", "JWT", false},
        {"at+jwt", "AT+JWT", false},
        {"at+jwt", "JWT", true},  // mismatch
        {"at+jwt", null, true},   // missing typ
    };
  }

  @Test(dataProvider = "expectedTypeCases")
  public void expectedType(String expected, String headerTyp, boolean shouldThrow) {
    // Use case: expectedType case-insensitive match, mismatch, missing typ.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = headerTyp == null
        ? new JWTEncoder().encode(jwt, signer(), b -> b.typ(null))
        : new JWTEncoder().encode(jwt, signer(), b -> b.typ(headerTyp));

    JWTDecoder decoder = JWTDecoder.builder().expectedType(expected).build();
    try {
      decoder.decode(encoded, VerifierResolver.of(verifier()));
      if (shouldThrow) {
        fail("Expected InvalidJWTException for typ=" + headerTyp + " expected=" + expected);
      }
    } catch (InvalidJWTException e) {
      if (!shouldThrow) {
        throw new AssertionError("Did not expect InvalidJWTException for typ=" + headerTyp, e);
      }
    }
  }

  // ---------------------------------------------------------------------
  // expectedAlgorithms (set, miss, broken-equals custom Algorithm)
  // ---------------------------------------------------------------------

  @Test
  public void expectedAlgorithms_match_accepted() {
    // Use case: expectedAlgorithms set; header alg in set -> accepted.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    JWTDecoder decoder = JWTDecoder.builder()
        .expectedAlgorithms(new HashSet<>(Collections.singletonList(Algorithm.HS256)))
        .build();
    JWT decoded = decoder.decode(encoded, VerifierResolver.of(verifier()));
    assertNotNull(decoded);
  }

  @Test
  public void expectedAlgorithms_miss_rejected() {
    // Use case: expectedAlgorithms set; header alg NOT in set -> rejected before verifier selection.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    JWTDecoder decoder = JWTDecoder.builder()
        .expectedAlgorithms(new HashSet<>(Collections.singletonList(Algorithm.RS256)))
        .build();
    try {
      decoder.decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected InvalidJWTException for alg not in expectedAlgorithms");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void expectedAlgorithms_brokenEquals_matchesByName() {
    // Use case: expectedAlgorithms with a custom Algorithm whose equals is Object-identity
    // still matches by name().
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    Set<Algorithm> set = new HashSet<>();
    set.add(new BrokenEqualsAlgorithm("HS256"));
    JWTDecoder decoder = JWTDecoder.builder().expectedAlgorithms(set).build();
    JWT decoded = decoder.decode(encoded, VerifierResolver.of(verifier()));
    assertNotNull(decoded);
  }

  // ---------------------------------------------------------------------
  // Size / depth / number-length boundaries
  // ---------------------------------------------------------------------

  @Test
  public void maxInputBytes_boundary() {
    // Use case: maxInputBytes boundary -- exactly N accepted, N+1 rejected.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer());
    int len = encoded.getBytes(StandardCharsets.UTF_8).length;

    JWTDecoder.builder().maxInputBytes(len).build()
        .decode(encoded, VerifierResolver.of(verifier())); // exactly N -> accepted

    try {
      JWTDecoder.builder().maxInputBytes(len - 1).build()
          .decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected InvalidJWTException for maxInputBytes < length");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void maxNestingDepth_boundary() {
    // Use case: maxNestingDepth boundary -- depth N accepted, depth N+1 rejected.
    StringBuilder nested = new StringBuilder();
    int depth = 6;
    for (int i = 0; i < depth; i++) nested.append("{\"a\":");
    nested.append("1");
    for (int i = 0; i < depth; i++) nested.append("}");

    String header = b64("{\"alg\":\"HS256\"}");
    String payload = b64("{\"sub\":\"abc\",\"deep\":" + nested + "}");
    String unsignedPrefix = header + "." + payload;
    byte[] sig = ((HMACSigner) signer()).sign(unsignedPrefix.getBytes(StandardCharsets.UTF_8));
    String token = unsignedPrefix + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

    JWTDecoder.builder().maxNestingDepth(depth + 5).build()
        .decode(token, VerifierResolver.of(verifier())); // accepted

    try {
      JWTDecoder.builder().maxNestingDepth(2).build()
          .decode(token, VerifierResolver.of(verifier()));
      fail("Expected JSONProcessingException at low depth");
    } catch (JSONProcessingException expected) {
      // good
    }
  }

  @Test
  public void maxNumberLength_boundary() {
    // Use case: maxNumberLength boundary -- a 1001-digit JSON number rejected when limit is 1000.
    StringBuilder digits = new StringBuilder();
    for (int i = 0; i < 1001; i++) digits.append('1');

    String header = b64("{\"alg\":\"HS256\"}");
    String payload = b64("{\"sub\":\"abc\",\"big\":" + digits + "}");
    String unsignedPrefix = header + "." + payload;
    byte[] sig = ((HMACSigner) signer()).sign(unsignedPrefix.getBytes(StandardCharsets.UTF_8));
    String token = unsignedPrefix + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

    try {
      JWTDecoder.builder().maxNumberLength(1000).build()
          .decode(token, VerifierResolver.of(verifier()));
      fail("Expected JSONProcessingException for over-long number");
    } catch (JSONProcessingException expected) {
      // good
    }

    JWTDecoder.builder().maxNumberLength(1001).build()
        .decode(token, VerifierResolver.of(verifier())); // accepted at boundary
  }

  // ---------------------------------------------------------------------
  // Duplicate JSON keys
  // ---------------------------------------------------------------------

  @Test
  public void duplicateJsonKeys_default_vs_opt_in() {
    // Use case: duplicate JSON keys rejected by default; accepted when allowDuplicateJSONKeys=true.
    String header = b64("{\"alg\":\"HS256\"}");
    String payload = b64("{\"sub\":\"abc\",\"sub\":\"def\"}");
    String unsignedPrefix = header + "." + payload;
    byte[] sig = ((HMACSigner) signer()).sign(unsignedPrefix.getBytes(StandardCharsets.UTF_8));
    String token = unsignedPrefix + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

    try {
      new JWTDecoder().decode(token, VerifierResolver.of(verifier()));
      fail("Expected JSONProcessingException for duplicate JSON key (default)");
    } catch (JSONProcessingException expected) {
      // good
    }

    JWT decoded = JWTDecoder.builder().allowDuplicateJSONKeys(true).build()
        .decode(token, VerifierResolver.of(verifier()));
    assertNotNull(decoded);
  }

  // ---------------------------------------------------------------------
  // Tampered payload
  // ---------------------------------------------------------------------

  @Test
  public void tamperedPayload_rejected() {
    // Use case: tampered payload (signature unchanged) -> InvalidJWTSignatureException.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    String[] parts = encoded.split("\\.", -1);
    String evilPayload = b64("{\"sub\":\"hacked\"}");
    String tampered = parts[0] + "." + evilPayload + "." + parts[2];

    try {
      new JWTDecoder().decode(tampered, VerifierResolver.of(verifier()));
      fail("Expected InvalidJWTSignatureException for tampered payload");
    } catch (InvalidJWTSignatureException expected) {
      // good
    }
  }

  // ---------------------------------------------------------------------
  // Custom validator
  // ---------------------------------------------------------------------

  @Test
  public void customValidator_issuerMismatch_throws() {
    // Use case: custom validator throws when issuer does not match expected.
    JWT jwt = JWT.builder().subject("abc").issuer("evil-issuer").build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    try {
      new JWTDecoder().decode(encoded, VerifierResolver.of(verifier()), decoded -> {
        if (!"expected-issuer".equals(decoded.issuer())) {
          throw new InvalidJWTException("Unexpected issuer: " + decoded.issuer());
        }
      });
      fail("Expected InvalidJWTException from validator");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void customValidator_issuerMatch_passes() {
    // Use case: custom validator runs and accepts a valid issuer.
    JWT jwt = JWT.builder().subject("abc").issuer("good").build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    JWT decoded = new JWTDecoder().decode(encoded, VerifierResolver.of(verifier()), d -> {
      if (!"good".equals(d.issuer())) throw new InvalidJWTException("nope");
    });
    assertNotNull(decoded);
  }

  // ---------------------------------------------------------------------
  // Signature-before-parse ordering
  // ---------------------------------------------------------------------

  @Test
  public void signatureBeforeParseOrdering() {
    // Use case: a token with valid header, BAD signature, and a payload that would
    // throw on parse (e.g. malformed JSON) must surface the signature failure FIRST,
    // not the JSON parse failure -- unauthenticated payloads must never be parsed
    // into JWT objects.
    String header = b64("{\"alg\":\"HS256\"}");
    // Payload that is NOT valid JSON -- if parsing ran first, this would throw
    // JSONProcessingException; the signature failure must surface first.
    String poisonPayload = b64("{not-valid-json");
    String unsignedPrefix = header + "." + poisonPayload;
    // Use a wrong signature: random bytes signed by a different key.
    byte[] wrongSig = HMACSigner.newSHA256Signer("wrong-key-but-also-32-bytes-long-aaaaaaaa")
        .sign(unsignedPrefix.getBytes(StandardCharsets.UTF_8));
    String token = unsignedPrefix + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(wrongSig);

    try {
      new JWTDecoder().decode(token, VerifierResolver.of(verifier()));
      fail("Expected InvalidJWTSignatureException to fire before payload parse");
    } catch (InvalidJWTSignatureException expected) {
      // good -- signature verification fired before payload parse
    } catch (JSONProcessingException jpe) {
      throw new AssertionError(
          "Ordering violation: payload parsed BEFORE signature was verified", jpe);
    }
  }

  // ---------------------------------------------------------------------
  // crit understood-parameters check
  // ---------------------------------------------------------------------

  @Test
  public void crit_unrecognized_rejected() {
    // Use case: crit listing an unknown name -> InvalidJWTException.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer(),
        b -> b.parameter("crit", Collections.singletonList("foo")).parameter("foo", "bar"));

    try {
      new JWTDecoder().decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected InvalidJWTException for unrecognized crit");
    } catch (InvalidJWTException expected) {
      // good
    }
  }

  @Test
  public void crit_registered_accepted() {
    // Use case: crit listing a name registered in criticalHeaders -> accepted.
    JWT jwt = JWT.builder().subject("abc").build();
    String encoded = new JWTEncoder().encode(jwt, signer(),
        b -> b.parameter("crit", Collections.singletonList("foo")).parameter("foo", "bar"));

    JWTDecoder decoder = JWTDecoder.builder()
        .criticalHeaders(new HashSet<>(Collections.singletonList("foo")))
        .build();
    JWT decoded = decoder.decode(encoded, VerifierResolver.of(verifier()));
    assertEquals(decoded.subject(), "abc");
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  /** Custom Algorithm with Object-identity equals/hashCode -- decoder must still match by name(). */
  private static final class BrokenEqualsAlgorithm implements Algorithm {
    private final String name;

    BrokenEqualsAlgorithm(String name) {
      this.name = name;
    }

    @Override
    public String name() {
      return name;
    }
    // intentionally inherits Object.equals / Object.hashCode (identity-based)
  }

  // ---------------------------------------------------------------------
  // Builder reusability (Javadoc contract: build() produces a new immutable decoder; the builder may be reused)
  // ---------------------------------------------------------------------

  @Test
  public void expired_exception_exposes_diagnostic_context() {
    Instant now = Instant.parse("2026-04-22T12:00:00Z");
    Instant exp = now.minusSeconds(30);
    // Use case: library consumers diagnosing clock-sync issues need to see the exp claim, the clock reading, and the applied skew.
    JWT jwt = JWT.builder().subject("s").expiresAt(exp).build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    JWTDecoder decoder = JWTDecoder.builder()
        .clock(Clock.fixed(now, ZoneOffset.UTC))
        .clockSkew(Duration.ZERO)
        .build();
    try {
      decoder.decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected JWTExpiredException");
    } catch (JWTExpiredException e) {
      assertEquals(e.getExpiration(), exp);
      assertEquals(e.getNow(), now);
      assertEquals(e.getClockSkew(), Duration.ZERO);
    }
  }

  @Test
  public void not_before_exception_exposes_diagnostic_context() {
    Instant now = Instant.parse("2026-04-22T12:00:00Z");
    Instant nbf = now.plusSeconds(30);
    Instant exp = now.plusSeconds(3600);
    // Use case: library consumers diagnosing clock-sync issues need to see the nbf claim, the clock reading, and the applied skew.
    JWT jwt = JWT.builder().subject("s").notBefore(nbf).expiresAt(exp).build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    JWTDecoder decoder = JWTDecoder.builder()
        .clock(Clock.fixed(now, ZoneOffset.UTC))
        .clockSkew(Duration.ZERO)
        .build();
    try {
      decoder.decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected JWTUnavailableForProcessingException");
    } catch (JWTUnavailableForProcessingException e) {
      assertEquals(e.getNotBefore(), nbf);
      assertEquals(e.getNow(), now);
      assertEquals(e.getClockSkew(), Duration.ZERO);
    }
  }

  @Test
  public void builder_reuse_producesIndependentDecoders() {
    // Use case: building twice from the same builder with a mutated clockSkew between calls must produce two independent decoders.
    Instant fakeNow = Instant.parse("2026-04-22T12:00:00Z");
    JWT jwt = JWT.builder()
        .subject("s")
        .issuedAt(fakeNow.minusSeconds(600))
        .expiresAt(fakeNow.minusSeconds(5))
        .build();
    String encoded = new JWTEncoder().encode(jwt, signer());

    JWTDecoder.Builder b = JWTDecoder.builder()
        .clock(Clock.fixed(fakeNow, ZoneOffset.UTC))
        .clockSkew(Duration.ZERO);
    JWTDecoder strict = b.build();
    try {
      strict.decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected JWTExpiredException under strict (zero-skew) decoder.");
    } catch (JWTExpiredException expected) {
    }

    b.clockSkew(Duration.ofSeconds(30));
    JWTDecoder lenient = b.build();
    assertNotNull(lenient.decode(encoded, VerifierResolver.of(verifier())));
    try {
      strict.decode(encoded, VerifierResolver.of(verifier()));
      fail("Original decoder must not have inherited the mutated clockSkew.");
    } catch (JWTExpiredException expected) {
    }
  }

  @Test
  public void builder_reuse_criticalHeaders_defensiveCopy() {
    // Use case: mutating the caller-supplied critical-headers set after build() must not leak into the already-built decoder.
    HashSet<String> crit = new HashSet<>();
    crit.add("org.lattejava.test.required");
    JWTDecoder.Builder b = JWTDecoder.builder().criticalHeaders(crit);
    JWTDecoder first = b.build();

    crit.add("org.lattejava.test.other");
    b.criticalHeaders(Collections.emptySet());
    JWTDecoder second = b.build();

    // Token declares "org.lattejava.test.required" in its crit list. `first` understands it (pass); `second` was built after the set was cleared (reject).
    JWT jwt = JWT.builder().subject("s").build();
    String encoded = new JWTEncoder().encode(jwt, signer(), h ->
        h.parameter("crit", java.util.List.of("org.lattejava.test.required"))
            .parameter("org.lattejava.test.required", "v"));

    assertNotNull(first.decode(encoded, VerifierResolver.of(verifier())));
    try {
      second.decode(encoded, VerifierResolver.of(verifier()));
      fail("Expected InvalidJWTException: second decoder must not see the original critical-headers set.");
    } catch (InvalidJWTException expected) {
    }
  }
}
