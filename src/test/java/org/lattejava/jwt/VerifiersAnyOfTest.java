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
import org.lattejava.jwt.algorithm.rsa.RSASigner;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Coverage of {@code Verifiers.anyOf}:
 * <ul>
 *   <li>{@code canVerify} returns true if ANY delegate's {@code canVerify} is true.</li>
 *   <li>{@code verify} invokes the FIRST matching delegate; the exception from that
 *       delegate propagates (no fall-through to subsequent verifiers).</li>
 *   <li>{@code MissingVerifierException} is thrown if no delegate matches.</li>
 *   <li>Empty list at construction time is rejected with
 *       {@link IllegalArgumentException} so misuse surfaces immediately.</li>
 *   <li>Custom {@code Algorithm} implementations with broken {@code equals} still
 *       work because the dispatch is keyed on {@code Algorithm.name()}.</li>
 * </ul>
 *
 * @author Daniel DeGroff
 */
public class VerifiersAnyOfTest {
  private static final String HMAC_SECRET_32 = "super-secret-key-that-is-at-least-32-bytes-long!!";

  private static String readFile(String name) {
    try {
      return new String(Files.readAllBytes(Paths.get("src/test/resources/" + name)));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void anyOf_picksMatchingDelegate() {
    // Use case: First matching verifier is used (ordered delegation). Two verifiers,
    // each accepting a distinct algorithm; signatures from each round-trip through anyOf.
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    Verifier rsa = RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"));
    Verifier composite = Verifiers.anyOf(hmac, rsa);

    assertTrue(composite.canVerify(Algorithm.HS256));
    assertTrue(composite.canVerify(Algorithm.RS256));
    assertFalse(composite.canVerify(Algorithm.ES256));

    Signer hmacSigner = HMACSigner.newSHA256Signer(HMAC_SECRET_32);
    byte[] msg = "msg".getBytes(StandardCharsets.UTF_8);
    composite.verify(Algorithm.HS256, msg, hmacSigner.sign(msg));

    Signer rsaSigner = RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem"));
    composite.verify(Algorithm.RS256, msg, rsaSigner.sign(msg));
  }

  @Test
  public void anyOf_noMatchThrowsMissingVerifier() {
    // Use case: No matching verifier throws MissingVerifierException.
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    Verifier composite = Verifiers.anyOf(hmac);

    assertFalse(composite.canVerify(Algorithm.RS256));
    assertThrows(MissingVerifierException.class,
        () -> composite.verify(Algorithm.RS256,
            "m".getBytes(StandardCharsets.UTF_8),
            new byte[]{0}));
  }

  @Test
  public void anyOf_singleVerifierBehavesAsPassThrough() {
    // Use case: Single verifier behaves identically to direct use.
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    Verifier composite = Verifiers.anyOf(hmac);
    assertTrue(composite.canVerify(Algorithm.HS256));

    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32);
    byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
    composite.verify(Algorithm.HS256, msg, signer.sign(msg));
  }

  @Test
  public void anyOf_failFastOnFirstMatchInvalidSignature() {
    // Use case: Fail-fast -- first canVerify match that fails verify propagates the
    // exception immediately. The second verifier (which would have matched and might
    // even succeed) is NOT consulted.
    Verifier first = HMACVerifier.newVerifier(HMAC_SECRET_32);
    AtomicInteger secondCalls = new AtomicInteger();
    Verifier second = new Verifier() {
      @Override public boolean canVerify(Algorithm a) {
        return a.name().equals("HS256");
      }
      @Override public void verify(Algorithm a, byte[] m, byte[] s) {
        secondCalls.incrementAndGet();
      }
    };
    Verifier composite = Verifiers.anyOf(first, second);

    // bogus signature -- HMACVerifier (first match) will throw; second is never called
    assertThrows(InvalidJWTSignatureException.class,
        () -> composite.verify(Algorithm.HS256,
            "m".getBytes(StandardCharsets.UTF_8),
            new byte[32]));
    assertEquals(secondCalls.get(), 0,
        "Second verifier must not be invoked once first match throws");
  }

  @Test
  public void anyOf_emptyVarargsThrowsAtConstruction() {
    // Use case: Empty list rejected at construction so the caller sees the misuse immediately
    // rather than later discovering that every verify() call throws MissingVerifierException.
    assertThrows(IllegalArgumentException.class, () -> Verifiers.anyOf());
  }

  @Test
  public void anyOf_emptyArrayThrowsAtConstruction() {
    Verifier[] empty = new Verifier[0];
    assertThrows(IllegalArgumentException.class, () -> Verifiers.anyOf(empty));
  }

  @Test
  public void anyOf_nullArrayThrows() {
    assertThrows(NullPointerException.class, () -> Verifiers.anyOf((Verifier[]) null));
  }

  @Test
  public void anyOf_nullElementThrows() {
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    assertThrows(NullPointerException.class, () -> Verifiers.anyOf(hmac, null));
  }

  @Test
  public void anyOf_customAlgorithmWithBrokenEqualsRoutedByName() {
    // Use case: Custom Algorithm impl with broken equals still works because the dispatch
    // is keyed on Algorithm.name().
    // Custom algorithm whose name is "HS256" but whose equals() always returns false.
    Algorithm broken = new Algorithm() {
      @Override public String name() { return "HS256"; }
      @Override public boolean equals(Object o) { return false; }
      @Override public int hashCode() { return 0; }
    };
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    Verifier composite = Verifiers.anyOf(hmac);
    assertTrue(composite.canVerify(broken),
        "anyOf must consult delegate.canVerify(broken) which keys off name(), not equals()");

    Signer signer = HMACSigner.newSHA256Signer(HMAC_SECRET_32);
    byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
    composite.verify(broken, msg, signer.sign(msg));
  }

  // Sanity: composite returned from anyOf must not be null.
  @Test
  public void anyOf_returnsNonNull() {
    Verifier hmac = HMACVerifier.newVerifier(HMAC_SECRET_32);
    assertNotNull(Verifiers.anyOf(hmac));
  }
}
