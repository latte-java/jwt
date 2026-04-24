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

import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

/**
 * Covers {@link VerifierResolver}: the three static factories ({@code of},
 * {@code byKid}, {@code from}), the {@code byKid} no-kid behavior, and the
 * defense-in-depth {@code canVerify} re-check on resolved verifiers.
 *
 * @author Daniel DeGroff
 */
public class VerifierResolverTest {

  @Test
  public void of_returnsVerifierWhenCanVerify() {
    // Use case: VerifierResolver.of returns the verifier when canVerify is true.
    Verifier v = new RecordingVerifier(true);
    VerifierResolver resolver = VerifierResolver.of(v);
    Header header = Header.builder().alg(Algorithm.HS256).build();
    assertSame(resolver.resolve(header), v);
  }

  @Test
  public void of_returnsNullWhenCannotVerify() {
    // Use case: VerifierResolver.of re-checks canVerify; when false, returns null.
    Verifier v = new RecordingVerifier(false);
    VerifierResolver resolver = VerifierResolver.of(v);
    Header header = Header.builder().alg(Algorithm.HS256).build();
    assertNull(resolver.resolve(header));
  }

  @Test
  public void byKid_noKidInHeader_returnsNull() {
    // Use case: VerifierResolver.byKid with a header that has no kid returns null.
    Map<String, Verifier> map = new HashMap<>();
    map.put("k1", new RecordingVerifier(true));
    VerifierResolver resolver = VerifierResolver.byKid(map);
    Header header = Header.builder().alg(Algorithm.HS256).build();
    assertNull(resolver.resolve(header));
  }

  @Test
  public void byKid_kidMatch_returnsVerifier() {
    // Use case: VerifierResolver.byKid resolves the verifier for the header's kid when present.
    Verifier v1 = new RecordingVerifier(true);
    Verifier v2 = new RecordingVerifier(true);
    Map<String, Verifier> map = new HashMap<>();
    map.put("k1", v1);
    map.put("k2", v2);
    VerifierResolver resolver = VerifierResolver.byKid(map);
    Header header = Header.builder().alg(Algorithm.HS256).kid("k2").build();
    assertSame(resolver.resolve(header), v2);
  }

  @Test
  public void byKid_unknownKid_returnsNull() {
    // Use case: VerifierResolver.byKid with an unknown kid returns null.
    Map<String, Verifier> map = new HashMap<>();
    map.put("k1", new RecordingVerifier(true));
    VerifierResolver resolver = VerifierResolver.byKid(map);
    Header header = Header.builder().alg(Algorithm.HS256).kid("unknown").build();
    assertNull(resolver.resolve(header));
  }

  @Test
  public void from_arbitraryLambda_delegates() {
    // Use case: VerifierResolver.from delegates to an arbitrary Function<Header, Verifier>.
    Verifier v = new RecordingVerifier(true);
    AtomicReference<Header> seen = new AtomicReference<>();
    VerifierResolver resolver = VerifierResolver.from(h -> {
      seen.set(h);
      return v;
    });
    Header header = Header.builder().alg(Algorithm.RS256).kid("issuer-1").build();
    assertSame(resolver.resolve(header), v);
    assertNotNull(seen.get());
    assertSame(seen.get(), header);
  }

  /** Minimal {@link Verifier} that reports a configurable {@code canVerify} value. */
  private static final class RecordingVerifier implements Verifier {
    private final boolean canVerify;

    RecordingVerifier(boolean canVerify) {
      this.canVerify = canVerify;
    }

    @Override
    public boolean canVerify(Algorithm algorithm) {
      return canVerify;
    }

    @Override
    public void verify(byte[] message, byte[] signature) {
      // not exercised in this test
    }
  }
}
