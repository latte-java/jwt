/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;
import java.util.concurrent.atomic.*;

import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Covers {@link VerifierResolver}: the three static factories ({@code of}, {@code byKid}, {@code from}), the
 * {@code byKid} no-kid behavior, and the defense-in-depth {@code canVerify} re-check on resolved verifiers.
 *
 * @author Daniel DeGroff
 */
public class VerifierResolverTest {

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
  public void byKid_noKidInHeader_returnsNull() {
    // Use case: VerifierResolver.byKid with a header that has no kid returns null.
    Map<String, Verifier> map = new HashMap<>();
    map.put("k1", new RecordingVerifier(true));
    VerifierResolver resolver = VerifierResolver.byKid(map);
    Header header = Header.builder().alg(Algorithm.HS256).build();
    assertNull(resolver.resolve(header));
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

  @Test
  public void of_returnsNullWhenCannotVerify() {
    // Use case: VerifierResolver.of re-checks canVerify; when false, returns null.
    Verifier v = new RecordingVerifier(false);
    VerifierResolver resolver = VerifierResolver.of(v);
    Header header = Header.builder().alg(Algorithm.HS256).build();
    assertNull(resolver.resolve(header));
  }

  @Test
  public void of_returnsVerifierWhenCanVerify() {
    // Use case: VerifierResolver.of returns the verifier when canVerify is true.
    Verifier v = new RecordingVerifier(true);
    VerifierResolver resolver = VerifierResolver.of(v);
    Header header = Header.builder().alg(Algorithm.HS256).build();
    assertSame(resolver.resolve(header), v);
  }

  /**
   * Minimal {@link Verifier} that reports a configurable {@code canVerify} value.
   */
  private record RecordingVerifier(boolean canVerify) implements Verifier {

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
