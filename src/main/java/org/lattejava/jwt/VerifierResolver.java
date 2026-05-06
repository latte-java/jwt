/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;
import java.util.function.*;

/**
 * Resolves a {@link Verifier} for a given JWT {@link Header}. Returning {@code null} means "no verifier for this
 * header" -- the decoder then throws {@link MissingVerifierException}.
 *
 * <p>Regardless of which resolver is used, {@link JWTDecoder} re-checks
 * {@code verifier.canVerify(header.alg())} on the returned verifier as defense-in-depth. A verifier whose
 * {@code canVerify} returns false for the header's algorithm is treated the same as a {@code null} resolver result
 * ({@link MissingVerifierException}).</p>
 *
 * @author Daniel DeGroff
 */
public interface VerifierResolver {
  /**
   * Look up a verifier by the header's {@code kid}. Returns {@code null} if {@code kid} is absent from the header OR if
   * the header's {@code kid} is not a key in the map.
   *
   * <p>This is intentional: {@code byKid} is for applications that identify
   * keys by {@code kid}, and a token without a {@code kid} is not verifiable under this strategy. Callers wanting
   * "try-by-kid-then-fall-back" should compose resolvers explicitly or use {@link #from(Function)}.</p>
   *
   * @param map kid → verifier map; must be non-null
   * @return a resolver that returns the verifier for the header's kid, or null
   */
  static VerifierResolver byKid(Map<String, Verifier> map) {
    Objects.requireNonNull(map, "map");
    return header -> header.kid() == null ? null : map.get(header.kid());
  }

  /**
   * Arbitrary resolver, for cases where {@code kid}-based lookup is insufficient (e.g., resolution by {@code iss}, by
   * {@code x5t}, or via an out-of-band registry). The decoder still invokes {@link Verifier#canVerify(Algorithm)} on
   * the returned verifier; a verifier that returns false from {@code canVerify} for the header's algorithm is rejected
   * with {@link MissingVerifierException}.
   *
   * @param fn the resolver function; must be non-null
   * @return a resolver delegating to {@code fn}
   */
  static VerifierResolver from(Function<Header, Verifier> fn) {
    Objects.requireNonNull(fn, "fn");
    return fn::apply;
  }

  /**
   * Always return the given verifier (after the verifier's {@link Verifier#canVerify(Algorithm)} check passes for the
   * header's algorithm). When {@code canVerify} returns false the resolver yields {@code null}, which the decoder
   * reports as {@link MissingVerifierException}.
   *
   * @param v the verifier to wrap; must be non-null
   * @return a resolver that returns {@code v} when it can verify the header's alg
   */
  static VerifierResolver of(Verifier v) {
    Objects.requireNonNull(v, "verifier");
    return header -> v.canVerify(header.alg()) ? v : null;
  }

  /**
   * Return the verifier for this header, or {@code null} if none applies.
   *
   * @param header the parsed JOSE header
   * @return the matching verifier, or null
   */
  Verifier resolve(Header header);
}
