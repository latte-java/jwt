/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

/**
 * Subset of {@link Header.Builder} exposed to {@link JWTEncoder#encode} callers. This interface intentionally omits
 * {@code alg()} -- the algorithm is always determined by the {@link Signer} and cannot be overridden by the caller. The
 * type system enforces that the header {@code alg} matches the actual signing algorithm.
 *
 * <p>{@link #kid(String)} can be called to override or clear (pass
 * {@code null}) the {@code kid} inherited from the signer. Other parameters ({@code typ}, {@code cty}, {@code x5t},
 * etc.) can be set freely via {@link #typ(String)} and {@link #parameter(String, Object)}.</p>
 *
 * @author Daniel DeGroff
 */
public interface HeaderCustomizer {
  /**
   * Override or clear the {@code kid} header parameter. By default the encoder pre-populates {@code kid} from
   * {@link Signer#kid()}; calling this method with a non-null value overrides that, and passing {@code null} clears
   * it.
   *
   * @param keyId the key id, or null to clear
   * @return this customizer
   */
  HeaderCustomizer kid(String keyId);

  /**
   * Set an arbitrary header parameter. Passing a {@code null} value clears the parameter. The parameter name must NOT
   * be {@code "alg"}; attempting to set {@code "alg"} via this method throws {@link IllegalArgumentException} so the
   * invariant {@code header.alg() == signer.algorithm()} is preserved at runtime even when a caller routes the literal
   * string {@code "alg"} through here.
   *
   * @param name  the parameter name
   * @param value the parameter value, or null to clear
   * @return this customizer
   * @throws IllegalArgumentException if {@code name} is {@code "alg"}
   */
  HeaderCustomizer parameter(String name, Object value);

  /**
   * Set the {@code typ} header parameter (RFC 7515 §4.1.9). Pass {@code null} to clear.
   *
   * @param type the type value (e.g. "JWT", "at+jwt"), or null to clear
   * @return this customizer
   */
  HeaderCustomizer typ(String type);
}
