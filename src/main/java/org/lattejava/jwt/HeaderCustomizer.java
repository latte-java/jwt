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

/**
 * Subset of {@link Header.Builder} exposed to {@link JWTEncoder#encode}
 * callers. Per spec §5, this interface intentionally omits {@code alg()} --
 * the algorithm is always determined by the {@link Signer} and cannot be
 * overridden by the caller. The type system enforces that the header
 * {@code alg} matches the actual signing algorithm.
 *
 * <p>{@link #kid(String)} can be called to override or clear (pass
 * {@code null}) the {@code kid} inherited from the signer. Other parameters
 * ({@code typ}, {@code cty}, {@code x5t}, etc.) can be set freely via
 * {@link #typ(String)} and {@link #parameter(String, Object)}.</p>
 *
 * @author The Latte Project
 */
public interface HeaderCustomizer {
  /**
   * Set the {@code typ} header parameter (RFC 7515 §4.1.9). Pass {@code null}
   * to clear.
   *
   * @param type the type value (e.g. "JWT", "at+jwt"), or null to clear
   * @return this customizer
   */
  HeaderCustomizer typ(String type);

  /**
   * Override or clear the {@code kid} header parameter. By default the
   * encoder pre-populates {@code kid} from {@link Signer#kid()}; calling
   * this method with a non-null value overrides that, and passing
   * {@code null} clears it.
   *
   * @param keyId the key id, or null to clear
   * @return this customizer
   */
  HeaderCustomizer kid(String keyId);

  /**
   * Set an arbitrary header parameter. Passing a {@code null} value clears
   * the parameter. The parameter name must NOT be {@code "alg"}; attempting
   * to set {@code "alg"} via this method throws
   * {@link IllegalArgumentException} so that the spec invariant
   * "header.alg() == signer.algorithm()" is preserved at runtime in case a
   * caller routes the literal string {@code "alg"} through here.
   *
   * @param name  the parameter name
   * @param value the parameter value, or null to clear
   * @return this customizer
   * @throws IllegalArgumentException if {@code name} is {@code "alg"}
   */
  HeaderCustomizer parameter(String name, Object value);
}
