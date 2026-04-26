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

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.JWTException;

/**
 * Thrown by {@link JWKSource#refresh()} when an operator-driven refresh fails.
 * {@link #reason()} carries the categorical reason so callers can dispatch
 * programmatically without inspecting the cause chain.
 */
public final class JWKSRefreshException extends JWTException {
  private final Reason reason;

  public JWKSRefreshException(Reason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public JWKSRefreshException(Reason reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }

  /**
   * Categorical reason a refresh failed.
   */
  public enum Reason {
    /** Every JWK in the fetched JWKS was rejected by {@code Verifiers.fromJWK}, or the JWKS contained no keys. */
    EMPTY_RESULT,
    /** Network-level failure: connect timeout, read timeout, DNS resolution, etc. */
    NETWORK,
    /** HTTP response had a non-2xx status code. The cause is an {@code HTTPResponseException}. */
    NON_2XX,
    /** JWKS document failed to parse as JSON, or the JWK structure was invalid. */
    PARSE,
    /** The awaiter timed out waiting for a singleflight refresh to complete. The fetch itself may still complete asynchronously. */
    TIMEOUT
  }
}
