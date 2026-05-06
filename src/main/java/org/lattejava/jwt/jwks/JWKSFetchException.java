/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.*;

/**
 * Thrown by JWKS-endpoint fetches: {@link JWKS#refresh()} on a remote-backed JWKS, {@code JWKS.fetch(...)} (one-shot),
 * and the initial fetch performed inside {@code Builder.build()} when {@code failFast == true} and the JWKS hop fails.
 * {@link #reason()} carries the categorical reason so callers can dispatch programmatically without inspecting the
 * cause chain.
 */
public final class JWKSFetchException extends JWTException {
  private final Reason reason;

  public JWKSFetchException(Reason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public JWKSFetchException(Reason reason, String message, Throwable cause) {
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
    /**
     * Every JWK in the fetched JWKS was rejected by {@code Verifiers.fromJWK}, or the JWKS contained no keys.
     */
    EMPTY_RESULT,
    /**
     * Network-level failure: connect timeout, read timeout, DNS resolution, etc.
     */
    NETWORK,
    /**
     * HTTP response had a non-2xx status code. The cause is an {@code HTTPResponseException}.
     */
    NON_2XX,
    /**
     * JWKS document failed to parse as JSON, or the JWK structure was invalid.
     */
    PARSE,
    /**
     * The awaiter timed out waiting for a singleflight refresh to complete. The fetch itself may still complete
     * asynchronously.
     */
    TIMEOUT
  }
}
