/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

/**
 * Thrown by {@link Verifiers#fromJWK} when a JSON Web Key cannot be turned into a {@link Verifier}. {@link #reason()}
 * carries the categorical reason so callers can dispatch programmatically (e.g. log security-relevant rejections such
 * as {@link Reason#ALG_CRV_MISMATCH} at warn while logging benign ones at debug).
 */
public final class InvalidJWKException extends JWTException {
  private final Reason reason;

  public InvalidJWKException(Reason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public InvalidJWKException(Reason reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }

  /**
   * Categorical reason a JWK was rejected.
   */
  public enum Reason {
    /**
     * {@code alg}, {@code kty}, and {@code crv} are mutually inconsistent (e.g. {@code ES256} with {@code crv=P-384}).
     */
    ALG_CRV_MISMATCH,
    /**
     * {@code alg} is one of {@code HS256}, {@code HS384}, {@code HS512} (symmetric secrets do not belong on a public
     * JWKS).
     */
    HMAC_ALG,
    /**
     * {@code kty} is {@code oct} (symmetric secrets do not belong on a public JWKS).
     */
    KTY_OCT,
    /**
     * {@code alg} is missing.
     */
    MISSING_ALG,
    /**
     * {@code kid} is missing.
     */
    MISSING_KID,
    /**
     * Key material did not parse cleanly, or verifier construction failed.
     */
    PARSE_FAILURE,
    /**
     * {@code use} is present and not {@code sig} (e.g. {@code enc}).
     */
    USE_ENC
  }
}
