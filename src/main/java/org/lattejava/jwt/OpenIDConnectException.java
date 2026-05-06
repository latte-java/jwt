/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

/**
 * Thrown by {@code OpenIDConnect.discover(...)} and {@code OpenIDConnect.discoverFromWellKnown(...)} for any
 * discovery-fetch failure: network error, non-2xx HTTP response, JSON parse error, missing {@code jwks_uri} or
 * {@code issuer} field, oversize response, redirect overflow, cross-origin redirect rejection, and the OIDC Discovery
 * 1.0 §4.3 issuer-equality mismatch.
 *
 * <p>Intentionally does <strong>not</strong> extend {@link JWTException}.
 * Discovery is a precursor to JWT verification, not a JWT operation. Putting it under {@code JWTException} would
 * mislead {@code catch} blocks targeting JWT-specific failures.</p>
 */
public class OpenIDConnectException extends RuntimeException {
  public OpenIDConnectException(String message) {
    super(message);
  }

  public OpenIDConnectException(String message, Throwable cause) {
    super(message, cause);
  }
}
