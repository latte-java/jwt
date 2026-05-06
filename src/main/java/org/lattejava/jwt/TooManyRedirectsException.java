/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

/**
 * Thrown when an HTTP-fetching helper (e.g. {@link org.lattejava.jwt.jwks.JWKS} or
 * {@link org.lattejava.jwt.OpenIDConnect#discover(String)}) follows more redirects than allowed by its
 * {@code maxRedirects} configuration.
 *
 * @author Daniel DeGroff
 */
public class TooManyRedirectsException extends JWTException {
  public TooManyRedirectsException(String message) {
    super(message);
  }

  public TooManyRedirectsException(String message, Throwable cause) {
    super(message, cause);
  }
}
