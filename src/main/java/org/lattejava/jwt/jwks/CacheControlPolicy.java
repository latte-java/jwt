/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.jwks;

/**
 * Governs how {@code JWKS} interprets the JWKS endpoint's {@code Cache-Control} response header.
 */
public enum CacheControlPolicy {
  /**
   * Clamp the server's {@code max-age} into {@code [minRefreshInterval, refreshInterval]}.
   */
  CLAMP,
  /**
   * Ignore the server's {@code max-age}; always refresh on the configured interval.
   */
  IGNORE
}
