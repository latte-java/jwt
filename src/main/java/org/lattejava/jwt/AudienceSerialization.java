/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

/**
 * Controls how the {@code aud} (audience) claim is serialized. Defaults to {@link #ALWAYS_ARRAY}; opt in to
 * {@link #STRING_WHEN_SINGLE} to emit a single JSON string when the audience has exactly one value.
 *
 * @author Daniel DeGroff
 */
public enum AudienceSerialization {
  /**
   * Emit {@code aud} as a JSON array of strings regardless of audience size.
   */
  ALWAYS_ARRAY,

  /**
   * Emit {@code aud} as a single JSON string when the audience has exactly one value; emit a JSON array of strings
   * otherwise.
   */
  STRING_WHEN_SINGLE
}
