/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.internal;

/**
 * Sanitize attacker-controlled strings before interpolation into exception messages. Applies two protections:
 * <ul>
 *   <li>Replace control characters with '?' to prevent log injection
 *       via embedded CRLF or terminal escape sequences. Covers C0
 *       (0x00-0x1F), DEL (0x7F), and C1 (0x80-0x9F) — the C1 range is
 *       interpreted by some terminals (xterm with 8-bit controls
 *       enabled) as alternate-form ANSI escape openers.</li>
 *   <li>Truncate at 256 characters with an ellipsis suffix to prevent
 *       log-volume blowup from maliciously large header values.</li>
 * </ul>
 *
 * <p>This is not a secrets protection — the values processed here
 * (typ, crit, redirect Location) are not sensitive. It is defense in
 * depth against downstream log pipelines that do not themselves escape
 * or size-limit; in the best case the receiving logger is also
 * sanitizing and this layer is redundant.</p>
 *
 * @author Daniel DeGroff
 */
public final class MessageSanitizer {
  private static final int MAX_LENGTH = 256;

  private MessageSanitizer() {
  }

  public static String forMessage(String input) {
    if (input == null) {
      return null;
    }
    StringBuilder sb = new StringBuilder(Math.min(input.length(), MAX_LENGTH));
    int limit = Math.min(input.length(), MAX_LENGTH);
    for (int i = 0; i < limit; i++) {
      char c = input.charAt(i);
      // Strip C0 (0x00-0x1F), DEL (0x7F), and C1 (0x80-0x9F) controls.
      sb.append((c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F)) ? '?' : c);
    }
    if (input.length() > MAX_LENGTH) {
      sb.append("...");
    }
    return sb.toString();
  }
}
