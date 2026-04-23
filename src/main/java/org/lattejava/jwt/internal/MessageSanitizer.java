/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 */

package org.lattejava.jwt.internal;

/**
 * Sanitize attacker-controlled strings before interpolation into
 * exception messages. Applies two protections:
 * <ul>
 *   <li>Replace ASCII control characters (below 0x20) with '?' to
 *       prevent log injection via embedded CRLF or terminal escape
 *       sequences.</li>
 *   <li>Truncate at 256 characters with an ellipsis suffix to prevent
 *       log-volume blowup from maliciously large header values.</li>
 * </ul>
 *
 * <p>This is not a secrets protection — the values processed here
 * (typ, crit, redirect Location) are not sensitive. It is insurance
 * against downstream log pipelines that do not themselves escape or
 * size-limit.</p>
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
      sb.append(c < 0x20 ? '?' : c);
    }
    if (input.length() > MAX_LENGTH) {
      sb.append("...");
    }
    return sb.toString();
  }
}
