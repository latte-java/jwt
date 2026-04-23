/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 */

package org.lattejava.jwt.internal;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class MessageSanitizerTest {
  @Test
  public void null_returns_null() {
    // Use case: pass-through for absent values so callers can use the
    // sanitizer unconditionally.
    assertNull(MessageSanitizer.forMessage(null));
  }

  @Test
  public void short_printable_string_unchanged() {
    // Use case: normal header values are short and printable; no
    // transformation needed.
    assertEquals(MessageSanitizer.forMessage("JWT"), "JWT");
  }

  @Test
  public void control_characters_replaced_with_question_mark() {
    // Use case: attacker-controlled typ header with embedded CRLF must
    // not be echoed into line-delimited logs verbatim.
    assertEquals(MessageSanitizer.forMessage("foo\r\n[ERROR]"), "foo??[ERROR]");
    assertEquals(MessageSanitizer.forMessage("tab\there"), "tab?here");
  }

  @Test
  public void long_string_truncated_with_ellipsis() {
    // Use case: a 10MB typ header must not blow up downstream log
    // aggregation.
    String input = "x".repeat(300);
    String output = MessageSanitizer.forMessage(input);
    assertEquals(output.length(), 259); // 256 + "..."
    assertEquals(output.substring(0, 256), "x".repeat(256));
    assertEquals(output.substring(256), "...");
  }

  @Test
  public void exactly_256_chars_unchanged() {
    String input = "x".repeat(256);
    assertEquals(MessageSanitizer.forMessage(input), input);
  }
}
