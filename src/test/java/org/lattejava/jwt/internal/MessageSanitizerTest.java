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
