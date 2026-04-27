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
