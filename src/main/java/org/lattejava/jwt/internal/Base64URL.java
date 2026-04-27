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

import java.util.*;

/**
 * Centralized URL-safe Base64 codec without padding -- the variant required by RFC 7515 (JWS), RFC 7517 (JWK), and RFC
 * 7638 (JWK thumbprint).
 *
 * <p>The JDK's {@link java.util.Base64#getUrlEncoder()} returns a cached encoder that emits
 * padding; calling {@code .withoutPadding()} on it allocates a fresh {@code Encoder} on every invocation. This class
 * caches the no-padding encoder once at class-init time so the per-call allocation is eliminated. The cached encoder
 * and decoder are immutable and thread-safe per the JDK contract.</p>
 */
public final class Base64URL {
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

  private Base64URL() {
  }

  /**
   * Decode a URL-safe Base64 byte array (with or without padding) into the original bytes.
   *
   * @param bytes the URL-safe Base64 input, ASCII bytes
   * @return the decoded bytes
   * @throws IllegalArgumentException if the input is not valid URL-safe Base64
   */
  public static byte[] decode(byte[] bytes) {
    return DECODER.decode(bytes);
  }

  /**
   * Decode a URL-safe Base64 string (with or without padding) into the original bytes.
   *
   * @param s the URL-safe Base64 input
   * @return the decoded bytes
   * @throws IllegalArgumentException if the input is not valid URL-safe Base64
   */
  public static byte[] decode(String s) {
    return DECODER.decode(s);
  }

  /**
   * Encode the given bytes as URL-safe Base64 with no padding, returning a fresh byte array.
   *
   * @param bytes the bytes to encode
   * @return the URL-safe Base64 encoding, as ASCII bytes
   */
  public static byte[] encode(byte[] bytes) {
    return ENCODER.encode(bytes);
  }

  /**
   * Encode the given bytes as URL-safe Base64 with no padding, returning a String.
   *
   * @param bytes the bytes to encode
   * @return the URL-safe Base64 encoding
   */
  public static String encodeToString(byte[] bytes) {
    return ENCODER.encodeToString(bytes);
  }
}
