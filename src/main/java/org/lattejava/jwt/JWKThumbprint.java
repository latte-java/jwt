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

import org.lattejava.jwt.jwks.JSONWebKey;

import java.util.Base64;

/**
 * RFC 7638 / RFC 8037 JWK Thumbprint computation.
 *
 * <p>Thumbprint bytes are computed from a canonical JSON serialization of
 * the key's required member subset (RFC 7638 §3.2 / RFC 8037 §2) using an
 * internal canonical writer, NOT the user-pluggable JSON processor -- this
 * guarantees thumbprint bytes are independent of which JSON library is
 * configured.</p>
 *
 * <p>Use {@link #compute(String, JSONWebKey)} to obtain the raw digest
 * bytes, and {@link #base64url(byte[])} to produce the RFC 7515
 * base64url-no-pad encoding used in JWK {@code kid} / {@code x5t} fields.</p>
 *
 * @author Daniel DeGroff
 */
public final class JWKThumbprint {

  private JWKThumbprint() {
  }

  /**
   * Base64url-encode the given digest bytes (no padding), as required by
   * RFC 7515 / RFC 7638 for use in JWK {@code kid} values.
   *
   * @param digest the raw digest bytes
   * @return the base64url encoding of {@code digest} without padding
   */
  public static String base64url(byte[] digest) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  /**
   * Computes the JWK thumbprint of {@code key} using the given JCA digest
   * algorithm name (e.g. {@code "SHA-1"} or {@code "SHA-256"}) and returns
   * the raw digest bytes.
   *
   * <p>Use {@link #base64url(byte[])} to obtain the RFC 7515
   * base64url-no-pad encoding suitable for JWK {@code kid}.</p>
   *
   * @param algorithm the JCA digest algorithm name; non-null
   * @param key       the JWK; non-null and {@code key.kty} must be set
   * @return the raw digest bytes
   * @throws IllegalArgumentException if {@code key.kty} is null or
   *                                  unsupported, or if {@code algorithm} is
   *                                  unknown
   */
  public static byte[] compute(String algorithm, JSONWebKey key) {
    return org.lattejava.jwt.internal.JWKThumbprint.computeBytes(algorithm, key);
  }
}
