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
 * Thrown by {@code OpenIDConnect.discover(...)} and {@code OpenIDConnect.discoverFromWellKnown(...)} for any
 * discovery-fetch failure: network error, non-2xx HTTP response, JSON parse error, missing {@code jwks_uri} or
 * {@code issuer} field, oversize response, redirect overflow, cross-origin redirect rejection, and the OIDC Discovery
 * 1.0 §4.3 issuer-equality mismatch.
 *
 * <p>Intentionally does <strong>not</strong> extend {@link JWTException}.
 * Discovery is a precursor to JWT verification, not a JWT operation. Putting it under {@code JWTException} would
 * mislead {@code catch} blocks targeting JWT-specific failures.</p>
 */
public class OpenIDConnectException extends RuntimeException {
  public OpenIDConnectException(String message) {
    super(message);
  }

  public OpenIDConnectException(String message, Throwable cause) {
    super(message, cause);
  }
}
