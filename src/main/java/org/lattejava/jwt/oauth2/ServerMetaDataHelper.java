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

package org.lattejava.jwt.oauth2;

import org.lattejava.jwt.AbstractHttpHelper;
import org.lattejava.jwt.jwks.JSONWebKeySetHelper;

import java.net.HttpURLConnection;
import java.util.Objects;

/**
 * Fetches RFC 8414 OAuth 2.0 Authorization Server Metadata from a well-known
 * discovery endpoint, with the same response-hardening defaults as
 * {@link JSONWebKeySetHelper} (per-hop body cap, manual redirect counting).
 *
 * @author Daniel DeGroff
 */
public class ServerMetaDataHelper extends AbstractHttpHelper {
  private static volatile int maxResponseSize = DEFAULT_MAX_RESPONSE_BYTES;

  private static volatile int maxRedirects = DEFAULT_MAX_REDIRECTS;

  /**
   * Set the maximum response size in bytes that will be read. {@code -1}
   * disables the cap. Default: 1 MiB.
   */
  public static void setMaxResponseSize(int maxBytes) {
    ServerMetaDataHelper.maxResponseSize = maxBytes;
  }

  /**
   * Set the maximum number of HTTP redirects to follow. {@code 0} disables
   * redirect following. Default: 3.
   */
  public static void setMaxRedirects(int max) {
    ServerMetaDataHelper.maxRedirects = max;
  }

  /**
   * Retrieve OAuth2 Authorization Server Metadata using the issuer as a
   * starting point.
   */
  public static AuthorizationServerMetaData retrieveFromIssuer(String issuer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    return retrieveFromWellKnownConfiguration(issuer + "/.well-known/oauth-authorization-server");
  }

  /**
   * Retrieve OAuth2 Authorization Server Metadata via the supplied
   * {@link HttpURLConnection}.
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection, maxResponseSize, maxRedirects,
        is -> AuthorizationServerMetaData.fromMap(JSONWebKeySetHelper.parseJSON(is)),
        ServerMetaDataException::new);
  }

  /**
   * Retrieve OAuth2 Authorization Server Metadata from a well-known endpoint
   * URL.
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(String endpoint) {
    return retrieveFromWellKnownConfiguration(buildURLConnection(endpoint));
  }

  public static class ServerMetaDataException extends RuntimeException {
    public ServerMetaDataException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
