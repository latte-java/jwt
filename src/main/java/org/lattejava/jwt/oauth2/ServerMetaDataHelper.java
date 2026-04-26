/*
 * Copyright (c) 2026, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.lattejava.jwt.oauth2;

import org.lattejava.jwt.internal.http.AbstractHTTPHelper;
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
public class ServerMetaDataHelper extends AbstractHTTPHelper {
  /** Default maximum response body size: 1 MiB. */
  private static final int DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

  /** Default maximum number of HTTP redirects to follow. */
  private static final int DEFAULT_MAX_REDIRECTS = 3;

  private static volatile int maxResponseSize = DEFAULT_MAX_RESPONSE_BYTES;

  private static volatile int maxRedirects = DEFAULT_MAX_REDIRECTS;

  /**
   * Reset all tunable OAuth 2.0 metadata fetch defaults to their built-in
   * values. Useful for tests that mutate these via setters.
   */
  public static void resetDefaults() {
    maxResponseSize = DEFAULT_MAX_RESPONSE_BYTES;
    maxRedirects = DEFAULT_MAX_REDIRECTS;
  }

  /**
   * Set the maximum response size in bytes that will be read. Must be
   * strictly positive; the response cap cannot be disabled. Default: 1 MiB.
   *
   * @throws IllegalArgumentException if {@code maxBytes &lt;= 0}
   */
  public static void setMaxResponseSize(int maxBytes) {
    if (maxBytes <= 0) {
      throw new IllegalArgumentException("maxResponseSize must be > 0; the response cap cannot be disabled");
    }
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
        (conn, is) -> AuthorizationServerMetaData.fromMap(JSONWebKeySetHelper.parseJSON(is)),
        ServerMetaDataException::new);
  }

  /**
   * Retrieve OAuth2 Authorization Server Metadata from a well-known endpoint
   * URL.
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(String endpoint) {
    return retrieveFromWellKnownConfiguration(buildURLConnection(endpoint, ServerMetaDataException::new));
  }

  public static class ServerMetaDataException extends RuntimeException {
    public ServerMetaDataException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
