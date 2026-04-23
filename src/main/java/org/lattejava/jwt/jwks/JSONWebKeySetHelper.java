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

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.AbstractHttpHelper;
import org.lattejava.jwt.JSONProcessor;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.LatteJSONProcessor;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Fetches JSON Web Keys from a JWKS endpoint or via OpenID Connect discovery.
 *
 * <p>Response hardening (spec §8):</p>
 * <ul>
 *   <li>{@code maxResponseBytes} -- 1 MiB by default; per-hop body cap.</li>
 *   <li>{@code maxRedirects} -- 3 by default; manual hop counting via
 *       {@link HttpURLConnection#setInstanceFollowRedirects(boolean)} = false.</li>
 *   <li>No URL scheme restriction.</li>
 * </ul>
 *
 * @author The Latte Project
 */
public class JSONWebKeySetHelper extends AbstractHttpHelper {
  private static volatile int maxResponseSize = DEFAULT_MAX_RESPONSE_BYTES;

  private static volatile int maxRedirects = DEFAULT_MAX_REDIRECTS;

  /**
   * Set the maximum response size in bytes that will be read from an HTTP
   * endpoint. A value of {@code -1} disables the cap. Default: 1 MiB.
   */
  public static void setMaxResponseSize(int maxBytes) {
    JSONWebKeySetHelper.maxResponseSize = maxBytes;
  }

  /**
   * Set the maximum number of HTTP redirects to follow. {@code 0} disables
   * redirect following entirely. Default: 3.
   */
  public static void setMaxRedirects(int max) {
    JSONWebKeySetHelper.maxRedirects = max;
  }

  /**
   * Retrieve a list of JSON Web Keys from the JWK endpoint using the OIDC
   * issuer as a starting point.
   */
  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer) {
    return retrieveKeysFromIssuer(issuer, null);
  }

  /**
   * Retrieve a list of JSON Web Keys from the JWK endpoint using the OIDC
   * issuer as a starting point, with an optional connection customizer.
   */
  public static List<JSONWebKey> retrieveKeysFromIssuer(String issuer, Consumer<HttpURLConnection> consumer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    return retrieveKeysFromWellKnownConfiguration(issuer + "/.well-known/openid-configuration", consumer);
  }

  /**
   * Retrieve JSON Web Keys from an OpenID Connect well-known discovery
   * endpoint.
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection, maxResponseSize, maxRedirects,
        is -> {
          Map<String, Object> response = parseJSON(is);
          Object jwksURI = response.get("jwks_uri");
          if (!(jwksURI instanceof String) || ((String) jwksURI).isEmpty()) {
            String endpoint = httpURLConnection.getURL().toString();
            throw new JSONWebKeySetException("The well-known endpoint [" + endpoint + "] has not defined a JSON Web Key Set endpoint. Missing the [jwks_uri] property.");
          }
          return retrieveKeysFromJWKS((String) jwksURI);
        },
        JSONWebKeyException::new);
  }

  /**
   * Retrieve JSON Web Keys from an OpenID Connect well-known discovery
   * endpoint URL.
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint) {
    return retrieveKeysFromWellKnownConfiguration(endpoint, null);
  }

  /**
   * Retrieve JSON Web Keys from an OpenID Connect well-known discovery
   * endpoint URL, with an optional connection customizer.
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint);
    if (consumer != null) {
      consumer.accept(connection);
    }

    return retrieveKeysFromWellKnownConfiguration(connection);
  }

  /**
   * Retrieve JSON Web Keys from a JWKS endpoint URL.
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint) {
    return retrieveKeysFromJWKS(endpoint, null);
  }

  /**
   * Retrieve JSON Web Keys from a JWKS endpoint URL, with an optional
   * connection customizer.
   */
  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint);
    if (consumer != null) {
      consumer.accept(connection);
    }

    return retrieveKeysFromJWKS(connection);
  }

  /**
   * Retrieve JSON Web Keys from a JWKS endpoint via the supplied
   * {@link HttpURLConnection}.
   */
  @SuppressWarnings("unchecked")
  public static List<JSONWebKey> retrieveKeysFromJWKS(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection, maxResponseSize, maxRedirects,
        is -> {
          Map<String, Object> response = parseJSON(is);
          Object keys = response.get("keys");
          if (!(keys instanceof List)) {
            String endpoint = httpURLConnection.getURL().toString();
            throw new JSONWebKeySetException("The JWKS endpoint [" + endpoint + "] returned a response without a [keys] array.");
          }
          List<JSONWebKey> result = new ArrayList<>();
          for (Object element : (List<Object>) keys) {
            if (!(element instanceof Map)) {
              String endpoint = httpURLConnection.getURL().toString();
              throw new JSONWebKeySetException("The JWKS endpoint [" + endpoint + "] returned a response with a non-object element in [keys].");
            }
            result.add(JSONWebKey.fromMap((Map<String, Object>) element));
          }
          return result;
        },
        JSONWebKeyException::new);
  }

  /**
   * Read the input stream fully (subject to the {@link AbstractHttpHelper.LimitedInputStream}
   * cap that the caller already wrapped it with) and parse as a top-level
   * JSON object.
   */
  public static Map<String, Object> parseJSON(InputStream is) {
    JSONProcessor processor = new LatteJSONProcessor();
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int n;
      while ((n = is.read(buffer)) != -1) {
        out.write(buffer, 0, n);
      }
      return processor.deserialize(out.toByteArray());
    } catch (JSONProcessingException e) {
      throw new JSONWebKeySetException("Failed to parse JSON response.", e);
    } catch (java.io.IOException e) {
      // Propagate IO failures (including ResponseTooLargeException) so the
      // caller's exception wrapper can decorate them.
      throw new RuntimeException(e);
    }
  }

  public static class JSONWebKeySetException extends RuntimeException {
    public JSONWebKeySetException(String message) {
      super(message);
    }

    public JSONWebKeySetException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
