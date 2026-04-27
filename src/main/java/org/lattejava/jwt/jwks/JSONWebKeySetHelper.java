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

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.JSONProcessor;
import org.lattejava.jwt.JSONProcessingException;
import org.lattejava.jwt.LatteJSONProcessor;
import org.lattejava.jwt.internal.http.AbstractHTTPHelper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Consumer;

/**
 * Fetches JSON Web Keys from a JWKS endpoint or via OpenID Connect discovery.
 *
 * <p>Response hardening:</p>
 * <ul>
 *   <li>{@code maxResponseBytes} -- 1 MiB by default; per-hop body cap.</li>
 *   <li>{@code maxRedirects} -- 3 by default; manual hop counting via
 *       {@link HttpURLConnection#setInstanceFollowRedirects(boolean)} = false.</li>
 *   <li>No URL scheme restriction.</li>
 * </ul>
 *
 * <p>JSON parse hardening (mirrors {@link org.lattejava.jwt.JWTDecoder} defaults):</p>
 * <ul>
 *   <li>{@code maxNestingDepth} -- 16 by default; bounds JSON object/array
 *       nesting depth to defend against stack-blowup parses.</li>
 *   <li>{@code maxNumberLength} -- 1000 digits by default; bounds the digit
 *       run of a single JSON number so {@code BigInteger}/{@code BigDecimal}
 *       construction cannot be coerced into pathological cost.</li>
 *   <li>{@code maxObjectMembers} -- 1000 by default; bounds the number of
 *       members in any single JSON object.</li>
 *   <li>{@code maxArrayElements} -- 10000 by default; bounds the number of
 *       elements in any single JSON array (e.g. {@code keys}).</li>
 *   <li>{@code allowDuplicateJSONKeys} -- {@code false} by default; duplicate
 *       member names raise {@link org.lattejava.jwt.JSONProcessingException}
 *       at parse time, so a malicious JWKS cannot smuggle a second
 *       {@code keys}/{@code kid} past the parser.</li>
 * </ul>
 *
 * @author Daniel DeGroff
 */
public class JSONWebKeySetHelper extends AbstractHTTPHelper {
  /** Default JSON parse limits mirror {@link org.lattejava.jwt.JWTDecoder}. */
  public static final int DEFAULT_MAX_NESTING_DEPTH = 16;

  public static final int DEFAULT_MAX_NUMBER_LENGTH = 1000;

  public static final int DEFAULT_MAX_OBJECT_MEMBERS = LatteJSONProcessor.DEFAULT_MAX_OBJECT_MEMBERS;

  public static final int DEFAULT_MAX_ARRAY_ELEMENTS = LatteJSONProcessor.DEFAULT_MAX_ARRAY_ELEMENTS;

  public static final boolean DEFAULT_ALLOW_DUPLICATE_JSON_KEYS = false;

  /** Default maximum response body size: 1 MiB. */
  private static final int DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

  /** Default maximum number of HTTP redirects to follow. */
  private static final int DEFAULT_MAX_REDIRECTS = 3;

  private static volatile int maxResponseSize = DEFAULT_MAX_RESPONSE_BYTES;

  private static volatile int maxRedirects = DEFAULT_MAX_REDIRECTS;

  private static volatile int maxNestingDepth = DEFAULT_MAX_NESTING_DEPTH;

  private static volatile int maxNumberLength = DEFAULT_MAX_NUMBER_LENGTH;

  private static volatile int maxObjectMembers = DEFAULT_MAX_OBJECT_MEMBERS;

  private static volatile int maxArrayElements = DEFAULT_MAX_ARRAY_ELEMENTS;

  private static volatile boolean allowDuplicateJSONKeys = DEFAULT_ALLOW_DUPLICATE_JSON_KEYS;

  /**
   * Reset all tunable JWKS / discovery fetch defaults to their built-in
   * values. Useful for tests that mutate these via setters.
   */
  public static void resetDefaults() {
    maxResponseSize = DEFAULT_MAX_RESPONSE_BYTES;
    maxRedirects = DEFAULT_MAX_REDIRECTS;
    maxNestingDepth = DEFAULT_MAX_NESTING_DEPTH;
    maxNumberLength = DEFAULT_MAX_NUMBER_LENGTH;
    maxObjectMembers = DEFAULT_MAX_OBJECT_MEMBERS;
    maxArrayElements = DEFAULT_MAX_ARRAY_ELEMENTS;
    allowDuplicateJSONKeys = DEFAULT_ALLOW_DUPLICATE_JSON_KEYS;
  }

  /**
   * Set the maximum response size in bytes that will be read from an HTTP
   * endpoint. Must be strictly positive; the response cap cannot be
   * disabled. Default: 1 MiB.
   *
   * @throws IllegalArgumentException if {@code maxBytes &lt;= 0}
   */
  public static void setMaxResponseSize(int maxBytes) {
    if (maxBytes <= 0) {
      throw new IllegalArgumentException("maxResponseSize must be > 0; the response cap cannot be disabled");
    }
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
   * Set the maximum JSON object/array nesting depth accepted by the
   * built-in JSON parser when reading JWKS / OIDC discovery responses.
   * Must be strictly positive. Default: 16.
   *
   * @throws IllegalArgumentException if {@code maxDepth &lt;= 0}
   */
  public static void setMaxNestingDepth(int maxDepth) {
    if (maxDepth <= 0) {
      throw new IllegalArgumentException("maxNestingDepth must be > 0 but found [" + maxDepth + "]");
    }
    JSONWebKeySetHelper.maxNestingDepth = maxDepth;
  }

  /**
   * Set the maximum digit-run length of a single JSON number accepted by
   * the built-in JSON parser. Must be strictly positive. Default: 1000.
   *
   * @throws IllegalArgumentException if {@code maxLength &lt;= 0}
   */
  public static void setMaxNumberLength(int maxLength) {
    if (maxLength <= 0) {
      throw new IllegalArgumentException("maxNumberLength must be > 0 but found [" + maxLength + "]");
    }
    JSONWebKeySetHelper.maxNumberLength = maxLength;
  }

  /**
   * Set the maximum number of members accepted in any single JSON object by
   * the built-in JSON parser when reading JWKS / OIDC discovery responses.
   * Must be strictly positive. Default: {@value #DEFAULT_MAX_OBJECT_MEMBERS}.
   *
   * @throws IllegalArgumentException if {@code maxMembers &lt;= 0}
   */
  public static void setMaxObjectMembers(int maxMembers) {
    if (maxMembers <= 0) {
      throw new IllegalArgumentException("maxObjectMembers must be > 0 but found [" + maxMembers + "]");
    }
    JSONWebKeySetHelper.maxObjectMembers = maxMembers;
  }

  /**
   * Set the maximum number of elements accepted in any single JSON array by
   * the built-in JSON parser when reading JWKS / OIDC discovery responses.
   * Must be strictly positive. Default: {@value #DEFAULT_MAX_ARRAY_ELEMENTS}.
   *
   * @throws IllegalArgumentException if {@code maxElements &lt;= 0}
   */
  public static void setMaxArrayElements(int maxElements) {
    if (maxElements <= 0) {
      throw new IllegalArgumentException("maxArrayElements must be > 0 but found [" + maxElements + "]");
    }
    JSONWebKeySetHelper.maxArrayElements = maxElements;
  }

  /**
   * Permit (or forbid) duplicate JSON object member names in JWKS / OIDC
   * discovery responses. Default: {@code false} (duplicates raise
   * {@link org.lattejava.jwt.JSONProcessingException} at parse time).
   */
  public static void setAllowDuplicateJSONKeys(boolean allow) {
    JSONWebKeySetHelper.allowDuplicateJSONKeys = allow;
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
   * endpoint. The connection passed in is used for the discovery hop only;
   * the inner JWKS hop is unauthenticated. Use the (String, Consumer) overload
   * to apply the customizer to both hops.
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    String jwksURI = retrieveJWKSURI(httpURLConnection);
    return retrieveKeysFromJWKS(jwksURI);
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
   * endpoint URL, with an optional connection customizer applied to both
   * the discovery hop and the subsequent JWKS hop.
   */
  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint, JSONWebKeyException::new);
    if (consumer != null) {
      consumer.accept(connection);
    }
    String jwksURI = retrieveJWKSURI(connection);
    return retrieveKeysFromJWKS(jwksURI, consumer);
  }

  private static String retrieveJWKSURI(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection, maxResponseSize, maxRedirects,
        (conn, is) -> {
          Map<String, Object> response = parseJSON(is);
          Object jwksURI = response.get("jwks_uri");
          if (!(jwksURI instanceof String uri) || uri.isEmpty()) {
            String endpoint = conn.getURL().toString();
            throw new JSONWebKeySetException("Well-known endpoint [" + endpoint + "] response is missing the [jwks_uri] property");
          }
          return uri;
        },
        JSONWebKeyException::new);
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
    HttpURLConnection connection = buildURLConnection(endpoint, JSONWebKeyException::new);
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
        (conn, is) -> {
          Map<String, Object> response = parseJSON(is);
          Object keys = response.get("keys");
          if (!(keys instanceof List<?> keyList)) {
            String endpoint = conn.getURL().toString();
            throw new JSONWebKeySetException("JWKS endpoint [" + endpoint + "] response is missing the [keys] array");
          }
          List<JSONWebKey> result = new ArrayList<>();
          for (Object element : keyList) {
            if (!(element instanceof Map)) {
              String endpoint = conn.getURL().toString();
              throw new JSONWebKeySetException("JWKS endpoint [" + endpoint + "] response contains a non-object element in [keys]");
            }
            result.add(JSONWebKey.fromMap((Map<String, Object>) element));
          }
          return result;
        },
        JSONWebKeyException::new);
  }

  // -----------------------------------------------------------
  // Package-visible richer responses for JWKS. Returns the parsed
  // keys plus the HTTP status and the response headers JWKS needs
  // (Cache-Control, Retry-After).
  // -----------------------------------------------------------

  static JWKSResponse retrieveJWKSResponseFromIssuer(String issuer, Consumer<HttpURLConnection> consumer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }
    return retrieveJWKSResponseFromWellKnownConfiguration(issuer + "/.well-known/openid-configuration", consumer);
  }

  static JWKSResponse retrieveJWKSResponseFromWellKnownConfiguration(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint, JSONWebKeyException::new);
    if (consumer != null) {
      consumer.accept(connection);
    }
    String jwksURI = retrieveJWKSURI(connection);
    return retrieveJWKSResponseFromJWKS(jwksURI, consumer);
  }

  @SuppressWarnings("unchecked")
  static JWKSResponse retrieveJWKSResponseFromJWKS(String endpoint, Consumer<HttpURLConnection> consumer) {
    HttpURLConnection connection = buildURLConnection(endpoint, JSONWebKeyException::new);
    if (consumer != null) {
      consumer.accept(connection);
    }
    return get(connection, maxResponseSize, maxRedirects,
        (conn, is) -> {
          Map<String, Object> response = parseJSON(is);
          Object keys = response.get("keys");
          if (!(keys instanceof List<?> keyList)) {
            String url = conn.getURL().toString();
            throw new JSONWebKeySetException("JWKS endpoint [" + url + "] response is missing the [keys] array");
          }
          List<JSONWebKey> result = new ArrayList<>();
          for (Object element : keyList) {
            if (!(element instanceof Map)) {
              String url = conn.getURL().toString();
              throw new JSONWebKeySetException("JWKS endpoint [" + url + "] response contains a non-object element in [keys]");
            }
            result.add(JSONWebKey.fromMap((Map<String, Object>) element));
          }
          int status = -1;
          try { status = conn.getResponseCode(); } catch (IOException ignored) {}
          Map<String, String> sel = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
          for (String name : new String[]{"Cache-Control", "Retry-After"}) {
            String v = conn.getHeaderField(name);
            if (v != null) sel.put(name, v);
          }
          return new JWKSResponse(result, status, sel);
        },
        JSONWebKeyException::new);
  }

  /**
   * Read the input stream fully (subject to the per-hop response-size cap
   * that the caller already wrapped it with) and parse as a top-level JSON
   * object.
   */
  public static Map<String, Object> parseJSON(InputStream is) {
    JSONProcessor processor = new LatteJSONProcessor(maxNestingDepth, maxNumberLength,
        maxObjectMembers, maxArrayElements, allowDuplicateJSONKeys);
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int n;
      while ((n = is.read(buffer)) != -1) {
        out.write(buffer, 0, n);
      }
      return processor.deserialize(out.toByteArray());
    } catch (JSONProcessingException e) {
      throw new JSONWebKeySetException("Failed to parse JSON response", e);
    } catch (IOException e) {
      throw new JSONWebKeySetException("Failed to read JWKS response", e);
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
