/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt;

import org.lattejava.jwt.internal.Base64URL;
import org.lattejava.jwt.internal.HardenedJSON;
import org.lattejava.jwt.internal.MessageSanitizer;
import org.lattejava.jwt.internal.SHAKE256;
import org.lattejava.jwt.internal.http.AbstractHTTPHelper;

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Helpers for OpenID Connect.
 *
 * @author Daniel DeGroff
 */
public class OpenIDConnect {

  /**
   * Generate the hash of the Access Token specified by the OpenID Connect Core spec for the <code>at_hash</code> claim.
   *
   * @param accessToken the ASCII form of the access token
   * @param algorithm   the algorithm to be used when encoding the Id Token
   * @return a hash to be used as the <code>at_hash</code> claim in the Id Token claim payload
   */
  public static String at_hash(String accessToken, Algorithm algorithm) {
    return generate_hash(accessToken, algorithm);
  }

  /**
   * Generate the hash of the Authorization Code as specified by the OpenID Connect Core spec for the <code>c_hash</code> claim.
   *
   * @param authorizationCode the ASCII form of the authorization code
   * @param algorithm         the algorithm to be used when encoding the Id Token
   * @return a hash to be used as the <code>c_hash</code> claim in the Id Token claim payload
   */
  public static String c_hash(String authorizationCode, Algorithm algorithm) {
    return generate_hash(authorizationCode, algorithm);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata for the given issuer. Appends
   * {@code /.well-known/openid-configuration} to the issuer (after trimming a trailing slash).
   * Enforces OIDC Discovery 1.0 §4.3 issuer-equality validation: the response's {@code issuer}
   * field must equal the input issuer (after single-trailing-slash normalization on both sides).
   * Throws {@link OpenIDConnectException} on any failure (network, non-2xx, parse error, missing
   * required field, mismatched issuer, cross-origin redirect rejection, oversize response).
   *
   * @param issuer the OIDC issuer URL
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discover(String issuer) {
    return discover(issuer, FetchLimits.defaults(), null);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata for the given issuer. Appends
   * {@code /.well-known/openid-configuration} to the issuer (after trimming a trailing slash).
   * Enforces OIDC Discovery 1.0 §4.3 issuer-equality validation: the response's {@code issuer}
   * field must equal the input issuer (after single-trailing-slash normalization on both sides).
   * Throws {@link OpenIDConnectException} on any failure (network, non-2xx, parse error, missing
   * required field, mismatched issuer, cross-origin redirect rejection, oversize response).
   *
   * @param issuer     the OIDC issuer URL
   * @param customizer an optional {@link Consumer} to configure the {@link HttpURLConnection} before the request is sent; may be {@code null}
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discover(String issuer, Consumer<HttpURLConnection> customizer) {
    return discover(issuer, FetchLimits.defaults(), customizer);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata for the given issuer. Appends
   * {@code /.well-known/openid-configuration} to the issuer (after trimming a trailing slash).
   * Enforces OIDC Discovery 1.0 §4.3 issuer-equality validation: the response's {@code issuer}
   * field must equal the input issuer (after single-trailing-slash normalization on both sides).
   * Throws {@link OpenIDConnectException} on any failure (network, non-2xx, parse error, missing
   * required field, mismatched issuer, cross-origin redirect rejection, oversize response).
   *
   * @param issuer the OIDC issuer URL
   * @param limits the fetch and parse hardening limits to apply
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discover(String issuer, FetchLimits limits) {
    return discover(issuer, limits, null);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata for the given issuer. Appends
   * {@code /.well-known/openid-configuration} to the issuer (after trimming a trailing slash).
   * Enforces OIDC Discovery 1.0 §4.3 issuer-equality validation: the response's {@code issuer}
   * field must equal the input issuer (after single-trailing-slash normalization on both sides).
   * Throws {@link OpenIDConnectException} on any failure (network, non-2xx, parse error, missing
   * required field, mismatched issuer, cross-origin redirect rejection, oversize response).
   *
   * @param issuer     the OIDC issuer URL
   * @param limits     the fetch and parse hardening limits to apply
   * @param customizer an optional {@link Consumer} to configure the {@link HttpURLConnection} before the request is sent; may be {@code null}
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discover(String issuer, FetchLimits limits, Consumer<HttpURLConnection> customizer) {
    Objects.requireNonNull(issuer, "issuer");
    Objects.requireNonNull(limits, "limits");
    String trimmed = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    String url = trimmed + "/.well-known/openid-configuration";
    return doDiscover(url, issuer, limits, customizer);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata from a fully-qualified well-known URL.
   * <strong>Does not</strong> perform issuer-equality validation — no expected issuer is supplied.
   * This is a security downgrade relative to {@link #discover(String)}; callers with an OIDC issuer
   * should prefer {@link #discover(String)}. This overload is also the right entry point for an
   * RFC 8414 server's {@code /.well-known/oauth-authorization-server} URL.
   *
   * @param wellKnownURL the full well-known URL of the discovery document
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL) {
    return discoverFromWellKnown(wellKnownURL, FetchLimits.defaults(), null);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata from a fully-qualified well-known URL.
   * <strong>Does not</strong> perform issuer-equality validation — no expected issuer is supplied.
   * This is a security downgrade relative to {@link #discover(String)}; callers with an OIDC issuer
   * should prefer {@link #discover(String)}. This overload is also the right entry point for an
   * RFC 8414 server's {@code /.well-known/oauth-authorization-server} URL.
   *
   * @param wellKnownURL the full well-known URL of the discovery document
   * @param customizer   an optional {@link Consumer} to configure the {@link HttpURLConnection} before the request is sent; may be {@code null}
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL, Consumer<HttpURLConnection> customizer) {
    return discoverFromWellKnown(wellKnownURL, FetchLimits.defaults(), customizer);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata from a fully-qualified well-known URL.
   * <strong>Does not</strong> perform issuer-equality validation — no expected issuer is supplied.
   * This is a security downgrade relative to {@link #discover(String)}; callers with an OIDC issuer
   * should prefer {@link #discover(String)}. This overload is also the right entry point for an
   * RFC 8414 server's {@code /.well-known/oauth-authorization-server} URL.
   *
   * @param wellKnownURL the full well-known URL of the discovery document
   * @param limits       the fetch and parse hardening limits to apply
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL, FetchLimits limits) {
    return discoverFromWellKnown(wellKnownURL, limits, null);
  }

  /**
   * Fetches the OpenID Connect Provider Metadata from a fully-qualified well-known URL.
   * <strong>Does not</strong> perform issuer-equality validation — no expected issuer is supplied.
   * This is a security downgrade relative to {@link #discover(String)}; callers with an OIDC issuer
   * should prefer {@link #discover(String)}. This overload is also the right entry point for an
   * RFC 8414 server's {@code /.well-known/oauth-authorization-server} URL.
   *
   * @param wellKnownURL the full well-known URL of the discovery document
   * @param limits       the fetch and parse hardening limits to apply
   * @param customizer   an optional {@link Consumer} to configure the {@link HttpURLConnection} before the request is sent; may be {@code null}
   * @return the parsed {@link OpenIDConnectConfiguration}
   * @throws OpenIDConnectException on any failure
   */
  public static OpenIDConnectConfiguration discoverFromWellKnown(String wellKnownURL, FetchLimits limits, Consumer<HttpURLConnection> customizer) {
    Objects.requireNonNull(wellKnownURL, "wellKnownURL");
    Objects.requireNonNull(limits, "limits");
    return doDiscover(wellKnownURL, null, limits, customizer);
  }

  private static OpenIDConnectConfiguration doDiscover(String url, String expectedIssuer,
      FetchLimits limits, Consumer<HttpURLConnection> customizer) {
    HttpURLConnection connection = AbstractHTTPHelper.buildURLConnection(url, OpenIDConnectException::new);
    if (customizer != null) {
      customizer.accept(connection);
    }

    Map<String, Object> raw;
    try {
      raw = AbstractHTTPHelper.get(connection,
          limits.maxResponseBytes(),
          limits.maxRedirects(),
          !limits.allowCrossOriginRedirects(),
          (conn, is) -> HardenedJSON.parse(is, limits),
          OpenIDConnectException::new);
    } catch (OpenIDConnectException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new OpenIDConnectException("Failed to fetch OIDC discovery document from [" + MessageSanitizer.forMessage(url) + "]", e);
    }

    OpenIDConnectConfiguration cfg;
    try {
      cfg = OpenIDConnectConfiguration.fromMap(raw);
    } catch (IllegalArgumentException e) {
      throw new OpenIDConnectException("Discovery document at [" + MessageSanitizer.forMessage(url) + "] is malformed: " + MessageSanitizer.forMessage(e.getMessage()), e);
    }

    if (cfg.jwksURI() == null || cfg.jwksURI().isEmpty()) {
      throw new OpenIDConnectException("Discovery document at [" + MessageSanitizer.forMessage(url) + "] is missing the [jwks_uri] field");
    }

    if (expectedIssuer != null) {
      if (cfg.issuer() == null || cfg.issuer().isEmpty()) {
        throw new OpenIDConnectException("Discovery document at [" + MessageSanitizer.forMessage(url) + "] is missing the [issuer] field");
      }
      String expectedTrim = expectedIssuer.endsWith("/") ? expectedIssuer.substring(0, expectedIssuer.length() - 1) : expectedIssuer;
      String actualTrim = cfg.issuer().endsWith("/") ? cfg.issuer().substring(0, cfg.issuer().length() - 1) : cfg.issuer();
      if (!expectedTrim.equals(actualTrim)) {
        throw new OpenIDConnectException("Discovery document issuer [" + MessageSanitizer.forMessage(cfg.issuer()) + "] does not match the expected issuer [" + MessageSanitizer.forMessage(expectedIssuer) + "]");
      }
    }

    return cfg;
  }

  private static String generate_hash(String string, Algorithm algorithm) {
    Objects.requireNonNull(string);
    Objects.requireNonNull(algorithm);

    byte[] input = string.getBytes(StandardCharsets.UTF_8);
    byte[] leftMostBytes;

    switch (algorithm.name()) {
      case "ES256":
      case "HS256":
      case "PS256":
      case "RS256":
        leftMostBytes = takeLeftMost(getDigest("SHA-256").digest(input), 16); // 256/2 = 128 bits
        break;
      case "ES384":
      case "HS384":
      case "PS384":
      case "RS384":
        leftMostBytes = takeLeftMost(getDigest("SHA-384").digest(input), 24); // 384/2 = 192 bits
        break;
      case "Ed25519":
      case "ES512":
      case "HS512":
      case "PS512":
      case "RS512":
        leftMostBytes = takeLeftMost(getDigest("SHA-512").digest(input), 32); // 512/2 = 256 bits
        break;
      case "Ed448":
        // Ed448 uses a 114-byte SHAKE256 hash; recommended at_hash/c_hash length is half of that = 57 bytes.
        // See https://bitbucket.org/openid/connect/issues/1125. SHAKE256 is implemented internally
        // (FIPS 202) with optional JCE-provider preference for FIPS deployments.
        leftMostBytes = SHAKE256.digest(input, 57);
        break;
      default:
        throw new IllegalArgumentException("Unsupported algorithm [" + algorithm + "]");
    }

    return Base64URL.encodeToString(leftMostBytes);
  }

  private static byte[] takeLeftMost(byte[] digest, int bytes) {
    int toIndex = Math.min(digest.length, bytes);
    return Arrays.copyOfRange(digest, 0, toIndex);
  }

  private static MessageDigest getDigest(String digest) {
    try {
      return MessageDigest.getInstance(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new JWTSigningException("Required message digest algorithm [" + digest + "] is not registered with this JVM", e);
    }
  }
}
