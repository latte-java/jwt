/*
 * Copyright (c) 2026, the latte-java project authors
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

package org.lattejava.jwt.internal.http;

import org.lattejava.jwt.HTTPResponseException;
import org.lattejava.jwt.ResponseTooLargeException;
import org.lattejava.jwt.TooManyRedirectsException;
import org.lattejava.jwt.internal.MessageSanitizer;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Shared HTTP helper for JWKS / discovery / metadata fetches.
 *
 * <h3>Response hardening</h3>
 * <ul>
 *   <li>Per-hop body cap via {@link LimitedInputStream} -- response read
 *       aborts mid-stream once {@code maxResponseBytes} is exceeded.</li>
 *   <li>Manual redirect following with a configurable hop count
 *       ({@code maxRedirects}). The platform's auto-redirect is disabled via
 *       {@link HttpURLConnection#setInstanceFollowRedirects(boolean)} so the
 *       body cap applies independently to each hop.</li>
 *   <li>No scheme restriction -- caller chose the URL.</li>
 * </ul>
 *
 * @author Daniel DeGroff
 */
public abstract class AbstractHTTPHelper {
  /**
   * Performs a GET on the supplied connection, manually following up to
   * {@code maxRedirects} 3xx responses, capping each hop's body at
   * {@code maxResponseBytes} bytes.
   *
   * <p>When {@code sameOriginRedirectsOnly} is {@code true}, any redirect
   * that changes the scheme, host, or port relative to the original URL is
   * rejected by invoking {@code exception} with a message of the form
   * {@code "Refusing cross-origin redirect from [<origin>] to [<origin>]"}.
   *
   * @param urlConnection           the prepared {@link HttpURLConnection} (the helper sets
   *                                the request method and disables auto-redirect)
   * @param maxResponseBytes        per-hop body cap; must be strictly positive (the
   *                                cap cannot be disabled)
   * @param maxRedirects            maximum number of 3xx redirects to follow before
   *                                aborting; {@code 0} disables redirect following
   * @param sameOriginRedirectsOnly when {@code true}, cross-origin redirects are rejected
   * @param consumer                response-body parser
   * @param exception               wrapper for any {@link IOException} surfaced
   * @throws IllegalArgumentException if {@code maxResponseBytes <= 0}
   */
  public static <T> T get(HttpURLConnection urlConnection, int maxResponseBytes, int maxRedirects, boolean sameOriginRedirectsOnly, BiFunction<HttpURLConnection, InputStream, T> consumer, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    if (maxResponseBytes <= 0) {
      throw new IllegalArgumentException("maxResponseBytes must be > 0; the response cap cannot be disabled");
    }
    HttpURLConnection current = urlConnection;
    URL originalURL = current.getURL();
    String originalEndpoint = originalURL.toString();
    int redirectsFollowed = 0;
    while (true) {
      String endpoint = current.getURL().toString();
      try {
        current.setRequestMethod("GET");
      } catch (java.net.ProtocolException e) {
        throw exception.apply("Failed to prepare the request to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }
      // Disable auto-redirect so we can apply the per-hop body cap.
      current.setInstanceFollowRedirects(false);

      try {
        current.connect();
      } catch (IOException e) {
        throw exception.apply("Failed to connect to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }

      int status;
      try {
        status = current.getResponseCode();
      } catch (IOException e) {
        throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }

      // Redirect handling: 301, 302, 303, 307, 308
      if (status >= 300 && status <= 399 && status != 304 && status != 305 && status != 306) {
        if (redirectsFollowed >= maxRedirects) {
          throw new TooManyRedirectsException("Failed to make a request to [" + originalEndpoint + "] after exceeding maximum redirect count [" + maxRedirects + "]");
        }
        String location = current.getHeaderField("Location");
        if (location == null || location.isEmpty()) {
          throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]: status [" + status + "] returned without a Location header", null);
        }
        URL nextURL;
        try {
          nextURL = new URL(current.getURL(), location);
        } catch (IOException e) {
          throw exception.apply("Failed to parse redirect Location header [" + MessageSanitizer.forMessage(location) + "] from [" + MessageSanitizer.forMessage(endpoint) + "]", e);
        }
        if (sameOriginRedirectsOnly && !sameOrigin(originalURL, nextURL)) {
          throw exception.apply("Refusing cross-origin redirect from [" + originString(originalURL) + "] to [" + originString(nextURL) + "]", null);
        }
        current = buildURLConnection(nextURL.toString(), exception);
        redirectsFollowed++;
        continue;
      }

      if (status < 200 || status > 299) {
        Map<String, List<String>> headers;
        try {
          headers = current.getHeaderFields();
        } catch (RuntimeException ignored) {
          headers = Collections.emptyMap();
        }
        HTTPResponseException httpEx = new HTTPResponseException(status, headers);
        throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]: status code [" + status + "] returned", httpEx);
      }

      try (InputStream is = new LimitedInputStream(new BufferedInputStream(current.getInputStream()), maxResponseBytes)) {
        return consumer.apply(current, is);
      } catch (IOException e) {
        // ResponseTooLargeException (IOException) flows through here; callers
        // inspect the cause chain to recover it.
        throw exception.apply("Failed to parse the response as JSON from [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }
    }
  }

  /**
   * Open and prepare an {@link HttpURLConnection} for {@code endpoint}.
   *
   * @param endpoint  the URL to open
   * @param exception caller-supplied wrapper for any {@link IOException} surfaced while
   *                  opening the connection. Passed through so each subclass can surface a
   *                  domain-appropriate type (e.g. {@code JSONWebKeyException} for the JWKS
   *                  helper, {@code ServerMetaDataException} for the OAuth2 helper) rather
   *                  than leaking a JWKS-named exception out of an unrelated caller.
   */
  public static HttpURLConnection buildURLConnection(String endpoint, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    try {
      HttpURLConnection urlConnection = (HttpURLConnection) new URL(endpoint).openConnection();
      urlConnection.setDoOutput(true);
      urlConnection.setConnectTimeout(10_000);
      urlConnection.setReadTimeout(10_000);
      urlConnection.addRequestProperty("User-Agent", "latte-jwt (https://github.com/latte-java/jwt)");
      return urlConnection;
    } catch (IOException e) {
      throw exception.apply("Failed to build connection to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
    }
  }

  private static int effectivePort(URL url) {
    int port = url.getPort();
    return port == -1 ? url.getDefaultPort() : port;
  }

  private static String originString(URL url) {
    return MessageSanitizer.forMessage(url.getProtocol()) + "://" + MessageSanitizer.forMessage(url.getHost()) + ":" + effectivePort(url);
  }

  private static boolean sameOrigin(URL a, URL b) {
    return a.getProtocol().equalsIgnoreCase(b.getProtocol())
        && a.getHost().equalsIgnoreCase(b.getHost())
        && effectivePort(a) == effectivePort(b);
  }

  /**
   * An InputStream wrapper that limits the number of bytes that can be read.
   * Throws a {@link ResponseTooLargeException} when the configured maximum
   * is exceeded mid-stream (the read aborts; the library never buffers past
   * the limit).
   */
  static class LimitedInputStream extends InputStream {
    private final InputStream delegate;
    private final int maximumBytes;
    private int bytesRead;

    LimitedInputStream(InputStream delegate, int maximumBytes) {
      if (maximumBytes <= 0) {
        throw new IllegalArgumentException("maximumBytes must be > 0");
      }
      this.delegate = delegate;
      this.maximumBytes = maximumBytes;
    }

    @Override
    public int read() throws IOException {
      if (bytesRead >= maximumBytes) {
        throw new ResponseTooLargeException(maximumBytes);
      }

      int b = delegate.read();
      if (b != -1) {
        bytesRead++;
        if (bytesRead > maximumBytes) {
          throw new ResponseTooLargeException(maximumBytes);
        }
      }

      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int remaining = maximumBytes - bytesRead;
      if (remaining <= 0) {
        // Try to read one more byte to confirm the stream is over the cap.
        int probe = delegate.read();
        if (probe == -1) {
          return -1;
        }
        throw new ResponseTooLargeException(maximumBytes);
      }
      // Allow one byte beyond the cap so we can detect overflow on the next read.
      len = Math.min(len, remaining + 1);

      int read = delegate.read(b, off, len);
      if (read > 0) {
        bytesRead += read;
      }

      if (bytesRead > maximumBytes) {
        throw new ResponseTooLargeException(maximumBytes);
      }

      return read;
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }
  }
}
