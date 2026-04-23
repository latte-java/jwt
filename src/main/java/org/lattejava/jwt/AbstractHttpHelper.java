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

package org.lattejava.jwt;

import org.lattejava.jwt.internal.MessageSanitizer;
import org.lattejava.jwt.jwks.JSONWebKeySetHelper;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.function.BiFunction;
import java.util.function.Function;

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
public abstract class AbstractHttpHelper {
  /** Default maximum response body size: 1 MiB. */
  public static final int DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

  /** Default maximum number of HTTP redirects to follow. */
  public static final int DEFAULT_MAX_REDIRECTS = 3;

  protected static <T> T get(HttpURLConnection urlConnection, int maxResponseSize, Function<InputStream, T> consumer, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    return get(urlConnection, maxResponseSize, DEFAULT_MAX_REDIRECTS, consumer, exception);
  }

  /**
   * Performs a GET on the supplied connection, manually following up to
   * {@code maxRedirects} 3xx responses, capping each hop's body at
   * {@code maxResponseBytes} bytes.
   *
   * @param urlConnection    the prepared {@link HttpURLConnection} (the helper sets
   *                         the request method and disables auto-redirect)
   * @param maxResponseBytes per-hop body cap; {@code -1} disables the cap
   * @param maxRedirects     maximum number of 3xx redirects to follow before
   *                         aborting; {@code 0} disables redirect following
   * @param consumer         response-body parser
   * @param exception        wrapper for any {@link IOException} surfaced
   */
  protected static <T> T get(HttpURLConnection urlConnection, int maxResponseBytes, int maxRedirects, Function<InputStream, T> consumer, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    HttpURLConnection current = urlConnection;
    String originalEndpoint = current.getURL().toString();
    int redirectsFollowed = 0;
    while (true) {
      String endpoint = current.getURL().toString();
      try {
        current.setRequestMethod("GET");
      } catch (Exception e) {
        throw exception.apply("Failed to prepare the request to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }
      // Disable auto-redirect so we can apply the per-hop body cap.
      current.setInstanceFollowRedirects(false);

      try {
        current.connect();
      } catch (Exception e) {
        throw exception.apply("Failed to connect to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }

      int status;
      try {
        status = current.getResponseCode();
      } catch (Exception e) {
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
        // Drain & close the body of the redirect hop so the connection can be reused.
        try {
          InputStream errorBody = current.getErrorStream();
          if (errorBody != null) {
            errorBody.close();
          }
        } catch (IOException ignored) {
          // Best-effort drain/close of the redirect hop's error stream so the connection can be reused.
          // Only close() can throw here (getErrorStream() returns null, not throws), and an IOException
          // draining a hop we've already chosen to abandon is not actionable.
        }
        current = buildURLConnection(nextURL.toString());
        redirectsFollowed++;
        continue;
      }

      if (status < 200 || status > 299) {
        throw exception.apply("Failed to make a request to [" + MessageSanitizer.forMessage(endpoint) + "]: status code [" + status + "] returned", null);
      }

      try (InputStream is = new LimitedInputStream(new BufferedInputStream(current.getInputStream()), maxResponseBytes)) {
        return consumer.apply(is);
      } catch (RuntimeException e) {
        throw e;
      } catch (Exception e) {
        throw exception.apply("Failed to parse the response as JSON from [" + MessageSanitizer.forMessage(endpoint) + "]", e);
      }
    }
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
      this.delegate = delegate;
      this.maximumBytes = maximumBytes;
    }

    @Override
    public int read() throws IOException {
      if (maximumBytes != -1 && bytesRead >= maximumBytes) {
        throw new ResponseTooLargeException(maximumBytes);
      }

      int b = delegate.read();
      if (b != -1) {
        bytesRead++;
        if (maximumBytes != -1 && bytesRead > maximumBytes) {
          throw new ResponseTooLargeException(maximumBytes);
        }
      }

      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (maximumBytes != -1) {
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
      }

      int read = delegate.read(b, off, len);
      if (read > 0) {
        bytesRead += read;
      }

      if (maximumBytes != -1 && bytesRead > maximumBytes) {
        throw new ResponseTooLargeException(maximumBytes);
      }

      return read;
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }
  }

  protected static HttpURLConnection buildURLConnection(String endpoint) {
    try {
      HttpURLConnection urlConnection = (HttpURLConnection) new URL(endpoint).openConnection();
      urlConnection.setDoOutput(true);
      urlConnection.setConnectTimeout(10_000);
      urlConnection.setReadTimeout(10_000);
      urlConnection.addRequestProperty("User-Agent", "latte-jwt (https://github.com/latte-java/jwt)");
      return urlConnection;
    } catch (IOException e) {
      throw new JSONWebKeySetHelper.JSONWebKeySetException("Failed to build connection to [" + MessageSanitizer.forMessage(endpoint) + "]", e);
    }
  }
}
