/*
 * Copyright (c) 2025, the latte-java project authors
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

import org.lattejava.jwt.jwks.JSONWebKeySetHelper;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * @author Daniel DeGroff
 */
public abstract class AbstractHttpHelper {
  protected static <T> T get(HttpURLConnection urlConnection, int maxResponseSize, Function<InputStream, T> consumer, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    String endpoint = urlConnection.getURL().toString();

    try {
      urlConnection.setRequestMethod("GET");
      urlConnection.connect();
    } catch (Exception e) {
      throw exception.apply("Failed to connect to [" + endpoint + "].", e);
    }

    int status;
    try {
      status = urlConnection.getResponseCode();
    } catch (Exception e) {
      throw exception.apply("Failed to make a request to [" + endpoint + "].", e);
    }

    if (status < 200 || status > 299) {
      throw exception.apply("Failed to make a request to [" + endpoint + "], a status code of [" + status + "] was returned.", null);
    }

    try (InputStream is = new LimitedInputStream(new BufferedInputStream(urlConnection.getInputStream()), maxResponseSize)) {
      return consumer.apply(is);
    } catch (Exception e) {
      throw exception.apply("Failed to parse the response as JSON from [" + endpoint + "].", e);
    }
  }

  /**
   * An InputStream wrapper that limits the number of bytes that can be read.
   * Throws an ResponseTooLargeException when the maximum number of bytes has been exceeded.
   */
  private static class LimitedInputStream extends InputStream {
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
      }

      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (maximumBytes != -1) {
        int remaining = maximumBytes - bytesRead;
        if (remaining <= 0) {
          throw new ResponseTooLargeException(maximumBytes);
        }
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
      throw new JSONWebKeySetHelper.JSONWebKeySetException("Failed to build connection to [" + endpoint + "].", e);
    }
  }
}
