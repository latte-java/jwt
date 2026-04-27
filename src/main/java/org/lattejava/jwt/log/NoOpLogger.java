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

package org.lattejava.jwt.log;

/**
 * Singleton {@link Logger} that swallows every event. Default for {@code JWKS.Builder.logger(Logger)} so the library is
 * silent unless the integrator opts in.
 */
public final class NoOpLogger implements Logger {
  public static final NoOpLogger INSTANCE = new NoOpLogger();

  private NoOpLogger() {
  }

  @Override
  public void debug(String message) {
  }

  @Override
  public void debug(String message, Object... values) {
  }

  @Override
  public void debug(String message, Throwable throwable) {
  }

  @Override
  public void error(String message) {
  }

  @Override
  public void error(String message, Throwable throwable) {
  }

  @Override
  public void info(String message) {
  }

  @Override
  public void info(String message, Object... values) {
  }

  @Override
  public boolean isDebugEnabled() {
    return false;
  }

  @Override
  public boolean isErrorEnabled() {
    return false;
  }

  @Override
  public boolean isInfoEnabled() {
    return false;
  }

  @Override
  public boolean isTraceEnabled() {
    return false;
  }

  @Override
  public boolean isWarnEnabled() {
    return false;
  }

  @Override
  public void setLevel(Level level) {
  }

  @Override
  public void trace(String message) {
  }

  @Override
  public void trace(String message, Object... values) {
  }

  @Override
  public void warn(String message) {
  }

  @Override
  public void warn(String message, Object... values) {
  }

  @Override
  public void warn(String message, Throwable throwable) {
  }
}
