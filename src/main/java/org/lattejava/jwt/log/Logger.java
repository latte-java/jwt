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
 * A small logging interface used by latte-jwt internals (notably {@code JWKS}). Removes any compile-time coupling to a
 * specific logging framework like SLF4J or JUL.
 *
 * <p>Shape mirrors {@code org.lattejava.http.log.Logger} with one
 * intentional addition: a {@code warn} level. Integrators that wrap a single SLF4J/JUL adapter for both libraries map
 * {@code warn} to the underlying framework's {@code WARNING}.</p>
 */
public interface Logger {
  void debug(String message);

  void debug(String message, Object... values);

  void debug(String message, Throwable throwable);

  void error(String message);

  void error(String message, Throwable throwable);

  void info(String message);

  void info(String message, Object... values);

  boolean isDebugEnabled();

  default boolean isEnabledForLevel(Level level) {
    return switch (level) {
      case Trace -> isTraceEnabled();
      case Debug -> isDebugEnabled();
      case Info -> isInfoEnabled();
      case Warn -> isWarnEnabled();
      case Error -> isErrorEnabled();
    };
  }

  boolean isErrorEnabled();

  boolean isInfoEnabled();

  boolean isTraceEnabled();

  boolean isWarnEnabled();

  /**
   * Sets the level of this logger. Optional; implementations whose level is controlled by the underlying framework may
   * treat this as a no-op.
   *
   * @param level the new level
   */
  void setLevel(Level level);

  void trace(String message);

  void trace(String message, Object... values);

  void warn(String message);

  void warn(String message, Object... values);

  void warn(String message, Throwable throwable);
}
