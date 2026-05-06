/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
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
