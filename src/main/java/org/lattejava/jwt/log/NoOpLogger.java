/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
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
