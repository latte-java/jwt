/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.log;

/**
 * Severity levels for {@link Logger} events. Constants are ordered from most-verbose to least-verbose:
 * {@code Trace < Debug < Info < Warn < Error}.
 */
public enum Level {
  Trace, Debug, Info, Warn, Error
}
