/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.log;

import org.testng.annotations.*;

import static org.testng.Assert.*;

public class NoOpLoggerTest {
  @Test
  public void noOpLogger_swallowsAllLevels() {
    // Use case: every method must be safe to call; nothing throws; nothing logs.
    Logger logger = NoOpLogger.INSTANCE;
    assertNotNull(logger);
    logger.trace("t");
    logger.trace("t {}", "v");
    logger.debug("d");
    logger.debug("d {}", "v");
    logger.debug("d", new RuntimeException("x"));
    logger.info("i");
    logger.info("i {}", "v");
    logger.warn("w");
    logger.warn("w {}", "v");
    logger.warn("w", new RuntimeException("x"));
    logger.error("e");
    logger.error("e", new RuntimeException("x"));
    assertFalse(logger.isTraceEnabled());
    assertFalse(logger.isDebugEnabled());
    assertFalse(logger.isInfoEnabled());
    assertFalse(logger.isWarnEnabled());
    assertFalse(logger.isErrorEnabled());
    assertFalse(logger.isEnabledForLevel(Level.Trace));
    assertFalse(logger.isEnabledForLevel(Level.Error));
    logger.setLevel(Level.Debug);  // tolerated, no-op
  }
}
