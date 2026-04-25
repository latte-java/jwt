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

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

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
