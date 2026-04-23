/*
 * Copyright (c) 2016, FusionAuth, All Rights Reserved
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

import java.time.Duration;
import java.time.Instant;

/**
 * The JWT is not yet valid. The JWT has claimed it is not valid before a time that is in the future.
 * <p>
 * Carries the {@code nbf} claim, the clock reading used for the check, and the
 * applied clock skew so consumers diagnosing clock-sync issues can read the
 * numbers directly instead of parsing them out of a message. Any of the three
 * may be {@code null} if the exception was thrown without diagnostic context.
 *
 * @author Daniel DeGroff
 */
public class JWTUnavailableForProcessingException extends JWTException {
  private final Instant notBefore;

  private final Instant now;

  private final Duration clockSkew;

  public JWTUnavailableForProcessingException() {
    this(null, null, null);
  }

  public JWTUnavailableForProcessingException(Instant notBefore, Instant now, Duration clockSkew) {
    this.notBefore = notBefore;
    this.now = now;
    this.clockSkew = clockSkew;
  }

  public Duration getClockSkew() {
    return clockSkew;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public Instant getNow() {
    return now;
  }
}
