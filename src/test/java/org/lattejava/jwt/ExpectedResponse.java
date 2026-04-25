/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

import java.nio.file.Path;

/**
 * @author Daniel DeGroff
 */
public class ExpectedResponse implements Buildable<ExpectedResponse> {
  public String contentType = "application/json";

  /** When set, sent as the {@code Location:} header (used with 3xx status codes). */
  public String redirectLocation;

  public String response;

  public Path responseFile;

  /**
   * When &gt; 0 the handler emits exactly this many bytes for the body
   * regardless of {@link #response} content. Used to test
   * {@code maxResponseBytes} enforcement without keeping a large literal in
   * the test source.
   */
  public int responseSize = -1;

  public int status = 200;
}