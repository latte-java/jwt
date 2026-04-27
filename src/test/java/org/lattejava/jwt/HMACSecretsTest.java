/*
 * Copyright (c) 2016-2026, FusionAuth, All Rights Reserved
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

import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.testng.Assert.assertEquals;

/**
 * @author Daniel DeGroff
 */
public class HMACSecretsTest extends BaseTest {
  @Test
  public void hmacSecretLengths() {
    String hmac256 = HMACSecrets.generateSHA256();
    assertEquals(hmac256.length(), 44);
    assertEquals(Base64.getDecoder().decode(hmac256.getBytes(StandardCharsets.UTF_8)).length, 32);

    String hmac384 = HMACSecrets.generateSHA384();
    assertEquals(hmac384.length(), 64);
    assertEquals(Base64.getDecoder().decode(hmac384.getBytes(StandardCharsets.UTF_8)).length, 48);

    String hmac512 = HMACSecrets.generateSHA512();
    assertEquals(hmac512.length(), 88);
    assertEquals(Base64.getDecoder().decode(hmac512.getBytes(StandardCharsets.UTF_8)).length, 64);
  }
}
