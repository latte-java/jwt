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

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Static factories for generating HMAC secrets sized for the SHA-256, SHA-384, and SHA-512 hash functions.
 *
 * @author Daniel DeGroff
 */
public class HMACSecrets {
  /**
   * Generate a 32 byte (256 bit) HMAC secret for use with a SHA-256 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA256() {
    return generateSecureRandom(32);
  }

  /**
   * Generate a 48 byte (384 bit) HMAC secret for use with a SHA-384 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA384() {
    return generateSecureRandom(48);
  }

  /**
   * Generate a 64 byte (512 bit) HMAC secret for use with a SHA-512 hash.
   *
   * @return a secret for use with an HMAC signing and verification scheme.
   */
  public static String generateSHA512() {
    return generateSecureRandom(64);
  }

  private static String generateSecureRandom(int bytes) {
    byte[] buffer = new byte[bytes];
    new SecureRandom().nextBytes(buffer);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
  }
}
