/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

import org.lattejava.jwt.internal.SHAKE256;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Helpers for OpenID Connect.
 *
 * @author Daniel DeGroff
 */
public class OpenIDConnect {

  /**
   * Generate the hash of the Access Token specified by the OpenID Connect Core spec for the <code>at_hash</code> claim.
   *
   * @param accessToken the ASCII form of the access token
   * @param algorithm   the algorithm to be used when encoding the Id Token
   * @return a hash to be used as the <code>at_hash</code> claim in the Id Token claim payload
   */
  public static String at_hash(String accessToken, Algorithm algorithm) {
    return generate_hash(accessToken, algorithm);
  }

  /**
   * Generate the hash of the Authorization Code as specified by the OpenID Connect Core spec for the <code>c_hash</code> claim.
   *
   * @param authorizationCode the ASCII form of the authorization code
   * @param algorithm         the algorithm to be used when encoding the Id Token
   * @return a hash to be used as the <code>c_hash</code> claim in the Id Token claim payload
   */
  public static String c_hash(String authorizationCode, Algorithm algorithm) {
    return generate_hash(authorizationCode, algorithm);
  }

  private static String generate_hash(String string, Algorithm algorithm) {
    Objects.requireNonNull(string);
    Objects.requireNonNull(algorithm);

    byte[] input = string.getBytes(StandardCharsets.UTF_8);
    byte[] leftMostBytes;

    switch (algorithm.name()) {
      case "ES256":
      case "HS256":
      case "PS256":
      case "RS256":
        leftMostBytes = takeLeftMost(getDigest("SHA-256").digest(input), 16); // 256/2 = 128 bits
        break;
      case "ES384":
      case "HS384":
      case "PS384":
      case "RS384":
        leftMostBytes = takeLeftMost(getDigest("SHA-384").digest(input), 24); // 384/2 = 192 bits
        break;
      case "Ed25519":
      case "ES512":
      case "HS512":
      case "PS512":
      case "RS512":
        leftMostBytes = takeLeftMost(getDigest("SHA-512").digest(input), 32); // 512/2 = 256 bits
        break;
      case "Ed448":
        // Ed448 uses a 114-byte SHAKE256 hash; recommended at_hash/c_hash length is half of that = 57 bytes.
        // See https://bitbucket.org/openid/connect/issues/1125. SHAKE256 is implemented internally
        // (FIPS 202) with optional JCE-provider preference for FIPS deployments.
        leftMostBytes = SHAKE256.digest(input, 57);
        break;
      default:
        throw new IllegalArgumentException("You specified an unsupported algorithm. The algorithm [" + algorithm + "]"
            + " is not supported. You must use Ed25519, Ed448, ES256, ES384, ES512, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384 or RS512.");
    }

    return new String(Base64.getUrlEncoder().withoutPadding().encode(leftMostBytes));
  }

  private static byte[] takeLeftMost(byte[] digest, int bytes) {
    int toIndex = Math.min(digest.length, bytes);
    return Arrays.copyOfRange(digest, 0, toIndex);
  }

  private static MessageDigest getDigest(String digest) {
    try {
      return MessageDigest.getInstance(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
