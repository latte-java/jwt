/*
 * Copyright (c) 2016-2019, FusionAuth, All Rights Reserved
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

/**
 * JWT Signer.
 *
 * @author Daniel DeGroff
 */
public interface Signer {

  /**
   * Return the algorithm supported by this signer.
   *
   * @return the algorithm.
   */
  Algorithm getAlgorithm();

  /**
   * Return the kid used for this signer.
   *
   * @return the kid
   */
  default String getKid() {
    throw new UnsupportedOperationException();
  }

  /**
   * Sign the provided message bytes and return the signature.
   *
   * <p>As of 7.0, the Signer contract takes raw bytes (the JWT signing input
   * bytes -- the dot-joined header and payload segments). Encoding to
   * {@code byte[]} is the encoder's responsibility.</p>
   *
   * @param message The signing-input bytes to sign.
   * @return The message signature in a byte array.
   */
  byte[] sign(byte[] message);
}
