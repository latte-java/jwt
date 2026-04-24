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

/**
 * The JWT was properly constructed but the signature is invalid. This token should not be trusted.
 * <p>
 * This exception carries no message and no cause by design: its <em>presence</em> is the signal. Propagating a
 * JCA-level detail such as "Signature length not correct" would turn verification failures into an oracle that leaks
 * information about the shape of the rejected ciphertext to an attacker probing variations of a forged signature.
 *
 * @author Daniel DeGroff
 */
public class InvalidJWTSignatureException extends JWTException {
  public InvalidJWTSignatureException() {
  }
}
