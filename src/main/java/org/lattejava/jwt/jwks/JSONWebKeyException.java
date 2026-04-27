/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.jwks;

/**
 * Thrown when JWK construction or conversion fails (malformed input, unsupported key type, invalid encoding, etc.).
 *
 * <p>Intentionally <em>not</em> a {@code JWTException}: a JSON Web Key is a
 * standalone key artifact (RFC 7517) that may be produced, consumed, or round-tripped entirely outside of any JWT flow.
 * Modelling JWK errors as JWT errors would mislead callers writing generic JWT error handlers into catching conditions
 * that have nothing to do with token processing.</p>
 *
 * @author Daniel DeGroff
 */
public class JSONWebKeyException extends RuntimeException {
  public JSONWebKeyException(String message, Throwable cause) {
    super(message, cause);
  }

  public JSONWebKeyException(String message) {
    super(message);
  }
}
