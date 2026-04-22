/*
 * Copyright (c) 2016-2023, FusionAuth, All Rights Reserved
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

import org.lattejava.jwt.json.Mapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * TODO Checkpoint 5: full rewrite. This class is a transitional shim that
 * keeps the build green after the {@link JWT}/{@link Header} model rewrite in
 * Checkpoint 3 -- it now serializes via the new {@code toSerializableMap()}
 * API and a {@link Header.Builder} -- but the public API surface, the
 * {@code Consumer<Header>} / {@code Supplier<Header>} customization shape,
 * and the JSONProcessor wiring are all replaced in Checkpoint 5.
 *
 * @author Daniel DeGroff
 */
public class JWTEncoder {
  /**
   * Encode the JWT to produce a dot separated encoded string that can be sent in an HTTP request header.
   *
   * @param jwt    The JWT.
   * @param signer The signer used to add a signature to the JWT.
   * @return the encoded JWT string.
   */
  public String encode(JWT jwt, Signer signer) {
    return encode(jwt, signer, b -> b.kid(signer.kid()));
  }

  /**
   * Encode the JWT. The supplier returns a {@link Header.Builder} whose state
   * is consumed by the encoder; the encoder forces the {@code alg} value to
   * match the signer.
   *
   * @param jwt      The JWT.
   * @param signer   The signer used to add a signature to the JWT.
   * @param supplier A header-builder supplier; may be null.
   * @return the encoded JWT string.
   */
  public String encode(JWT jwt, Signer signer, Supplier<Header.Builder> supplier) {
    Header.Builder builder = supplier != null ? supplier.get() : Header.builder();
    return encode(jwt, signer, builder);
  }

  /**
   * Encode the JWT. The consumer mutates a fresh {@link Header.Builder}; the
   * encoder forces the {@code alg} value to match the signer.
   *
   * @param jwt      The JWT.
   * @param signer   The signer used to add a signature to the JWT.
   * @param consumer A header-builder consumer; may be null.
   * @return the encoded JWT string.
   */
  public String encode(JWT jwt, Signer signer, Consumer<Header.Builder> consumer) {
    Header.Builder builder = Header.builder();
    if (consumer != null) {
      consumer.accept(builder);
    }
    return encode(jwt, signer, builder);
  }

  private String encode(JWT jwt, Signer signer, Header.Builder builder) {
    Objects.requireNonNull(jwt);
    Objects.requireNonNull(signer);

    // The signer dictates the algorithm; caller cannot override.
    builder.alg(signer.algorithm());
    Header header = builder.build();

    Map<String, Object> headerMap = new LinkedHashMap<>(header.toSerializableMap());
    Map<String, Object> claimsMap = new LinkedHashMap<>(jwt.toSerializableMap());

    List<String> parts = new ArrayList<>(3);
    parts.add(base64Encode(Mapper.serialize(headerMap)));
    parts.add(base64Encode(Mapper.serialize(claimsMap)));

    byte[] message = String.join(".", parts).getBytes(StandardCharsets.UTF_8);
    byte[] signature = signer.sign(message);
    parts.add(base64Encode(signature));

    return String.join(".", parts);
  }

  private String base64Encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
