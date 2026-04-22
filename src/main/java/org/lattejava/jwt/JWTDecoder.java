/*
 * Copyright (c) 2016-2022, FusionAuth, All Rights Reserved
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
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * TODO Checkpoint 5: full rewrite. This class is a transitional shim that
 * keeps the build green after the {@link JWT}/{@link Header} model rewrite
 * in Checkpoint 3. It deserializes the header / claim segments through the
 * legacy {@link Mapper} into raw {@link Map} structures and then hydrates
 * via the new {@link Header#fromMap(Map)} / {@link JWT#fromMap(Map, Header)}
 * factories. Strict size / depth / number-length / crit understood-parameters
 * checks all land in Checkpoint 5.
 *
 * @author Daniel DeGroff
 */
public class JWTDecoder {
  private int clockSkew = 0;

  /**
   * Decode the JWT using one of they provided verifiers. One more verifiers may be provided, the first verifier found
   * supporting the algorithm reported by the JWT header will be utilized.
   *
   * @param encodedJWT The encoded JWT in string format.
   * @param verifiers  A map of verifiers.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Verifier... verifiers) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);

    String[] parts = getParts(encodedJWT);

    Header header = parseHeader(parts[0]);
    Verifier verifier = Arrays.stream(verifiers).filter(v -> v.canVerify(header.alg())).findFirst().orElse(null);

    return validate(encodedJWT, parts, header, verifier);
  }

  /**
   * Specify the number of seconds allowed for clock skew used for calculating the expiration and not before instants of a JWT.
   *
   * @param clockSkew the number of seconds allowed for clock skew.
   * @return this
   */
  public JWTDecoder withClockSkew(int clockSkew) {
    this.clockSkew = clockSkew;
    return this;
  }

  /**
   * Decode the JWT using one of they provided verifiers. A JWT header value named <code>kid</code> is expected to
   * contain the key to look up the correct verifier.
   *
   * @param encodedJWT The encoded JWT in string format.
   * @param verifiers  A map of verifiers.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers) {
    return decode(encodedJWT, verifiers, h -> h.kid());
  }

  /**
   * Decode the JWT using one of they provided verifiers. A JWT header value named <code>kid</code> is expected to
   * contain the key to look up the correct verifier.
   *
   * @param encodedJWT       The encoded JWT in string format.
   * @param verifierFunction A function that takes a key identifier and returns a verifier.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Function<String, Verifier> verifierFunction) {
    return decode(encodedJWT, verifierFunction, h -> h.kid());
  }

  /**
   * Decode the JWT using one of they provided verifiers.
   *
   * @param encodedJWT       The encoded JWT in string format.
   * @param verifierFunction A function that takes a key identifier returns a verifier.
   * @param keyFunction      A function used to look up the verifier key from the header.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Function<String, Verifier> verifierFunction, Function<Header, String> keyFunction) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifierFunction);
    Objects.requireNonNull(keyFunction);
    return decodeJWT(encodedJWT, verifierFunction, keyFunction);
  }

  private JWT decodeJWT(String encodedJWT, Function<String, Verifier> verifierFunction, Function<Header, String> keyFunction) {
    String[] parts = getParts(encodedJWT);

    Header header = parseHeader(parts[0]);
    String key = keyFunction.apply(header);
    Verifier verifier = verifierFunction.apply(key);

    return validate(encodedJWT, parts, header, verifier);
  }

  /**
   * Decode the JWT using one of they provided verifiers.
   *
   * @param encodedJWT  The encoded JWT in string format.
   * @param verifiers   A map of verifiers.
   * @param keyFunction A function used to look up the verifier key from the header.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers, Function<Header, String> keyFunction) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);
    Objects.requireNonNull(keyFunction);
    return decodeJWT(encodedJWT, verifiers::get, keyFunction);
  }

  private byte[] base64Decode(String string) {
    try {
      return Base64.getUrlDecoder().decode(string);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTException("The encoded JWT is not properly Base64 encoded.", e);
    }
  }

  private String[] getParts(String encodedJWT) {
    String[] parts = encodedJWT.split("\\.");
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return parts;
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }

  @SuppressWarnings("unchecked")
  private Header parseHeader(String segment) {
    Map<String, Object> raw = Mapper.deserialize(base64Decode(segment), Map.class);
    return Header.fromMap(raw);
  }

  @SuppressWarnings("unchecked")
  private JWT parseClaims(String segment, Header header) {
    Map<String, Object> raw = Mapper.deserialize(base64Decode(segment), Map.class);
    return JWT.fromMap(raw, header);
  }

  private JWT validate(String encodedJWT, String[] parts, Header header, Verifier verifier) {
    if (parts.length == 2) {
      throw new MissingSignatureException("The JWT is missing a signature");
    }

    if (verifier == null) {
      throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.alg().name() + "]");
    }

    if (!verifier.canVerify(header.alg())) {
      throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.alg().name() + "]");
    }

    verifySignature(verifier, header, parts[2], encodedJWT);

    JWT jwt = parseClaims(parts[1], header);
    Instant now = nowInstant();

    Instant nowMinusSkew = now.minusSeconds(clockSkew);
    if (jwt.isExpired(nowMinusSkew)) {
      throw new JWTExpiredException();
    }

    Instant nowPlusSkew = now.plusSeconds(clockSkew);
    if (jwt.isUnavailableForProcessing(nowPlusSkew)) {
      throw new JWTUnavailableForProcessingException();
    }

    return jwt;
  }

  /**
   * @return the 'now' to be used to validate 'exp' and 'nbf' claims (legacy
   *     ZonedDateTime; subclasses override this for time-machine variants).
   */
  protected ZonedDateTime now() {
    return ZonedDateTime.now(ZoneOffset.UTC);
  }

  private Instant nowInstant() {
    return now().toInstant();
  }

  private void verifySignature(Verifier verifier, Header header, String signature, String encodedJWT) {
    int index = encodedJWT.lastIndexOf('.');
    byte[] message = encodedJWT.substring(0, index).getBytes(StandardCharsets.UTF_8);

    byte[] signatureBytes = base64Decode(signature);
    verifier.verify(header.alg(), message, signatureBytes);
  }
}
