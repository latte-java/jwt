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

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Consumer;

import org.lattejava.jwt.internal.Base64URL;

/**
 * Encodes a {@link JWT} into a compact JWS string:
 *
 * <ol>
 *   <li>Build {@link Header} -- pre-populated with {@code alg} from
 *       {@link Signer#algorithm()} and {@code kid} from {@link Signer#kid()}.</li>
 *   <li>Serialize header via {@link JSONProcessor} and base64url-encode (no padding).</li>
 *   <li>Serialize JWT claims and base64url-encode (no padding).</li>
 *   <li>Concatenate {@code headerB64.payloadB64}.</li>
 *   <li>Convert the concatenated string to bytes via {@code getBytes(UTF_8)},
 *       call {@link Signer#sign(byte[])}, base64url-encode the signature.</li>
 *   <li>Return {@code headerB64.payloadB64.signatureB64}.</li>
 * </ol>
 *
 * <p>The {@code alg} header parameter is always derived from the signer and
 * cannot be modified by the caller -- {@link HeaderCustomizer} intentionally
 * has no {@code .alg()} method (compile-time guarantee).</p>
 *
 * @author Daniel DeGroff
 */
public class JWTEncoder {
  private final JSONProcessor jsonProcessor;

  /** Constructs an encoder using the built-in {@link LatteJSONProcessor}. */
  public JWTEncoder() {
    this(new LatteJSONProcessor());
  }

  /**
   * Constructs an encoder using the given {@link JSONProcessor}.
   *
   * @param jsonProcessor the JSON processor; must be non-null
   */
  public JWTEncoder(JSONProcessor jsonProcessor) {
    this.jsonProcessor = Objects.requireNonNull(jsonProcessor, "jsonProcessor");
  }

  /**
   * Encode a JWT using the signer's defaults (no header customization).
   *
   * @param jwt    the JWT to encode; must be non-null
   * @param signer the signer; must be non-null
   * @return the compact JWS string
   */
  public String encode(JWT jwt, Signer signer) {
    return encodeInternal(jwt, signer, null);
  }

  /**
   * Encode a JWT, allowing the caller to customize header parameters
   * (other than {@code alg}, which is always taken from the signer).
   *
   * @param jwt        the JWT to encode; must be non-null
   * @param signer     the signer; must be non-null
   * @param customizer the header customizer; may be null
   * @return the compact JWS string
   */
  public String encode(JWT jwt, Signer signer, Consumer<HeaderCustomizer> customizer) {
    return encodeInternal(jwt, signer, customizer);
  }

  // ----------------------------------------------------------------------

  private String encodeInternal(JWT jwt, Signer signer, Consumer<HeaderCustomizer> customizer) {
    Objects.requireNonNull(jwt, "jwt");
    Objects.requireNonNull(signer, "signer");

    // Step 1: build header. Pre-populate alg from signer.algorithm() and kid from signer.kid().
    Header.Builder builder = Header.builder().alg(signer.algorithm()).kid(signer.kid());

    if (customizer != null) {
      // The HeaderCustomizer view intentionally lacks .alg() -- the type system
      // prevents the caller from overriding the signer-derived algorithm.
      customizer.accept(new BuilderHeaderCustomizer(builder));
    }

    Header header = builder.build();

    // Defense-in-depth: even if a custom Header.Builder mutation slipped through,
    // the encoded header MUST advertise the signer's algorithm.
    if (header.alg() == null || !header.alg().name().equals(signer.algorithm().name())) {
      throw new IllegalStateException(
          "Encoder invariant violated: expected header.alg [" + signer.algorithm().name()
              + "] but found [" + (header.alg() == null ? "null" : header.alg().name()) + "]");
    }

    // Steps 2-3: serialize header and payload, base64url (no padding).
    byte[] headerJson = jsonProcessor.serialize(header.toSerializableMap());
    byte[] payloadJson = jsonProcessor.serialize(jwt.toSerializableMap());

    String encodedHeader = base64UrlEncode(headerJson);
    String encodedPayload = base64UrlEncode(payloadJson);

    // Steps 4-5: concatenate, sign, base64url-encode the signature.
    String signingInput = encodedHeader + "." + encodedPayload;
    byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.UTF_8));
    String encodedSignature = base64UrlEncode(signature);

    // Step 6: return the compact JWS.
    return signingInput + "." + encodedSignature;
  }

  private static String base64UrlEncode(byte[] bytes) {
    return Base64URL.encodeToString(bytes);
  }

  /**
   * Adapts a {@link Header.Builder} to the {@link HeaderCustomizer} view.
   * The view exposes {@code typ}, {@code kid}, and arbitrary
   * {@code parameter(name, value)} -- but no {@code .alg()}.
   */
  private static final class BuilderHeaderCustomizer implements HeaderCustomizer {
    private final Header.Builder builder;

    BuilderHeaderCustomizer(Header.Builder builder) {
      this.builder = builder;
    }

    @Override
    public HeaderCustomizer typ(String type) {
      builder.typ(type);
      return this;
    }

    @Override
    public HeaderCustomizer kid(String keyId) {
      builder.kid(keyId);
      return this;
    }

    @Override
    public HeaderCustomizer parameter(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if ("alg".equals(name)) {
        throw new IllegalArgumentException(
            "HeaderCustomizer cannot set [alg] -- the algorithm is determined by the Signer");
      }
      builder.parameter(name, value);
      return this;
    }
  }
}
