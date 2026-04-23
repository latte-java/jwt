/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.lattejava.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Consumer;

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
 * @author The Latte Project
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
  // Backwards-compatible bridges (TODO Checkpoint 8: remove after legacy
  // callers migrate to the new HeaderCustomizer-shaped API).
  // ----------------------------------------------------------------------

  // ----------------------------------------------------------------------
  // No legacy bridges: existing call sites use the new
  // Consumer<HeaderCustomizer> shape via lambdas like b -> b.kid("abc"),
  // which compile-fits the new interface (typ/kid/parameter are all available
  // on HeaderCustomizer). Pre-existing test callers continue to work without
  // bridge methods.
  // ----------------------------------------------------------------------

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
          "Encoder invariant violated: header.alg [" + (header.alg() == null ? "null" : header.alg().name())
              + "] must equal signer.algorithm [" + signer.algorithm().name() + "]");
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
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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
