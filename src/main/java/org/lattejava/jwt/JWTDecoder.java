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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Decodes a compact JWS into a {@link JWT}.
 *
 * <p>Defaults: {@code clockSkew=Duration.ZERO},
 * {@code maxInputBytes=262144}, {@code maxNestingDepth=16},
 * {@code maxNumberLength=1000}, {@code allowDuplicateJSONKeys=false}.</p>
 *
 * <p>All fields are final; instances are immutable and safe to share. Use
 * {@link Builder} for advanced configuration (custom {@link Clock},
 * {@code expectedType}, {@code expectedAlgorithms}, {@code criticalHeaders},
 * size/depth/number-length limits).</p>
 *
 * @author The Latte Project
 */
public class JWTDecoder {
  /** Default: 256 KiB. */
  static final int DEFAULT_MAX_INPUT_BYTES = 262_144;

  /** Default: 16. */
  static final int DEFAULT_MAX_NESTING_DEPTH = 16;

  /** Default: 1000. */
  static final int DEFAULT_MAX_NUMBER_LENGTH = 1000;

  private final JSONProcessor jsonProcessor;
  private final Clock clock;
  private final Duration clockSkew;
  private final Set<String> criticalHeaders;
  private final String expectedType;
  /** Internally keyed by {@code Algorithm.name()} so hostile {@code equals}
   * implementations on custom {@link Algorithm}s cannot subvert the whitelist. */
  private final Set<String> expectedAlgorithmNames;
  private final int maxInputBytes;

  /** Constructs a decoder with all defaults. */
  public JWTDecoder() {
    this(builderDefaults().materialize());
  }

  /**
   * Constructs a decoder using the supplied {@link JSONProcessor} (defaults
   * for everything else).
   *
   * @param jsonProcessor the JSON processor; must be non-null
   */
  public JWTDecoder(JSONProcessor jsonProcessor) {
    this(builderDefaults().jsonProcessor(jsonProcessor).materialize());
  }

  /**
   * Constructs a decoder with the supplied symmetric clock skew (defaults
   * for everything else).
   *
   * @param clockSkew clock skew applied symmetrically to {@code exp}/{@code nbf};
   *                  must be non-null and non-negative
   */
  public JWTDecoder(Duration clockSkew) {
    this(builderDefaults().clockSkew(clockSkew).materialize());
  }

  /**
   * Constructs a decoder with the supplied {@link JSONProcessor} and
   * symmetric clock skew (defaults for everything else).
   *
   * @param jsonProcessor the JSON processor; must be non-null
   * @param clockSkew     clock skew applied symmetrically to {@code exp}/{@code nbf};
   *                      must be non-null and non-negative
   */
  public JWTDecoder(JSONProcessor jsonProcessor, Duration clockSkew) {
    this(builderDefaults().jsonProcessor(jsonProcessor).clockSkew(clockSkew).materialize());
  }

  private JWTDecoder(Builder b) {
    this.jsonProcessor = b.jsonProcessor;
    this.clock = b.clock;
    this.clockSkew = b.clockSkew;
    this.criticalHeaders = Collections.unmodifiableSet(new LinkedHashSet<>(b.criticalHeaders));
    this.expectedType = b.expectedType;
    if (b.expectedAlgorithms == null) {
      this.expectedAlgorithmNames = null;
    } else {
      LinkedHashSet<String> names = new LinkedHashSet<>(b.expectedAlgorithms.size());
      for (Algorithm a : b.expectedAlgorithms) {
        names.add(a.name());
      }
      this.expectedAlgorithmNames = Collections.unmodifiableSet(names);
    }
    this.maxInputBytes = b.maxInputBytes;
  }

  private static Builder builderDefaults() {
    return new Builder();
  }

  // -------------------------------------------------------------------
  // Public decode API
  // -------------------------------------------------------------------

  /**
   * Decode a JWT, resolving the {@link Verifier} via the supplied
   * {@link VerifierResolver}. Signature verification runs BEFORE payload
   * deserialization so a malformed payload cannot be observed until the
   * signature has been validated.
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @param resolver   the verifier resolver; must be non-null
   * @return the decoded {@link JWT}
   */
  public JWT decode(String encodedJWT, VerifierResolver resolver) {
    return decode(encodedJWT, resolver, null);
  }

  /**
   * Decode a JWT with an optional post-decode validator. The validator
   * runs after signature verification and built-in time validation;
   * implementations throw any {@link JWTException} subclass to reject the
   * token.
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @param resolver   the verifier resolver; must be non-null
   * @param validator  optional post-decode validator; may be null
   * @return the decoded {@link JWT}
   */
  public JWT decode(String encodedJWT, VerifierResolver resolver, Consumer<JWT> validator) {
    Objects.requireNonNull(encodedJWT, "encodedJWT");
    Objects.requireNonNull(resolver, "resolver");

    Segments segments = parseSegments(encodedJWT, /* requireSignature */ true);
    Header header = parseHeader(segments.headerB64);

    // Step 5: algorithm whitelist
    if (expectedAlgorithmNames != null
        && !expectedAlgorithmNames.contains(header.alg().name())) {
      throw new InvalidJWTException(
          "Header [alg] [" + header.alg().name() + "] is not in the expectedAlgorithms whitelist");
    }

    // Step 6: type check
    enforceExpectedType(header);

    // Step 7: crit understood-parameters check
    enforceCrit(header);

    // Step 8: resolve verifier
    Verifier verifier = resolver.resolve(header);
    if (verifier == null || !verifier.canVerify(header.alg())) {
      throw new MissingVerifierException(
          "No verifier provided to verify signature signed using ["
              + header.alg().name() + "]");
    }

    // Step 9: verify signature BEFORE parsing payload
    String signingInput = segments.headerB64 + "." + segments.payloadB64;
    byte[] message = signingInput.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = strictBase64UrlDecode(segments.signatureB64, "signature");
    verifier.verify(header.alg(), message, signatureBytes);

    // Step 10: parse payload
    JWT jwt = parsePayload(segments.payloadB64, header);

    // Step 11: time validation with clock skew
    enforceTimeClaims(jwt);

    // Step 12: custom validator
    if (validator != null) {
      validator.accept(jwt);
    }

    return jwt;
  }

  /**
   * <strong>WARNING: This method does NOT verify the JWT signature.</strong>
   * The returned {@link JWT} has its header and claims populated but the
   * token's authenticity has not been validated. Size and structural defenses
   * still run (input size cap, segment count, base64url strictness, typ check).
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @return a {@link JWT} populated from the unverified token
   */
  public JWT decodeUnsecured(String encodedJWT) {
    Objects.requireNonNull(encodedJWT, "encodedJWT");

    Segments segments = parseSegments(encodedJWT, /* requireSignature */ false);
    Header header = parseHeader(segments.headerB64);
    enforceExpectedType(header);   // typ check still runs on unsecured decode
    return parsePayload(segments.payloadB64, header);
  }

  // -------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------

  /** Parse the input into segments after enforcing size and structural defenses. */
  private Segments parseSegments(String encodedJWT, boolean requireSignature) {
    // Step 1: input size check
    if (encodedJWT.getBytes(StandardCharsets.UTF_8).length > maxInputBytes) {
      throw new InvalidJWTException(
          "Encoded JWT exceeds maxInputBytes [" + maxInputBytes + "]");
    }

    // Step 3: split on '.', count segments by separator position.
    // We do NOT use String.split (which trims trailing empties); count dots
    // explicitly so that "a.b." (3 segments, empty signature) is recognized.
    int firstDot = encodedJWT.indexOf('.');
    int secondDot = firstDot < 0 ? -1 : encodedJWT.indexOf('.', firstDot + 1);
    int thirdDot = secondDot < 0 ? -1 : encodedJWT.indexOf('.', secondDot + 1);

    if (firstDot < 0 || secondDot < 0) {
      // Fewer than 2 separators -> 1 or 2 segments -> missing signature
      throw new MissingSignatureException(
          "Encoded JWT is missing a signature; expected three dot-separated segments");
    }
    if (thirdDot >= 0) {
      throw new InvalidJWTException(
          "Encoded JWT has more than three segments; expected exactly two '.' separators");
    }

    String headerB64 = encodedJWT.substring(0, firstDot);
    String payloadB64 = encodedJWT.substring(firstDot + 1, secondDot);
    String signatureB64 = encodedJWT.substring(secondDot + 1);

    if (headerB64.isEmpty()) {
      throw new InvalidJWTException("Encoded JWT header segment is empty");
    }
    if (payloadB64.isEmpty()) {
      throw new InvalidJWTException("Encoded JWT payload segment is empty");
    }

    // Step 2: base64url strictness on header and payload (signature handled
    // when we decode it).
    enforceStrictBase64Url(headerB64, "header");
    enforceStrictBase64Url(payloadB64, "payload");
    if (!signatureB64.isEmpty()) {
      enforceStrictBase64Url(signatureB64, "signature");
    } else if (requireSignature) {
      // For authenticated decode we still pass empty bytes through to the
      // verifier; built-in verifiers reject. We do not raise
      // MissingSignatureException here -- "a.b." is structurally valid, so
      // the rejection is handled by the verifier path. Resolver may still
      // return null first -> MissingVerifierException.
    }

    return new Segments(headerB64, payloadB64, signatureB64);
  }

  private Header parseHeader(String headerB64) {
    byte[] headerJson = strictBase64UrlDecode(headerB64, "header");
    Map<String, Object> raw = jsonProcessor.deserialize(headerJson);
    return Header.fromMap(raw);
  }

  private JWT parsePayload(String payloadB64, Header header) {
    byte[] payloadJson = strictBase64UrlDecode(payloadB64, "payload");
    Map<String, Object> raw = jsonProcessor.deserialize(payloadJson);
    return JWT.fromMap(raw, header);
  }

  private void enforceExpectedType(Header header) {
    if (expectedType == null) {
      return;
    }
    String typ = header.typ();
    if (typ == null || !typ.equalsIgnoreCase(expectedType)) {
      throw new InvalidJWTException("Header [typ] [" + typ
          + "] does not match expectedType [" + expectedType + "]");
    }
  }

  @SuppressWarnings("unchecked")
  private void enforceCrit(Header header) {
    Object critValue = header.get("crit");
    if (critValue == null) {
      return;
    }
    if (!(critValue instanceof List)) {
      // Header.fromMap already structurally validated, but defense-in-depth.
      throw new InvalidJWTException("Header [crit] must be a JSON array of strings");
    }
    for (Object name : (List<Object>) critValue) {
      if (!(name instanceof String)) {
        throw new InvalidJWTException("Header [crit] elements must be strings");
      }
      String entry = (String) name;
      if (!criticalHeaders.contains(entry)) {
        throw new InvalidJWTException(
            "Header [crit] lists unrecognized critical parameter [" + entry + "]");
      }
    }
  }

  private void enforceTimeClaims(JWT jwt) {
    long skewSeconds = clockSkew.getSeconds();
    Instant now = Instant.now(clock);
    Instant nowMinusSkew = skewSeconds > 0 ? now.minusSeconds(skewSeconds) : now;
    if (jwt.isExpired(nowMinusSkew)) {
      throw new JWTExpiredException(jwt.expiresAt(), now, clockSkew);
    }
    Instant nowPlusSkew = skewSeconds > 0 ? now.plusSeconds(skewSeconds) : now;
    if (jwt.isUnavailableForProcessing(nowPlusSkew)) {
      throw new JWTUnavailableForProcessingException(jwt.notBefore(), now, clockSkew);
    }
  }

  // -------------------------------------------------------------------
  // Strict base64url decode (alphabet, no padding, no whitespace)
  // -------------------------------------------------------------------

  static byte[] strictBase64UrlDecode(String segment, String name) {
    int len = segment.length();
    for (int i = 0; i < len; i++) {
      char c = segment.charAt(i);
      boolean ok = (c >= 'A' && c <= 'Z')
          || (c >= 'a' && c <= 'z')
          || (c >= '0' && c <= '9')
          || c == '-' || c == '_';
      if (!ok) {
        throw new InvalidJWTException(
            "JWT [" + name + "] segment contains invalid base64url character ["
                + c + "] at position [" + i + "]");
      }
    }
    try {
      return Base64.getUrlDecoder().decode(segment);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTException(
          "JWT [" + name + "] segment is not valid base64url", e);
    }
  }

  static void enforceStrictBase64Url(String segment, String name) {
    int len = segment.length();
    for (int i = 0; i < len; i++) {
      char c = segment.charAt(i);
      boolean ok = (c >= 'A' && c <= 'Z')
          || (c >= 'a' && c <= 'z')
          || (c >= '0' && c <= '9')
          || c == '-' || c == '_';
      if (!ok) {
        throw new InvalidJWTException(
            "JWT [" + name + "] segment contains invalid base64url character ["
                + c + "] at position [" + i + "]");
      }
    }
  }

  private static final class Segments {
    final String headerB64;
    final String payloadB64;
    final String signatureB64;

    Segments(String h, String p, String s) {
      this.headerB64 = h;
      this.payloadB64 = p;
      this.signatureB64 = s;
    }
  }

  // -------------------------------------------------------------------
  // Builder
  // -------------------------------------------------------------------

  /**
   * Returns a new {@link Builder} preconfigured with library defaults. This
   * is the canonical entry point for advanced decoder construction.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Mutable, reusable builder for {@link JWTDecoder}. After {@link #build()}
   * is called, the builder retains its state and may be further modified to
   * produce additional independent {@link JWTDecoder} instances; each
   * {@code build()} call produces a fresh immutable instance with an
   * independent copy of any collection fields.
   */
  public static final class Builder {
    private JSONProcessor jsonProcessor;
    private Clock clock = Clock.systemUTC();
    private Duration clockSkew = Duration.ZERO;
    private Set<String> criticalHeaders = Collections.emptySet();
    private String expectedType = null;
    private Set<Algorithm> expectedAlgorithms = null;
    private int maxInputBytes = DEFAULT_MAX_INPUT_BYTES;
    private int maxNestingDepth = DEFAULT_MAX_NESTING_DEPTH;
    private int maxNumberLength = DEFAULT_MAX_NUMBER_LENGTH;
    private boolean allowDuplicateJSONKeys = false;
    private boolean jsonProcessorExplicit = false;

    private Builder() {}

    public Builder jsonProcessor(JSONProcessor jsonProcessor) {
      this.jsonProcessor = Objects.requireNonNull(jsonProcessor, "jsonProcessor");
      this.jsonProcessorExplicit = true;
      return this;
    }

    /**
     * Override the {@link Clock} used for time validation.
     *
     * <p><strong>Tests and time travelers only.</strong> Production code must
     * leave this at {@link Clock#systemUTC()}.</p>
     */
    public Builder clock(Clock clock) {
      this.clock = Objects.requireNonNull(clock, "clock");
      return this;
    }

    /** Convenience for {@code clock(Clock.fixed(instant, ZoneOffset.UTC))}. */
    public Builder fixedTime(Instant instant) {
      Objects.requireNonNull(instant, "instant");
      this.clock = Clock.fixed(instant, ZoneOffset.UTC);
      return this;
    }

    public Builder clockSkew(Duration clockSkew) {
      Objects.requireNonNull(clockSkew, "clockSkew");
      if (clockSkew.isNegative()) {
        throw new IllegalArgumentException("clockSkew must not be negative");
      }
      this.clockSkew = clockSkew;
      return this;
    }

    public Builder criticalHeaders(Set<String> criticalHeaders) {
      this.criticalHeaders = criticalHeaders == null
          ? Collections.emptySet()
          : new LinkedHashSet<>(criticalHeaders);
      return this;
    }

    public Builder expectedType(String expectedType) {
      this.expectedType = expectedType;
      return this;
    }

    public Builder expectedAlgorithms(Set<Algorithm> expectedAlgorithms) {
      this.expectedAlgorithms = expectedAlgorithms == null
          ? null
          : new LinkedHashSet<>(expectedAlgorithms);
      return this;
    }

    public Builder maxInputBytes(int maxInputBytes) {
      if (maxInputBytes <= 0) {
        throw new IllegalArgumentException("maxInputBytes must be > 0");
      }
      this.maxInputBytes = maxInputBytes;
      return this;
    }

    public Builder maxNestingDepth(int maxNestingDepth) {
      if (maxNestingDepth <= 0) {
        throw new IllegalArgumentException("maxNestingDepth must be > 0");
      }
      this.maxNestingDepth = maxNestingDepth;
      return this;
    }

    public Builder maxNumberLength(int maxNumberLength) {
      if (maxNumberLength <= 0) {
        throw new IllegalArgumentException("maxNumberLength must be > 0");
      }
      this.maxNumberLength = maxNumberLength;
      return this;
    }

    public Builder allowDuplicateJSONKeys(boolean allow) {
      this.allowDuplicateJSONKeys = allow;
      return this;
    }

    public JWTDecoder build() {
      return new JWTDecoder(materialize());
    }

    /**
     * Materializes the builder into a frozen state ready for the
     * {@link JWTDecoder} constructor. Resolves the default
     * {@link LatteJSONProcessor} (configured with the parse-DoS limits from
     * this builder) when no processor was explicitly supplied.
     */
    Builder materialize() {
      if (!jsonProcessorExplicit) {
        // Default LatteJSONProcessor honors the parse-DoS limits configured
        // on this builder. Caller-supplied processors are expected to enforce
        // their own limits.
        this.jsonProcessor = new LatteJSONProcessor(
            maxNestingDepth, maxNumberLength, allowDuplicateJSONKeys);
      }
      return this;
    }
  }
}
