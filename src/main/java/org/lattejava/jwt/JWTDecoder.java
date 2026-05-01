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

import java.time.*;
import java.util.*;
import java.util.function.*;

import org.lattejava.jwt.internal.*;

/**
 * Decodes a compact JWS into a {@link JWT}.
 *
 * <p>Defaults: {@code clockSkew=Duration.ZERO},
 * {@code maxInputBytes=262144}, {@code maxNestingDepth=16}, {@code maxNumberLength=1000},
 * {@code maxObjectMembers=1000}, {@code maxArrayElements=10000}, {@code allowDuplicateJSONKeys=false}.</p>
 *
 * <p>All fields are final; instances are immutable and safe to share. Use
 * {@link Builder} for advanced configuration (custom {@link Clock}, {@code expectedType}, {@code expectedAlgorithms},
 * {@code criticalHeaders}, size/depth/number-length limits).</p>
 *
 * @author Daniel DeGroff
 */
public class JWTDecoder {
  /**
   * Default: 256 KiB.
   */
  static final int DEFAULT_MAX_INPUT_BYTES = 262_144;

  /**
   * Default: 16.
   */
  static final int DEFAULT_MAX_NESTING_DEPTH = 16;

  /**
   * Default: 1000.
   */
  static final int DEFAULT_MAX_NUMBER_LENGTH = 1000;

  private static final JWTDecoder DEFAULT_INSTANCE = new JWTDecoder(builderDefaults());
  private final Clock clock;
  private final Duration clockSkew;
  private final Set<String> criticalHeaders;
  /**
   * Internally keyed by {@code Algorithm.name()} so hostile {@code equals} implementations on custom {@link Algorithm}s
   * cannot subvert the whitelist.
   */
  private final Set<String> expectedAlgorithmNames;
  private final String expectedType;
  private final JSONProcessor jsonProcessor;
  private final int maxInputBytes;

  /**
   * Constructs a decoder with all defaults.
   */
  public JWTDecoder() {
    this(builderDefaults());
  }

  /**
   * Constructs a decoder using the supplied {@link JSONProcessor} (defaults for everything else).
   *
   * @param jsonProcessor the JSON processor; must be non-null
   */
  public JWTDecoder(JSONProcessor jsonProcessor) {
    this(builderDefaults().jsonProcessor(jsonProcessor));
  }

  /**
   * Constructs a decoder with the supplied symmetric clock skew (defaults for everything else).
   *
   * @param clockSkew clock skew applied symmetrically to {@code exp}/{@code nbf}; must be non-null and non-negative
   */
  public JWTDecoder(Duration clockSkew) {
    this(builderDefaults().clockSkew(clockSkew));
  }

  /**
   * Constructs a decoder with the supplied {@link JSONProcessor} and symmetric clock skew (defaults for everything
   * else).
   *
   * @param jsonProcessor the JSON processor; must be non-null
   * @param clockSkew     clock skew applied symmetrically to {@code exp}/{@code nbf}; must be non-null and
   *                      non-negative
   */
  public JWTDecoder(JSONProcessor jsonProcessor, Duration clockSkew) {
    this(builderDefaults().jsonProcessor(jsonProcessor).clockSkew(clockSkew));
  }

  private JWTDecoder(Builder b) {
    // Resolve the default JSON processor lazily (so the parse-DoS limits captured
    // on the builder flow into the LatteJSONProcessor when no caller-supplied
    // processor was provided).
    if (!b.jsonProcessorExplicit) {
      b.jsonProcessor = new LatteJSONProcessor(
          b.maxNestingDepth, b.maxNumberLength, b.maxObjectMembers, b.maxArrayElements,
          b.allowDuplicateJSONKeys);
    }
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

  /**
   * Returns a new {@link Builder} preconfigured with library defaults. This is the canonical entry point for advanced
   * decoder construction.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the shared default {@link JWTDecoder} used by {@link JWT#decode(String, VerifierResolver)} and its
   * overloads. Build your own with {@link #builder()} when you need non-default settings (custom {@link JSONProcessor},
   * {@code clockSkew}, allowed algorithms, {@code fixedTime}, etc.).
   *
   * @return the shared default instance; never {@code null}
   */
  public static JWTDecoder getDefault() {
    return DEFAULT_INSTANCE;
  }

  // -------------------------------------------------------------------
  // Public decode API
  // -------------------------------------------------------------------

  /**
   * Convert an ASCII-only substring of {@code s} to a freshly allocated {@code byte[]}. Faster than
   * {@code s.substring(from, to).getBytes(UTF_8)} for ASCII because it avoids the intermediate {@code String}
   * allocation. The caller is responsible for ensuring every char in {@code [from, to)} is below 0x80.
   */
  private static byte[] asciiBytes(String s, int from, int to) {
    byte[] out = new byte[to - from];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) s.charAt(from + i);
    }
    return out;
  }

  // -------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------

  private static Builder builderDefaults() {
    return new Builder();
  }

  /**
   * Decode a base64URL segment, wrapping any {@link IllegalArgumentException} from {@code Base64URL.decode} into a
   * domain {@link InvalidJWTException}. Alphabet validity is enforced by the underlying decoder; we do not pre-scan
   * because {@code parseSegments} has already accepted the substring as ASCII via the dot-separator math.
   */
  private static byte[] decodeBase64URL(String segment, String name) {
    try {
      return Base64URL.decode(segment);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTException(
          "JWT [" + name + "] segment is not valid base64url", e);
    }
  }

  /**
   * Decode a JWT, resolving the {@link Verifier} via the supplied {@link VerifierResolver}. Signature verification runs
   * BEFORE payload deserialization, so a malformed payload cannot be observed until the signature has been validated.
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @param resolver   the verifier resolver; must be non-null
   * @return the decoded {@link JWT}
   */
  public JWT decode(String encodedJWT, VerifierResolver resolver) {
    return decode(encodedJWT, resolver, null);
  }

  /**
   * Decode a JWT with an optional post-decode validator. The validator runs after signature verification and built-in
   * time validation; implementations throw any {@link JWTException} subclass to reject the token.
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

    // Algorithm whitelist.
    if (expectedAlgorithmNames != null
        && !expectedAlgorithmNames.contains(header.alg().name())) {
      throw new InvalidJWTException(
          "Header [alg] [" + header.alg().name() + "] is not in the expectedAlgorithms whitelist");
    }

    enforceExpectedType(header);
    enforceCrit(header);

    Verifier verifier = resolver.resolve(header);
    if (verifier == null || !verifier.canVerify(header.alg())) {
      throw new MissingVerifierException(
          "No verifier provided to verify signature signed using ["
              + header.alg().name() + "]");
    }

    // Verify the signature BEFORE parsing the payload so that untrusted payload bytes never reach the JSON parser
    // unless authenticated. Compute the signing input bytes directly from the encoded JWT — a char-to-byte cast is
    // safe for the header range (Base64URL.decode in parseHeader has already rejected any non-base64url char above)
    // and avoids the String allocation that encodedJWT.substring(0, secondDot).getBytes(UTF_8) would produce. A
    // non-base64url char inside the payload range would cause asciiBytes to truncate, and the subsequent HMAC
    // comparison would fail with InvalidJWTSignatureException -- parsePayload's Base64URL.decode then surfaces the
    // structural problem after the signature path has already rejected the token.
    byte[] message = asciiBytes(encodedJWT, 0, segments.signingInputEnd);
    byte[] signatureBytes = decodeBase64URL(segments.signatureB64, "signature");
    verifier.verify(message, signatureBytes);

    JWT jwt = parsePayload(segments.payloadB64, header);
    enforceTimeClaims(jwt);

    if (validator != null) {
      validator.accept(jwt);
    }

    return jwt;
  }

  /**
   * <strong>WARNING: This method does NOT verify the JWT signature.</strong>
   * Decode only the payload claims of {@code encodedJWT}, returning the parsed JSON object as a {@link Map}. The header
   * is not parsed or examined; no time, alg, type, or crit checks run. Useful when the caller needs to peek at claims
   * (commonly to look up a verifier by {@code iss}/{@code sub}) before performing an authenticated decode.
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @return the payload JSON object as a {@link Map}; never {@code null}
   * @throws InvalidJWTException if the input is not a structurally valid JWS
   */
  public Map<String, Object> decodeClaimsUnsecured(String encodedJWT) {
    Objects.requireNonNull(encodedJWT, "encodedJWT");
    if (encodedJWT.length() > maxInputBytes) {
      throw new InvalidJWTException("Encoded JWT exceeds maxInputBytes [" + maxInputBytes + "]");
    }
    int firstDot = encodedJWT.indexOf('.');
    int secondDot = firstDot < 0 ? -1 : encodedJWT.indexOf('.', firstDot + 1);
    if (firstDot < 0 || secondDot < 0) {
      throw new InvalidJWTException("Encoded JWT is missing required segments");
    }
    String payloadB64 = encodedJWT.substring(firstDot + 1, secondDot);
    if (payloadB64.isEmpty()) {
      throw new InvalidJWTException("Encoded JWT payload segment is empty");
    }
    byte[] payloadJson = decodeBase64URL(payloadB64, "payload");
    return jsonProcessor.deserialize(payloadJson);
  }

  /**
   * <strong>WARNING: This method does NOT verify the JWT signature.</strong>
   * Decode only the header of {@code encodedJWT}. Useful for the kid-lookup pattern: read the {@code kid}/{@code alg}
   * from the header, select a verifier, then call {@link #decode(String, VerifierResolver)} for an authenticated
   * decode.
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @return the parsed {@link Header}; never {@code null}
   * @throws InvalidJWTException if the input is not a structurally valid JWS
   */
  public Header decodeHeaderUnsecured(String encodedJWT) {
    Objects.requireNonNull(encodedJWT, "encodedJWT");
    if (encodedJWT.length() > maxInputBytes) {
      throw new InvalidJWTException("Encoded JWT exceeds maxInputBytes [" + maxInputBytes + "]");
    }
    int firstDot = encodedJWT.indexOf('.');
    if (firstDot <= 0) {
      throw new InvalidJWTException("Encoded JWT header segment is empty or missing");
    }
    String headerB64 = encodedJWT.substring(0, firstDot);
    return parseHeader(headerB64);
  }

  /**
   * <strong>WARNING: This method does NOT verify the JWT signature.</strong>
   * The returned {@link JWT} has its header and claims populated but the token's authenticity has not been validated.
   * Only the minimum structural defenses run (input size cap, segment count, base64url decode validity); the decoder's
   * configured {@code expectedType}, {@code expectedAlgorithms}, {@code criticalHeaders}, and time-claim checks are
   * <em>not</em> applied. Callers using this method are expected to inspect or verify the returned JWT themselves.
   *
   * @param encodedJWT the compact JWS string; must be non-null
   * @return a {@link JWT} populated from the unverified token
   */
  public JWT decodeUnsecured(String encodedJWT) {
    Objects.requireNonNull(encodedJWT, "encodedJWT");

    Segments segments = parseSegments(encodedJWT, /* requireSignature */ false);
    Header header = parseHeader(segments.headerB64);
    return parsePayload(segments.payloadB64, header);
  }

  private void enforceCrit(Header header) {
    Object critValue = header.get("crit");
    if (critValue == null) {
      return;
    }
    if (!(critValue instanceof List<?> critList)) {
      // Header.fromMap already structurally validated, but defense-in-depth.
      throw new InvalidJWTException("Header [crit] must be a JSON array of strings");
    }
    for (Object name : critList) {
      if (!(name instanceof String entry)) {
        throw new InvalidJWTException("Header [crit] elements must be strings");
      }
      if (!criticalHeaders.contains(entry)) {
        throw new InvalidJWTException(
            "Header [crit] lists unrecognized critical parameter [" + MessageSanitizer.forMessage(entry) + "]");
      }
    }
  }

  private void enforceExpectedType(Header header) {
    if (expectedType == null) {
      return;
    }
    String typ = header.typ();
    if (typ == null || !typ.equalsIgnoreCase(expectedType)) {
      throw new InvalidJWTException("Header [typ] [" + MessageSanitizer.forMessage(typ)
          + "] does not match expectedType [" + expectedType + "]");
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

  private Header parseHeader(String headerB64) {
    // Base64URL.decode is the alphabet check; a separate pre-scan would walk the segment a second time for no gain.
    byte[] headerJson = decodeBase64URL(headerB64, "header");
    Map<String, Object> raw = jsonProcessor.deserialize(headerJson);
    return Header.fromMap(raw);
  }

  private JWT parsePayload(String payloadB64, Header header) {
    // Base64URL.decode is the alphabet check; a separate pre-scan would walk the segment a second time for no gain.
    byte[] payloadJson = decodeBase64URL(payloadB64, "payload");
    Map<String, Object> raw = jsonProcessor.deserialize(payloadJson);
    return JWT.fromMap(raw, header);
  }

  /**
   * Parse the input into segments after enforcing size and structural defenses.
   */
  private Segments parseSegments(String encodedJWT, boolean requireSignature) {
    // Compact JWS uses only base64url + '.', a strict ASCII subset, so the
    // String char count equals the UTF-8 byte count. Any non-ASCII char would
    // be rejected by the per-character base64url alphabet scan below.
    if (encodedJWT.length() > maxInputBytes) {
      throw new InvalidJWTException(
          "Encoded JWT exceeds maxInputBytes [" + maxInputBytes + "]");
    }

    // Count separator positions directly -- String.split would trim a trailing
    // empty signature segment and we need to distinguish "a.b." (3 segments,
    // empty signature) from "a.b" (2 segments, no separator).
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
    // Base64URL alphabet validation is deferred to the per-segment decode calls
    // (decodeBase64URL below). java.util.Base64.getUrlDecoder() rejects invalid
    // characters with IllegalArgumentException, which we wrap into
    // InvalidJWTException with the segment name. For authenticated decode an
    // empty signature segment is structurally valid here ("a.b." passes); the
    // verifier rejects it downstream.

    // The signing input is the contiguous prefix encodedJWT[0, secondDot). Store the
    // boundary index rather than allocating a substring — decode() converts the bytes
    // directly via asciiBytes() when it needs them, and decodeUnsecured() doesn't need
    // them at all, so we save the allocation on that path entirely.
    return new Segments(headerB64, payloadB64, signatureB64, secondDot);
  }

  // -------------------------------------------------------------------
  // Builder
  // -------------------------------------------------------------------

  /**
   * Mutable, reusable builder for {@link JWTDecoder}. After {@link #build()} is called, the builder retains its state
   * and may be further modified to produce additional independent {@link JWTDecoder} instances; each {@code build()}
   * call produces a fresh immutable instance with an independent copy of any collection fields.
   */
  public static final class Builder {
    private boolean allowDuplicateJSONKeys = false;
    private Clock clock = Clock.systemUTC();
    private Duration clockSkew = Duration.ZERO;
    private Set<String> criticalHeaders = Collections.emptySet();
    private Set<Algorithm> expectedAlgorithms = null;
    private String expectedType = null;
    private JSONProcessor jsonProcessor;
    private boolean jsonProcessorExplicit = false;
    private int maxArrayElements = LatteJSONProcessor.DEFAULT_MAX_ARRAY_ELEMENTS;
    private int maxInputBytes = DEFAULT_MAX_INPUT_BYTES;
    private int maxNestingDepth = DEFAULT_MAX_NESTING_DEPTH;
    private int maxNumberLength = DEFAULT_MAX_NUMBER_LENGTH;
    private int maxObjectMembers = LatteJSONProcessor.DEFAULT_MAX_OBJECT_MEMBERS;

    private Builder() {
    }

    public Builder allowDuplicateJSONKeys(boolean allow) {
      this.allowDuplicateJSONKeys = allow;
      return this;
    }

    public JWTDecoder build() {
      return new JWTDecoder(this);
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

    /**
     * Whitelist of algorithms this decoder will accept. A header {@code alg} outside this set is rejected before
     * verifier resolution, even if a matching verifier exists.
     *
     * <p>Every {@link Verifier} is already 1:1 bound to a single algorithm
     * at construction time, so this whitelist is a policy layer on top of the structural protection -- not the primary
     * defense against algorithm confusion. Typical uses: subsetting a shared verifier pool for one endpoint,
     * deprecation windows where old-algorithm keys remain in the keystore but are no longer accepted, and
     * defense-in-depth pinning.</p>
     *
     * <p>Null or empty disables the whitelist (all resolvable algorithms
     * accepted).</p>
     *
     * @param expectedAlgorithms the whitelist, or null to disable
     * @return this builder
     */
    public Builder expectedAlgorithms(Set<Algorithm> expectedAlgorithms) {
      this.expectedAlgorithms = expectedAlgorithms == null
          ? null
          : new LinkedHashSet<>(expectedAlgorithms);
      return this;
    }

    public Builder expectedType(String expectedType) {
      this.expectedType = expectedType;
      return this;
    }

    /**
     * Convenience for {@code clock(Clock.fixed(instant, ZoneOffset.UTC))}.
     */
    public Builder fixedTime(Instant instant) {
      Objects.requireNonNull(instant, "instant");
      this.clock = Clock.fixed(instant, ZoneOffset.UTC);
      return this;
    }

    public Builder jsonProcessor(JSONProcessor jsonProcessor) {
      this.jsonProcessor = Objects.requireNonNull(jsonProcessor, "jsonProcessor");
      this.jsonProcessorExplicit = true;
      return this;
    }

    public Builder maxArrayElements(int maxArrayElements) {
      if (maxArrayElements <= 0) {
        throw new IllegalArgumentException("maxArrayElements must be > 0");
      }
      this.maxArrayElements = maxArrayElements;
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

    public Builder maxObjectMembers(int maxObjectMembers) {
      if (maxObjectMembers <= 0) {
        throw new IllegalArgumentException("maxObjectMembers must be > 0");
      }
      this.maxObjectMembers = maxObjectMembers;
      return this;
    }
  }

  private record Segments(String headerB64, String payloadB64, String signatureB64, int signingInputEnd) {
  }
}
