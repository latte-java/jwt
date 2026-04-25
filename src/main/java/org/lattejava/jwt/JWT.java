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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * JSON Web Token (JWT) as defined by RFC 7519.
 *
 * <p>This type is immutable. Instances are created via the {@link #builder()}
 * fluent API or hydrated from a JSON map via {@link #fromMap(Map, Header)}.</p>
 *
 * @author Daniel DeGroff
 */
public final class JWT {
  private static final Set<String> REGISTERED_CLAIM_NAMES = new HashSet<>(Arrays.asList(
      "iss", "sub", "aud", "exp", "nbf", "iat", "jti"
  ));

  private static final long MAX_INSTANT_SECOND_LONG = Instant.MAX.getEpochSecond();
  private static final long MIN_INSTANT_SECOND_LONG = Instant.MIN.getEpochSecond();
  private static final BigInteger MAX_INSTANT_SECOND = BigInteger.valueOf(MAX_INSTANT_SECOND_LONG);
  private static final BigInteger MIN_INSTANT_SECOND = BigInteger.valueOf(MIN_INSTANT_SECOND_LONG);

  private final String issuer;

  private final String subject;

  private final List<String> audience;

  private final AudienceSerialization audienceSerialization;

  private final Instant expiresAt;

  private final Instant notBefore;

  private final Instant issuedAt;

  private final String id;

  private final Map<String, Object> customClaims;

  private final Header header;

  private JWT(Builder b) {
    this.issuer = b.issuer;
    this.subject = b.subject;
    if (b.audience == null) {
      this.audience = Collections.emptyList();
      this.audienceSerialization = null;
    } else {
      // Defensive copy is null-permissive (preserves any null elements) by going
      // through ArrayList rather than List.copyOf, which rejects nulls.
      this.audience = Collections.unmodifiableList(new ArrayList<>(b.audience));
      this.audienceSerialization = b.audienceSerialization == null
          ? AudienceSerialization.ALWAYS_ARRAY
          : b.audienceSerialization;
    }
    this.expiresAt = b.expiresAt;
    this.notBefore = b.notBefore;
    this.issuedAt = b.issuedAt;
    this.id = b.id;
    this.customClaims = b.customClaims == null || b.customClaims.isEmpty()
        ? Collections.emptyMap()
        : Collections.unmodifiableMap(new LinkedHashMap<>(b.customClaims));
    this.header = b.header;
  }

  // ---------- Fluent getters ----------

  /**
   * Registered Claim {@code iss} as defined by RFC 7519 §4.1.1. Use of this claim is OPTIONAL.
   * <p>
   * The issuer claim identifies the principal that issued the JWT. If the value contains a
   * {@code :} it must be a URI.
   */
  public String issuer() {
    return issuer;
  }

  /**
   * Registered Claim {@code sub} as defined by RFC 7519 §4.1.2. Use of this claim is OPTIONAL.
   * <p>
   * The subject claim identifies the principal that is the subject of the JWT. If the value
   * contains a {@code :} it must be a URI.
   */
  public String subject() {
    return subject;
  }

  /**
   * Registered Claim {@code exp} as defined by RFC 7519 §4.1.4. Use of this claim is OPTIONAL.
   * <p>
   * The expiration time claim identifies the expiration time on or after which the JWT MUST NOT
   * be accepted for processing. Serialized as NumericDate (seconds since Epoch).
   */
  public Instant expiresAt() {
    return expiresAt;
  }

  /**
   * Registered Claim {@code nbf} as defined by RFC 7519 §4.1.5. Use of this claim is OPTIONAL.
   * <p>
   * This claim identifies the time before which the JWT MUST NOT be accepted for processing.
   * Serialized as NumericDate (seconds since Epoch).
   */
  public Instant notBefore() {
    return notBefore;
  }

  /**
   * Registered Claim {@code iat} as defined by RFC 7519 §4.1.6. Use of this claim is OPTIONAL.
   * <p>
   * The issued at claim identifies the time at which the JWT was issued. Serialized as
   * NumericDate (seconds since Epoch).
   */
  public Instant issuedAt() {
    return issuedAt;
  }

  /**
   * Registered Claim {@code jti} as defined by RFC 7519 §4.1.7. Use of this claim is OPTIONAL.
   * <p>
   * The JWT ID claim provides a unique identifier for the JWT.
   */
  public String id() {
    return id;
  }

  /**
   * The decoded JWT header. This is not considered part of the JWT payload, but is attached
   * here for caller convenience.
   */
  public Header header() {
    return header;
  }

  // ---------- Audience ----------

  /**
   * Registered Claim {@code aud} as defined by RFC 7519 §4.1.3. Use of this claim is OPTIONAL.
   * <p>
   * The audience claim identifies the recipients that the JWT is intended for. On the wire this
   * may be an array of strings or a single string; any string values containing a {@code :} must
   * be URIs. This accessor always returns a list (empty if the claim is absent); the
   * {@link AudienceSerialization} mode selects the serialized form and is available via
   * {@link #audienceSerialization()}.
   */
  public List<String> audience() {
    return audience;
  }

  /**
   * The {@link AudienceSerialization} mode for this JWT, or {@code null} when
   * {@code aud} is absent.
   */
  public AudienceSerialization audienceSerialization() {
    return audienceSerialization;
  }

  /**
   * Returns {@code true} if {@code value} appears in the {@code aud} claim.
   * {@code null} input returns {@code false}.
   */
  public boolean hasAudience(String value) {
    return value != null && audience.contains(value);
  }

  // ---------- Custom-claim accessors ----------

  /*
   * The get* family looks up a claim by name (registered or custom) and
   * coerces to the requested Java type. Absent claims return null; present
   * claims of the wrong JSON type throw InvalidJWTException (or
   * ClassCastException for typed list elements).
   */

  /** Look up a claim as a {@link String}. Returns {@code null} if absent; throws if the claim is not a JSON string. */
  public String getString(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof String s) {
      return s;
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a String");
  }

  /** Look up a numeric claim and narrow to {@code int} via {@link Number#intValue()}; returns {@code null} if absent. */
  public Integer getInteger(String name) {
    Number n = (Number) lookup(name);
    return n == null ? null : n.intValue();
  }

  /** Look up a numeric claim and narrow to {@code long} via {@link Number#longValue()}; returns {@code null} if absent. */
  public Long getLong(String name) {
    Number n = (Number) lookup(name);
    return n == null ? null : n.longValue();
  }

  /** Look up a numeric claim and narrow to {@code float} via {@link Number#floatValue()}; returns {@code null} if absent. */
  public Float getFloat(String name) {
    Number n = (Number) lookup(name);
    return n == null ? null : n.floatValue();
  }

  /** Look up a numeric claim and narrow to {@code double} via {@link Number#doubleValue()}; returns {@code null} if absent. */
  public Double getDouble(String name) {
    Number n = (Number) lookup(name);
    return n == null ? null : n.doubleValue();
  }

  /** Look up a boolean claim. Returns {@code null} if absent; throws if the claim is not a JSON boolean. */
  public Boolean getBoolean(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof Boolean b) {
      return b;
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a Boolean");
  }

  /**
   * Look up a numeric claim as a {@link BigDecimal}. Accepts values already
   * of type {@code BigDecimal}, {@code BigInteger}, or any {@link Number}
   * (narrowed via {@code doubleValue()}). Returns {@code null} if absent.
   */
  public BigDecimal getBigDecimal(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof BigDecimal bd) {
      return bd;
    }
    if (value instanceof BigInteger bi) {
      return new BigDecimal(bi);
    }
    if (value instanceof Number n) {
      return BigDecimal.valueOf(n.doubleValue());
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a numeric value");
  }

  /**
   * Look up a numeric claim as a {@link BigInteger}. Accepts values already
   * of type {@code BigInteger}, {@code BigDecimal} (truncated), or any
   * {@link Number} (narrowed via {@code longValue()}). Returns {@code null}
   * if absent.
   */
  public BigInteger getBigInteger(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof BigInteger bi) {
      return bi;
    }
    if (value instanceof BigDecimal bd) {
      return bd.toBigInteger();
    }
    if (value instanceof Number n) {
      return BigInteger.valueOf(n.longValue());
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a numeric value");
  }

  /** Look up a numeric claim as a raw {@link Number}. Returns {@code null} if absent; throws if the claim is not a JSON number. */
  public Number getNumber(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof Number n) {
      return n;
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a Number");
  }

  /** Look up a claim as its raw Java value (no type check). Returns {@code null} if absent. */
  public Object getObject(String name) {
    return lookup(name);
  }

  /** Look up a claim as a {@link Map}. Returns {@code null} if absent; throws if the claim is not a JSON object. */
  @SuppressWarnings("unchecked")
  public Map<String, Object> getMap(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof Map) {
      return (Map<String, Object>) value;
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a Map");
  }

  /** Look up a claim as a raw {@link List}. Returns {@code null} if absent; throws if the claim is not a JSON array. */
  @SuppressWarnings("unchecked")
  public List<Object> getList(String name) {
    Object value = lookup(name);
    if (value == null) {
      return null;
    }
    if (value instanceof List) {
      return (List<Object>) value;
    }
    throw new InvalidJWTException("Claim [" + name + "] is not a List");
  }

  /**
   * Look up a claim as a list of a specific element type. Returns {@code null}
   * if absent; throws {@link ClassCastException} on the first element that is
   * not an instance of {@code elementType}. Null elements are permitted.
   */
  public <T> List<T> getList(String name, Class<T> elementType) {
    List<Object> raw = getList(name);
    if (raw == null) {
      return null;
    }
    List<T> result = new ArrayList<>(raw.size());
    for (Object element : raw) {
      if (element != null && !elementType.isInstance(element)) {
        throw new ClassCastException("Claim [" + name + "] element is not of type [" + elementType.getName() + "]");
      }
      result.add(elementType.cast(element));
    }
    return result;
  }

  // ---------- Maps ----------

  /**
   * Returns all claims (registered + custom) as Java-typed values — timestamps are returned as
   * {@link Instant}, not as epoch-seconds. Suitable for callers reading claim state; for JSON
   * serialization use {@link #toSerializableMap()} which emits timestamps as NumericDate.
   */
  public Map<String, Object> claims() {
    Map<String, Object> merged = new LinkedHashMap<>();
    if (issuer != null) merged.put("iss", issuer);
    if (subject != null) merged.put("sub", subject);
    if (!audience.isEmpty()) merged.put("aud", audience);
    if (expiresAt != null) merged.put("exp", expiresAt);
    if (notBefore != null) merged.put("nbf", notBefore);
    if (issuedAt != null) merged.put("iat", issuedAt);
    if (id != null) merged.put("jti", id);
    for (Map.Entry<String, Object> e : customClaims.entrySet()) {
      if (e.getValue() != null) {
        merged.put(e.getKey(), e.getValue());
      }
    }
    return Collections.unmodifiableMap(merged);
  }

  /**
   * Returns a JSON-serializable view of the claims. Timestamps ({@code exp}, {@code nbf},
   * {@code iat}) are emitted as NumericDate (epoch seconds) per RFC 7519 §2, and {@code aud} is
   * emitted as either a single string or an array to match the recorded
   * {@link AudienceSerialization} mode.
   *
   * @apiNote The returned map is mutable and not shared with the {@code JWT}
   *     instance. Callers MUST NOT retain or mutate it -- the contract is that
   *     each call returns a fresh map intended for immediate handoff to a JSON
   *     serializer. The {@code aud} value, when present as an array, references
   *     the JWT's internal unmodifiable list directly; the JSON serializer only
   *     iterates it.
   */
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    if (issuer != null) out.put("iss", issuer);
    if (subject != null) out.put("sub", subject);
    if (!audience.isEmpty()) {
      if (audienceSerialization == AudienceSerialization.STRING_WHEN_SINGLE && audience.size() == 1) {
        out.put("aud", audience.get(0));
      } else {
        out.put("aud", audience);
      }
    }
    if (expiresAt != null) out.put("exp", expiresAt.getEpochSecond());
    if (notBefore != null) out.put("nbf", notBefore.getEpochSecond());
    if (issuedAt != null) out.put("iat", issuedAt.getEpochSecond());
    if (id != null) out.put("jti", id);
    for (Map.Entry<String, Object> e : customClaims.entrySet()) {
      if (e.getValue() != null) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  // ---------- Convenience ----------
  public boolean isExpired() {
    return isExpired(Instant.now(Clock.systemUTC()));
  }

  public boolean isExpired(Instant now) {
    // RFC 7519 §4.1.4: "the expiration time on or after which the JWT MUST
    // NOT be accepted". The boundary (now == exp) is expired.
    return expiresAt != null && !expiresAt.isAfter(now);
  }

  public boolean isUnavailableForProcessing() {
    return isUnavailableForProcessing(Instant.now(Clock.systemUTC()));
  }

  public boolean isUnavailableForProcessing(Instant now) {
    return notBefore != null && notBefore.isAfter(now);
  }

  // ---------- Factory ----------

  /**
   * Build a {@link JWT} from a parsed JSON object map and an already-parsed
   * {@link Header}. Registered claims ({@code iss}, {@code sub}, {@code aud},
   * {@code exp}, {@code nbf}, {@code iat}, {@code jti}) are validated for
   * type; all other entries are stored as custom claims.
   *
   * <p><strong>Aliasing note.</strong> Custom-claim values that are
   * {@code List} or {@code Map} instances are stored by reference rather
   * than deep-copied. Callers that retain a mutable alias to such a value
   * can observe their later mutations through {@link #getObject(String)},
   * {@link #getMap(String)}, or {@link #getList(String)} on the returned
   * {@link JWT}. To preserve full immutability, callers must not mutate
   * the input map's collection values after this method returns. The same
   * caveat applies to {@code Builder.claim}.</p>
   */
  public static JWT fromMap(Map<String, Object> map, Header header) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();
    b.header = header;

    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) {
        continue;
      }
      switch (name) {
        case "iss":
          b.issuer = expectString(name, value);
          break;
        case "sub":
          b.subject = expectString(name, value);
          break;
        case "jti":
          b.id = expectString(name, value);
          break;
        case "exp":
          b.expiresAt = expectInstant(name, value);
          break;
        case "nbf":
          b.notBefore = expectInstant(name, value);
          break;
        case "iat":
          b.issuedAt = expectInstant(name, value);
          break;
        case "aud":
          if (value instanceof String s) {
            b.audience = List.of(s);
            b.audienceSerialization = AudienceSerialization.STRING_WHEN_SINGLE;
          } else if (value instanceof List<?> raw) {
            List<String> strs = new ArrayList<>(raw.size());
            for (Object element : raw) {
              if (!(element instanceof String str)) {
                throw new InvalidJWTException("Claim [aud] must be a string or an array of strings");
              }
              strs.add(str);
            }
            b.audience = strs;
            b.audienceSerialization = AudienceSerialization.ALWAYS_ARRAY;
          } else {
            throw new InvalidJWTException("Claim [aud] must be a string or an array of strings");
          }
          break;
        default:
          b.customClaimsForWrite().put(name, value);
          break;
      }
    }

    return b.build();
  }

  // ---------- equals / hashCode / claimsEquals / toString ----------
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof JWT other)) return false;
    return Objects.equals(issuer, other.issuer)
        && Objects.equals(subject, other.subject)
        && Objects.equals(audience, other.audience)
        && audienceSerialization == other.audienceSerialization
        && Objects.equals(expiresAt, other.expiresAt)
        && Objects.equals(notBefore, other.notBefore)
        && Objects.equals(issuedAt, other.issuedAt)
        && Objects.equals(id, other.id)
        && Objects.equals(customClaims, other.customClaims)
        && Objects.equals(header, other.header);
  }

  @Override
  public int hashCode() {
    return Objects.hash(issuer, subject, audience, audienceSerialization, expiresAt,
        notBefore, issuedAt, id, customClaims, header);
  }

  /**
   * Returns true if the claim fields of this JWT equal the claim fields of the
   * other JWT. The {@link Header} is intentionally not consulted, and the
   * {@link AudienceSerialization} mode is intentionally ignored - audience is
   * compared by list contents.
   */
  public boolean claimsEquals(JWT other) {
    if (this == other) return true;
    if (other == null) return false;
    return Objects.equals(issuer, other.issuer)
        && Objects.equals(subject, other.subject)
        && Objects.equals(audience, other.audience)
        && Objects.equals(expiresAt, other.expiresAt)
        && Objects.equals(notBefore, other.notBefore)
        && Objects.equals(issuedAt, other.issuedAt)
        && Objects.equals(id, other.id)
        && Objects.equals(customClaims, other.customClaims);
  }

  @Override
  public String toString() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  // ---------- Builder ----------
  public static Builder builder() {
    return new Builder();
  }

  private Object lookup(String name) {
    if (name == null) {
      return null;
    }
    switch (name) {
      case "iss":
        return issuer;
      case "sub":
        return subject;
      case "aud":
        return audience.isEmpty() ? null : audience;
      case "exp":
        return expiresAt;
      case "nbf":
        return notBefore;
      case "iat":
        return issuedAt;
      case "jti":
        return id;
      default:
        return customClaims.get(name);
    }
  }

  private static String expectString(String name, Object value) {
    if (!(value instanceof String s)) {
      throw new InvalidJWTException("Claim [" + name + "] must be a String");
    }
    return s;
  }

  private static Instant expectInstant(String name, Object value) {
    if (!(value instanceof Number n)) {
      throw new InvalidJWTException("Claim [" + name + "] must be a numeric value (NumericDate)");
    }
    // Long fast-path: skips BigInteger materialization for values that already
    // fit in a long (LatteJSONProcessor's parseNumber returns Long for digit
    // runs <= 18, which covers every realistic NumericDate including epoch
    // seconds well past year 2100). Long.MIN/MAX_VALUE are still wider than
    // Instant.MIN/MAX, so the range check is required.
    if (n instanceof Long l) {
      long secs = l;
      if (secs > MAX_INSTANT_SECOND_LONG || secs < MIN_INSTANT_SECOND_LONG) {
        throw new InvalidJWTException("Claim [" + name + "] numeric value is outside the supported Instant range");
      }
      return Instant.ofEpochSecond(secs);
    }
    BigInteger asInt;
    if (n instanceof BigInteger bi) {
      asInt = bi;
    } else if (n instanceof BigDecimal bd) {
      asInt = bd.toBigInteger();
    } else {
      asInt = BigInteger.valueOf(n.longValue());
    }
    if (asInt.compareTo(MAX_INSTANT_SECOND) > 0 || asInt.compareTo(MIN_INSTANT_SECOND) < 0) {
      throw new InvalidJWTException("Claim [" + name + "] numeric value is outside the supported Instant range");
    }
    try {
      return Instant.ofEpochSecond(asInt.longValueExact());
    } catch (ArithmeticException e) {
      throw new InvalidJWTException("Claim [" + name + "] numeric value cannot be represented as a long", e);
    }
  }

  /**
   * Mutable, reusable builder for {@link JWT}. After {@link #build()} is
   * called, the builder retains its state and may be further modified to
   * produce additional independent {@link JWT} instances; each
   * {@code build()} call produces a fresh immutable instance with an
   * independent copy of any collection fields.
   */
  public static final class Builder {
    private String issuer;

    private String subject;

    private List<String> audience;

    private AudienceSerialization audienceSerialization;

    private Instant expiresAt;

    private Instant notBefore;

    private Instant issuedAt;

    private String id;

    private Map<String, Object> customClaims;

    private Header header;

    private Builder() {}

    private Map<String, Object> customClaimsForWrite() {
      if (customClaims == null) {
        customClaims = new LinkedHashMap<>();
      }
      return customClaims;
    }

    /**
     * Registered Claim {@code iss} as defined by RFC 7519 §4.1.1. Use of this claim is OPTIONAL.
     * <p>
     * The issuer claim identifies the principal that issued the JWT. If the value contains a
     * {@code :} it must be a URI.
     */
    public Builder issuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    /**
     * Registered Claim {@code sub} as defined by RFC 7519 §4.1.2. Use of this claim is OPTIONAL.
     * <p>
     * The subject claim identifies the principal that is the subject of the JWT. If the value
     * contains a {@code :} it must be a URI.
     */
    public Builder subject(String subject) {
      this.subject = subject;
      return this;
    }

    /**
     * Registered Claim {@code aud} as defined by RFC 7519 §4.1.3. Use of this claim is OPTIONAL.
     * <p>
     * The audience claim identifies the recipients that the JWT is intended for. On the wire this
     * may be an array of strings or a single string; any string values containing a {@code :} must
     * be URIs.
     * <p>
     * This overload sets a single-element audience. Serialization defaults to
     * {@link AudienceSerialization#ALWAYS_ARRAY}; call
     * {@link #audienceSerialization(AudienceSerialization)} to opt in to
     * {@link AudienceSerialization#STRING_WHEN_SINGLE}.
     */
    public Builder audience(String audience) {
      this.audience = audience == null ? null : List.of(audience);
      return this;
    }

    /**
     * Registered Claim {@code aud} as defined by RFC 7519 §4.1.3. Use of this claim is OPTIONAL.
     * <p>
     * The audience claim identifies the recipients that the JWT is intended for. On the wire this
     * may be an array of strings or a single string; any string values containing a {@code :} must
     * be URIs.
     * <p>
     * This overload sets the audience from a list. Serialization defaults to
     * {@link AudienceSerialization#ALWAYS_ARRAY}.
     */
    public Builder audience(List<String> audiences) {
      if (audiences == null) {
        this.audience = null;
      } else {
        this.audience = new ArrayList<>(audiences);
      }
      return this;
    }

    /**
     * Override the serialization form of the {@code aud} claim. Passing
     * {@code null} restores the builder default
     * ({@link AudienceSerialization#ALWAYS_ARRAY}). Has no effect when the
     * audience is absent.
     */
    public Builder audienceSerialization(AudienceSerialization mode) {
      this.audienceSerialization = mode;
      return this;
    }

    /**
     * Registered Claim {@code exp} as defined by RFC 7519 §4.1.4. Use of this claim is OPTIONAL.
     * <p>
     * The expiration time claim identifies the expiration time on or after which the JWT MUST NOT
     * be accepted for processing. Serialized as NumericDate (seconds since Epoch).
     */
    public Builder expiresAt(Instant expiration) {
      this.expiresAt = expiration;
      return this;
    }

    /**
     * Registered Claim {@code exp} as defined by RFC 7519 §4.1.4. Use of this claim is OPTIONAL.
     * <p>
     * The expiration time claim identifies the expiration time on or after which the JWT MUST NOT
     * be accepted for processing. Serialized as NumericDate (seconds since Epoch).
     */
    public Builder expiresAt(long epochSeconds) {
      this.expiresAt = Instant.ofEpochSecond(epochSeconds);
      return this;
    }

    /**
     * Registered Claim {@code nbf} as defined by RFC 7519 §4.1.5. Use of this claim is OPTIONAL.
     * <p>
     * This claim identifies the time before which the JWT MUST NOT be accepted for processing.
     * Serialized as NumericDate (seconds since Epoch).
     */
    public Builder notBefore(Instant notBefore) {
      this.notBefore = notBefore;
      return this;
    }

    /**
     * Registered Claim {@code nbf} as defined by RFC 7519 §4.1.5. Use of this claim is OPTIONAL.
     * <p>
     * This claim identifies the time before which the JWT MUST NOT be accepted for processing.
     * Serialized as NumericDate (seconds since Epoch).
     */
    public Builder notBefore(long epochSeconds) {
      this.notBefore = Instant.ofEpochSecond(epochSeconds);
      return this;
    }

    /**
     * Registered Claim {@code iat} as defined by RFC 7519 §4.1.6. Use of this claim is OPTIONAL.
     * <p>
     * The issued at claim identifies the time at which the JWT was issued. Serialized as
     * NumericDate (seconds since Epoch).
     */
    public Builder issuedAt(Instant issuedAt) {
      this.issuedAt = issuedAt;
      return this;
    }

    /**
     * Registered Claim {@code iat} as defined by RFC 7519 §4.1.6. Use of this claim is OPTIONAL.
     * <p>
     * The issued at claim identifies the time at which the JWT was issued. Serialized as
     * NumericDate (seconds since Epoch).
     */
    public Builder issuedAt(long epochSeconds) {
      this.issuedAt = Instant.ofEpochSecond(epochSeconds);
      return this;
    }

    /**
     * Registered Claim {@code jti} as defined by RFC 7519 §4.1.7. Use of this claim is OPTIONAL.
     * <p>
     * The JWT ID claim provides a unique identifier for the JWT.
     */
    public Builder id(String jwtId) {
      this.id = jwtId;
      return this;
    }

    /**
     * Add a claim. If the name matches a registered claim (iss, sub, aud, exp,
     * nbf, iat, jti), the value is routed to the corresponding typed setter
     * with type coercion. A value that cannot be coerced throws
     * {@link IllegalArgumentException}. Unrecognized names are stored in
     * {@code customClaims}.
     */
    public Builder claim(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (value == null) {
        return this;
      }
      switch (name) {
        case "iss":
          if (!(value instanceof String s)) {
            throw new IllegalArgumentException("Claim [iss] must be a String");
          }
          this.issuer = s;
          return this;
        case "sub":
          if (!(value instanceof String s)) {
            throw new IllegalArgumentException("Claim [sub] must be a String");
          }
          this.subject = s;
          return this;
        case "jti":
          if (!(value instanceof String s)) {
            throw new IllegalArgumentException("Claim [jti] must be a String");
          }
          this.id = s;
          return this;
        case "exp":
          this.expiresAt = coerceToInstant("exp", value);
          return this;
        case "nbf":
          this.notBefore = coerceToInstant("nbf", value);
          return this;
        case "iat":
          this.issuedAt = coerceToInstant("iat", value);
          return this;
        case "aud":
          if (value instanceof String s) {
            return audience(s);
          }
          if (value instanceof List<?> raw) {
            List<String> strs = new ArrayList<>(raw.size());
            for (Object element : raw) {
              if (!(element instanceof String es)) {
                throw new IllegalArgumentException("Claim [aud] list elements must be Strings");
              }
              strs.add(es);
            }
            return audience(strs);
          }
          throw new IllegalArgumentException("Claim [aud] must be a String or List<String>");
        default:
          if (REGISTERED_CLAIM_NAMES.contains(name)) {
            // defensive (should not happen given the switch above)
            throw new IllegalArgumentException("Registered claim [" + name + "] not handled by Builder.claim()");
          }
          customClaimsForWrite().put(name, value);
          return this;
      }
    }

    public JWT build() {
      return new JWT(this);
    }

    private static Instant coerceToInstant(String name, Object value) {
      if (value instanceof Instant instant) {
        return instant;
      }
      if (value instanceof ZonedDateTime zdt) {
        return zdt.toInstant();
      }
      if (value instanceof Number n) {
        return Instant.ofEpochSecond(n.longValue());
      }
      throw new IllegalArgumentException("Claim [" + name + "] cannot be coerced to Instant from value of type [" + value.getClass().getName() + "]");
    }
  }
}
