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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * JOSE Header (RFC 7515 §4) for a signed JWT (JWS). Immutable; create via
 * {@link #builder()} or {@link #fromMap(Map)}.
 *
 * @author Daniel DeGroff
 */
public final class Header {
  /** RFC 7515 registered header parameter names. */
  static final Set<String> REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
      "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"
  )));

  private final Algorithm alg;

  private final String typ;

  private final String kid;

  private final Map<String, Object> customParameters;

  private Header(Builder b) {
    this.alg = b.alg;
    this.typ = b.typ;
    this.kid = b.kid;
    this.customParameters = b.customParameters == null || b.customParameters.isEmpty()
        ? Collections.emptyMap()
        : Collections.unmodifiableMap(new LinkedHashMap<>(b.customParameters));
  }

  // ---------- Fluent getters ----------

  /** The signing algorithm declared in the {@code alg} header (RFC 7515 §4.1.1). Never null for a parsed header. */
  public Algorithm alg() {
    return alg;
  }

  /** The media type of the token declared in {@code typ} (RFC 7515 §4.1.9). Defaults to {@code "JWT"} on the builder side; may be null on a parsed header. */
  public String typ() {
    return typ;
  }

  /** The key identifier declared in {@code kid} (RFC 7515 §4.1.4), or null when unset. */
  public String kid() {
    return kid;
  }

  // ---------- Custom-parameter access ----------

  /**
   * Look up a header parameter by name. Standard parameters ({@code alg},
   * {@code typ}, {@code kid}) return the typed field; any other name reads
   * from the custom-parameters map.
   *
   * @param name the parameter name; {@code null} returns {@code null}
   * @return the parameter value, or {@code null} if absent
   */
  public Object get(String name) {
    if (name == null) {
      return null;
    }
    switch (name) {
      case "alg":
        return alg;
      case "typ":
        return typ;
      case "kid":
        return kid;
      default:
        return customParameters.get(name);
    }
  }

  /**
   * Convenience accessor that returns {@link #get(String)} coerced via
   * {@link Object#toString()}; returns {@code null} when the parameter is absent.
   */
  public String getString(String name) {
    Object value = get(name);
    return value == null ? null : value.toString();
  }

  // ---------- Maps ----------

  /**
   * Return all header parameters as an unmodifiable map. Standard parameters
   * appear with their typed values (e.g. {@code alg} is an {@link Algorithm});
   * use {@link #toSerializableMap()} if you need JSON-ready values.
   */
  public Map<String, Object> parameters() {
    Map<String, Object> merged = new LinkedHashMap<>();
    if (alg != null) merged.put("alg", alg);
    if (typ != null) merged.put("typ", typ);
    if (kid != null) merged.put("kid", kid);
    merged.putAll(customParameters);
    return Collections.unmodifiableMap(merged);
  }

  /**
   * Return a freshly allocated map suitable for JSON serialization. {@code alg} is
   * serialized by {@link Algorithm#name()}; {@code null}-valued custom
   * parameters are omitted.
   *
   * @apiNote The returned map is mutable and not shared with the {@code Header}
   *     instance. Callers MUST NOT retain or mutate it -- the contract is that
   *     each call returns a fresh map intended for immediate handoff to a JSON
   *     serializer.
   */
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    if (alg != null) out.put("alg", alg.name());
    if (typ != null) out.put("typ", typ);
    if (kid != null) out.put("kid", kid);
    for (Map.Entry<String, Object> e : customParameters.entrySet()) {
      if (e.getValue() != null) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  // ---------- Factory ----------

  /**
   * Build a {@link Header} from a parsed JSON object map. Enforces the RFC
   * 7515 structural rules on registered parameters: {@code alg} is required
   * and must be a string; {@code typ}, {@code kid}, {@code cty}, {@code x5t},
   * {@code x5t#S256}, and {@code x5u} must be strings; {@code x5c} must be
   * an array of strings; {@code crit} must be a non-empty array of distinct
   * strings that do not name any RFC 7515 registered parameter.
   *
   * <p><strong>Aliasing note.</strong> Collection values supplied via the
   * input map (notably {@code x5c}, {@code crit}, and any custom-parameter
   * {@code List} or {@code Map}) are stored by reference rather than
   * deep-copied. Callers that retain a mutable alias to such a value can
   * observe their later mutations through {@link #get(String)} on the
   * returned {@link Header}. To preserve full immutability, callers must
   * not mutate the input map's collection values after this method
   * returns. The same caveat applies to {@code Builder.parameter}.</p>
   *
   * @throws InvalidJWTException if a registered parameter has the wrong shape
   */
  public static Header fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();

    Object algRaw = map.get("alg");
    if (algRaw == null) {
      throw new InvalidJWTException("Header [alg] is missing");
    }
    if (!(algRaw instanceof String algName)) {
      throw new InvalidJWTException("Header [alg] must be a String");
    }
    b.alg = Algorithm.of(algName);

    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null || "alg".equals(name)) {
        continue;
      }
      switch (name) {
        case "typ":
          if (!(value instanceof String typ)) {
            throw new InvalidJWTException("Header [typ] must be a String");
          }
          b.typ = typ;
          break;
        case "kid":
          if (!(value instanceof String kid)) {
            throw new InvalidJWTException("Header [kid] must be a String");
          }
          b.kid = kid;
          break;
        case "cty":
        case "x5t":
        case "x5t#S256":
        case "x5u":
          if (!(value instanceof String)) {
            throw new InvalidJWTException("Header [" + name + "] must be a String");
          }
          b.customParametersForWrite().put(name, value);
          break;
        case "x5c":
          if (!(value instanceof List<?> x5c)) {
            throw new InvalidJWTException("Header [x5c] must be an array of strings");
          }
          for (Object element : x5c) {
            if (!(element instanceof String)) {
              throw new InvalidJWTException("Header [x5c] must be an array of strings");
            }
          }
          b.customParametersForWrite().put(name, value);
          break;
        case "crit":
          validateCrit(value);
          b.customParametersForWrite().put(name, value);
          break;
        default:
          b.customParametersForWrite().put(name, value);
          break;
      }
    }

    return b.build();
  }

  /**
   * Structural validation of the {@code crit} header parameter. The
   * understood-parameters check is performed by {@code JWTDecoder}, not here.
   */
  private static void validateCrit(Object value) {
    if (!(value instanceof List<?> raw)) {
      throw new InvalidJWTException("Header [crit] must be a JSON array of strings");
    }
    Set<String> seen = new LinkedHashSet<>();
    for (Object element : raw) {
      if (!(element instanceof String s)) {
        throw new InvalidJWTException("Header [crit] elements must be strings");
      }
      if (s.isEmpty()) {
        throw new InvalidJWTException("Header [crit] elements must be non-empty strings");
      }
      if (!seen.add(s)) {
        throw new InvalidJWTException("Header [crit] contains duplicate entry [" + s + "]");
      }
      if (REGISTERED_PARAMETER_NAMES.contains(s)) {
        throw new InvalidJWTException("Header [crit] must not list the registered RFC 7515 parameter [" + s + "]");
      }
    }
  }

  // ---------- equals / hashCode / toString ----------
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Header other)) return false;
    return Objects.equals(alg, other.alg)
        && Objects.equals(typ, other.typ)
        && Objects.equals(kid, other.kid)
        && Objects.equals(customParameters, other.customParameters);
  }

  @Override
  public int hashCode() {
    return Objects.hash(alg, typ, kid, customParameters);
  }

  @Override
  public String toString() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  /** Returns a new, empty {@link Builder}. */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Mutable, reusable builder for {@link Header}. After {@link #build()} is
   * called, the builder retains its state and may be further modified to
   * produce additional independent {@link Header} instances; each
   * {@code build()} call produces a fresh immutable instance with an
   * independent copy of any collection fields.
   */
  public static final class Builder {
    private Algorithm alg;

    private String typ = "JWT";

    private String kid;

    private Map<String, Object> customParameters;

    private Builder() {}

    private Map<String, Object> customParametersForWrite() {
      if (customParameters == null) {
        customParameters = new LinkedHashMap<>();
      }
      return customParameters;
    }

    /**
     * The signing algorithm declared in the {@code alg} header (RFC 7515 §4.1.1). Never null for
     * a parsed header; required before {@link #build()} for signed JWTs.
     */
    public Builder alg(Algorithm algorithm) {
      this.alg = algorithm;
      return this;
    }

    /**
     * The media type of the token declared in {@code typ} (RFC 7515 §4.1.9). Defaults to
     * {@code "JWT"} on the builder side; may be null on a parsed header. Passing {@code null}
     * clears it.
     */
    public Builder typ(String type) {
      this.typ = type;
      return this;
    }

    /**
     * The key identifier declared in {@code kid} (RFC 7515 §4.1.4), or null when unset. Passing
     * {@code null} clears it.
     */
    public Builder kid(String keyId) {
      this.kid = keyId;
      return this;
    }

    /**
     * Add a custom header parameter. If {@code name} is {@code "alg"},
     * {@code "typ"}, or {@code "kid"}, the call is routed to the corresponding
     * typed setter:
     *
     * <ul>
     *   <li>{@code "alg"}: value must be an {@link Algorithm} or
     *       {@link IllegalArgumentException} is thrown.</li>
     *   <li>{@code "typ"} / {@code "kid"}: value must be a {@link String} or
     *       {@link IllegalArgumentException} is thrown.</li>
     * </ul>
     *
     * Other names are stored in the custom-parameters map. Passing a
     * {@code null} value clears the parameter.
     */
    public Builder parameter(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if ("alg".equals(name)) {
        if (value == null) {
          this.alg = null;
          return this;
        }
        if (!(value instanceof Algorithm a)) {
          throw new IllegalArgumentException("Header [alg] must be an Algorithm instance");
        }
        this.alg = a;
        return this;
      }
      if ("typ".equals(name)) {
        if (value == null) {
          this.typ = null;
          return this;
        }
        if (!(value instanceof String s)) {
          throw new IllegalArgumentException("Header [typ] must be a String");
        }
        this.typ = s;
        return this;
      }
      if ("kid".equals(name)) {
        if (value == null) {
          this.kid = null;
          return this;
        }
        if (!(value instanceof String s)) {
          throw new IllegalArgumentException("Header [kid] must be a String");
        }
        this.kid = s;
        return this;
      }
      if (value == null) {
        // No need to lazy-init for a remove against a still-empty map.
        if (this.customParameters != null) {
          this.customParameters.remove(name);
        }
      } else {
        customParametersForWrite().put(name, value);
      }
      return this;
    }

    /** Produce an immutable {@link Header} from the builder's current state. */
    public Header build() {
      return new Header(this);
    }
  }
}
