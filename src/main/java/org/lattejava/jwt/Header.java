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
 * @author The Latte Project
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
    this.customParameters = Collections.unmodifiableMap(new LinkedHashMap<>(b.customParameters));
  }

  // ---------- Fluent getters ----------
  public Algorithm alg() {
    return alg;
  }

  public String typ() {
    return typ;
  }

  public String kid() {
    return kid;
  }

  // ---------- Custom-parameter access ----------
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

  public String getString(String name) {
    Object value = get(name);
    return value == null ? null : value.toString();
  }

  // ---------- Maps ----------
  public Map<String, Object> parameters() {
    Map<String, Object> merged = new LinkedHashMap<>();
    if (alg != null) merged.put("alg", alg);
    if (typ != null) merged.put("typ", typ);
    if (kid != null) merged.put("kid", kid);
    merged.putAll(customParameters);
    return Collections.unmodifiableMap(merged);
  }

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
    return Collections.unmodifiableMap(out);
  }

  // ---------- Factory ----------
  public static Header fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();

    Object algRaw = map.get("alg");
    if (algRaw == null) {
      throw new InvalidJWTException("Header is missing the required [alg] parameter");
    }
    if (!(algRaw instanceof String)) {
      throw new InvalidJWTException("Header parameter [alg] must be a String");
    }
    b.alg = Algorithm.of((String) algRaw);

    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null || "alg".equals(name)) {
        continue;
      }
      switch (name) {
        case "typ":
          if (!(value instanceof String)) {
            throw new InvalidJWTException("Header parameter [typ] must be a String");
          }
          b.typ = (String) value;
          break;
        case "kid":
          if (!(value instanceof String)) {
            throw new InvalidJWTException("Header parameter [kid] must be a String");
          }
          b.kid = (String) value;
          break;
        case "cty":
        case "x5t":
        case "x5t#S256":
        case "x5u":
          if (!(value instanceof String)) {
            throw new InvalidJWTException("Header parameter [" + name + "] must be a String");
          }
          b.customParameters.put(name, value);
          break;
        case "x5c":
          if (!(value instanceof List)) {
            throw new InvalidJWTException("Header parameter [x5c] must be an array of strings");
          }
          for (Object element : (List<?>) value) {
            if (!(element instanceof String)) {
              throw new InvalidJWTException("Header parameter [x5c] must be an array of strings");
            }
          }
          b.customParameters.put(name, value);
          break;
        case "crit":
          validateCrit(value);
          b.customParameters.put(name, value);
          break;
        default:
          b.customParameters.put(name, value);
          break;
      }
    }

    return b.build();
  }

  /**
   * Structural validation of the {@code crit} header parameter per spec §3
   * "Critical Header Parameter — Structural validation". The
   * understood-parameters check is performed by {@code JWTDecoder}, not here.
   */
  private static void validateCrit(Object value) {
    if (!(value instanceof List)) {
      throw new InvalidJWTException("Header parameter [crit] must be a JSON array of strings");
    }
    List<?> raw = (List<?>) value;
    Set<String> seen = new LinkedHashSet<>();
    for (Object element : raw) {
      if (!(element instanceof String)) {
        throw new InvalidJWTException("Header parameter [crit] elements must be strings");
      }
      String s = (String) element;
      if (s.isEmpty()) {
        throw new InvalidJWTException("Header parameter [crit] elements must be non-empty strings");
      }
      if (!seen.add(s)) {
        throw new InvalidJWTException("Header parameter [crit] contains duplicate entry [" + s + "]");
      }
      if (REGISTERED_PARAMETER_NAMES.contains(s)) {
        throw new InvalidJWTException("Header parameter [crit] must not list the registered RFC 7515 parameter [" + s + "]");
      }
    }
  }

  // ---------- equals / hashCode / toString ----------
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Header)) return false;
    Header other = (Header) o;
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

    private final Map<String, Object> customParameters = new LinkedHashMap<>();

    private Builder() {}

    public Builder alg(Algorithm algorithm) {
      this.alg = algorithm;
      return this;
    }

    public Builder typ(String type) {
      this.typ = type;
      return this;
    }

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
        if (!(value instanceof Algorithm)) {
          throw new IllegalArgumentException("Header parameter [alg] must be an Algorithm instance");
        }
        this.alg = (Algorithm) value;
        return this;
      }
      if ("typ".equals(name)) {
        if (value == null) {
          this.typ = null;
          return this;
        }
        if (!(value instanceof String)) {
          throw new IllegalArgumentException("Header parameter [typ] must be a String");
        }
        this.typ = (String) value;
        return this;
      }
      if ("kid".equals(name)) {
        if (value == null) {
          this.kid = null;
          return this;
        }
        if (!(value instanceof String)) {
          throw new IllegalArgumentException("Header parameter [kid] must be a String");
        }
        this.kid = (String) value;
        return this;
      }
      if (value == null) {
        this.customParameters.remove(name);
      } else {
        this.customParameters.put(name, value);
      }
      return this;
    }

    public Header build() {
      return new Header(this);
    }
  }
}
