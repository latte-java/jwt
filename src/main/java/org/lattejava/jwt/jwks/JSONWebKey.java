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

package org.lattejava.jwt.jwks;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.KeyType;
import org.lattejava.jwt.LatteJSONProcessor;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 §4</a>
 * and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518</a>.
 *
 * <p>Construct via {@link #builder()} for fluent immutable-style construction or
 * via {@link #fromMap(Map)} for JSON-driven construction. Public fields and
 * a no-arg constructor are retained for back-compat with the legacy 6.x test
 * surface and for Jackson-style serialization; new code should prefer the
 * builder.</p>
 *
 * <p>{@link #toString()} <strong>always</strong> redacts the private-key
 * material fields (d, dp, dq, p, q, qi) to {@code "***"}. Use
 * {@link #toJSON()} for the full content.</p>
 *
 * <p>See spec §8 for the design.</p>
 *
 * @author The Latte Project
 */
public class JSONWebKey {
  /** RFC 7517 / 7518 typed parameter names this class binds to its own fields. */
  static final Set<String> REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
      "alg", "crv", "kid", "kty", "use", "key_ops", "x5u",
      "d", "dp", "dq", "e", "n", "p", "q", "qi",
      "x", "y", "x5c", "x5t", "x5t#S256", "x5t_256"
  )));

  public Algorithm alg;

  public String crv;

  public String d;

  public String dp;

  public String dq;

  public String e;

  public String kid;

  public KeyType kty;

  public List<String> key_ops;

  public String n;

  @JsonAnySetter
  public Map<String, Object> other = new LinkedHashMap<>();

  public String p;

  public String q;

  public String qi;

  public String use;

  public String x;

  public List<String> x5c;

  public String x5t;

  @JsonProperty("x5t#S256")
  public String x5t_256;

  public String x5u;

  public String y;

  /**
   * Add a custom (non-registered) JWK parameter. Registered parameter names
   * (e.g. {@code "alg"}, {@code "x5t#S256"}) MUST be set via the typed fields;
   * calling this for a registered name throws {@link JSONWebKeyBuilderException}.
   *
   * @param name  the parameter name
   * @param value the value
   * @return this instance for chaining
   */
  public JSONWebKey add(String name, Object value) {
    Objects.requireNonNull(name, "name");
    if (REGISTERED_PARAMETER_NAMES.contains(name)) {
      throw new JSONWebKeyBuilderException("Cannot add a registered JWK parameter [" + name + "]; set it via the typed field.");
    }
    other.put(name, value);
    return this;
  }

  // ---------- Custom-parameter access ----------

  /**
   * @return the value of {@code name}; returns the typed field for registered
   * names or the value from the custom-parameters map.
   */
  public Object get(String name) {
    if (name == null) return null;
    switch (name) {
      case "alg": return alg;
      case "crv": return crv;
      case "kid": return kid;
      case "kty": return kty;
      case "use": return use;
      case "key_ops": return key_ops;
      case "x5u": return x5u;
      case "d": return d;
      case "dp": return dp;
      case "dq": return dq;
      case "e": return e;
      case "n": return n;
      case "p": return p;
      case "q": return q;
      case "qi": return qi;
      case "x": return x;
      case "y": return y;
      case "x5c": return x5c;
      case "x5t": return x5t;
      case "x5t#S256":
      case "x5t_256":
        return x5t_256;
      default: return other.get(name);
    }
  }

  /** Jackson {@code @JsonAnyGetter}: emit non-registered members as JSON top-level keys. */
  @JsonAnyGetter
  public Map<String, Object> getOther() {
    return other;
  }

  // ---------- Serialization ----------

  /**
   * Map suitable for JSON serialization. The Java field {@code x5t_256} is
   * emitted under the wire-form key {@code "x5t#S256"} per RFC 7517 §4.9.
   */
  @JsonIgnore
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    if (alg != null) out.put("alg", alg.name());
    if (crv != null) out.put("crv", crv);
    if (kid != null) out.put("kid", kid);
    if (kty != null) out.put("kty", kty.name());
    if (use != null) out.put("use", use);
    if (key_ops != null) out.put("key_ops", key_ops);
    if (x5u != null) out.put("x5u", x5u);
    if (d != null) out.put("d", d);
    if (dp != null) out.put("dp", dp);
    if (dq != null) out.put("dq", dq);
    if (e != null) out.put("e", e);
    if (n != null) out.put("n", n);
    if (p != null) out.put("p", p);
    if (q != null) out.put("q", q);
    if (qi != null) out.put("qi", qi);
    if (x != null) out.put("x", x);
    if (y != null) out.put("y", y);
    if (x5c != null) out.put("x5c", x5c);
    if (x5t != null) out.put("x5t", x5t);
    if (x5t_256 != null) out.put("x5t#S256", x5t_256);
    if (other != null) {
      for (Map.Entry<String, Object> entry : other.entrySet()) {
        if (entry.getValue() != null) {
          out.put(entry.getKey(), entry.getValue());
        }
      }
    }
    return Collections.unmodifiableMap(out);
  }

  /**
   * Build a {@link JSONWebKey} from a parsed JSON map. Reads {@code "x5t#S256"}
   * into the {@code x5t_256} field and {@code "key_ops"}/{@code "x5u"} into
   * their typed fields.
   */
  @SuppressWarnings("unchecked")
  public static JSONWebKey fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    JSONWebKey k = new JSONWebKey();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) continue;
      switch (name) {
        case "alg":
          k.alg = value instanceof Algorithm ? (Algorithm) value : Algorithm.of(value.toString());
          break;
        case "crv":  k.crv = value.toString(); break;
        case "kid":  k.kid = value.toString(); break;
        case "kty":
          k.kty = value instanceof KeyType ? (KeyType) value : KeyType.of(value.toString());
          break;
        case "use":  k.use = value.toString(); break;
        case "key_ops":
          if (!(value instanceof List)) {
            throw new IllegalArgumentException("JWK parameter [key_ops] must be an array of strings");
          }
          List<String> ops = new java.util.ArrayList<>();
          for (Object element : (List<Object>) value) {
            if (!(element instanceof String)) {
              throw new IllegalArgumentException("JWK parameter [key_ops] must be an array of strings");
            }
            ops.add((String) element);
          }
          k.key_ops = ops;
          break;
        case "x5u":  k.x5u = value.toString(); break;
        case "d":    k.d = value.toString(); break;
        case "dp":   k.dp = value.toString(); break;
        case "dq":   k.dq = value.toString(); break;
        case "e":    k.e = value.toString(); break;
        case "n":    k.n = value.toString(); break;
        case "p":    k.p = value.toString(); break;
        case "q":    k.q = value.toString(); break;
        case "qi":   k.qi = value.toString(); break;
        case "x":    k.x = value.toString(); break;
        case "y":    k.y = value.toString(); break;
        case "x5c":
          if (!(value instanceof List)) {
            throw new IllegalArgumentException("JWK parameter [x5c] must be an array of strings");
          }
          List<String> chain = new java.util.ArrayList<>();
          for (Object element : (List<Object>) value) {
            if (!(element instanceof String)) {
              throw new IllegalArgumentException("JWK parameter [x5c] must be an array of strings");
            }
            chain.add((String) element);
          }
          k.x5c = chain;
          break;
        case "x5t":  k.x5t = value.toString(); break;
        case "x5t#S256": k.x5t_256 = value.toString(); break;
        default:
          k.other.put(name, value);
          break;
      }
    }
    return k;
  }

  public String toJSON() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  /**
   * Returns a new {@code JSONWebKey} with all private key material removed
   * (d, dp, dq, p, q, qi). Safe to serve from a public JWKS endpoint.
   */
  public JSONWebKey toPublicJSONWebKey() {
    JSONWebKey copy = new JSONWebKey();
    copy.alg = alg;
    copy.crv = crv;
    copy.kid = kid;
    copy.kty = kty;
    copy.use = use;
    copy.key_ops = key_ops;
    copy.x5u = x5u;
    copy.e = e;
    copy.n = n;
    copy.x = x;
    copy.y = y;
    copy.x5c = x5c;
    copy.x5t = x5t;
    copy.x5t_256 = x5t_256;
    if (other != null) {
      copy.other.putAll(other);
    }
    return copy;
  }

  // ---------- Static convenience methods ----------

  public static JSONWebKey build(String encodedPEM) {
    return new JSONWebKeyBuilder().build(encodedPEM);
  }

  public static JSONWebKey build(Certificate certificate) {
    return new JSONWebKeyBuilder().build(certificate);
  }

  public static JSONWebKey build(PrivateKey privateKey) {
    return new JSONWebKeyBuilder().build(privateKey);
  }

  public static JSONWebKey build(PublicKey publicKey) {
    return new JSONWebKeyBuilder().build(publicKey);
  }

  public static PublicKey parse(JSONWebKey key) {
    return new JSONWebKeyParser().parse(key);
  }

  // ---------- toString / equals / hashCode ----------

  /**
   * Debug-friendly representation. Private key material fields (d, dp, dq, p,
   * q, qi) are <strong>always</strong> replaced with {@code "***"} regardless
   * of whether they are populated. Use {@link #toJSON()} for the full content.
   */
  @Override
  public String toString() {
    Map<String, Object> redacted = new LinkedHashMap<>(toSerializableMap());
    redacted.put("d", "***");
    redacted.put("dp", "***");
    redacted.put("dq", "***");
    redacted.put("p", "***");
    redacted.put("q", "***");
    redacted.put("qi", "***");
    return new String(new LatteJSONProcessor().serialize(redacted));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof JSONWebKey)) return false;
    JSONWebKey that = (JSONWebKey) o;
    return Objects.equals(algName(alg), algName(that.alg))
        && Objects.equals(crv, that.crv)
        && Objects.equals(d, that.d)
        && Objects.equals(dp, that.dp)
        && Objects.equals(dq, that.dq)
        && Objects.equals(e, that.e)
        && Objects.equals(kid, that.kid)
        && Objects.equals(ktyName(kty), ktyName(that.kty))
        && Objects.equals(n, that.n)
        && Objects.equals(p, that.p)
        && Objects.equals(q, that.q)
        && Objects.equals(qi, that.qi)
        && Objects.equals(use, that.use)
        && Objects.equals(key_ops, that.key_ops)
        && Objects.equals(x5u, that.x5u)
        && Objects.equals(x, that.x)
        && Objects.equals(x5c, that.x5c)
        && Objects.equals(x5t, that.x5t)
        && Objects.equals(x5t_256, that.x5t_256)
        && Objects.equals(y, that.y)
        && Objects.equals(other, that.other);
  }

  private static String algName(Algorithm a) { return a == null ? null : a.name(); }
  private static String ktyName(KeyType k) { return k == null ? null : k.name(); }

  @Override
  public int hashCode() {
    return Objects.hash(algName(alg), crv, d, dp, dq, e, kid, ktyName(kty), n, p, q, qi,
        use, key_ops, x5u, x, x5c, x5t, x5t_256, y, other);
  }

  // ---------- Builder ----------

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Fluent builder for {@link JSONWebKey}. Calling {@link #build()} returns a
   * new instance; the builder may be reused.
   */
  public static final class Builder {
    private final JSONWebKey k = new JSONWebKey();

    public Builder alg(Algorithm v)          { k.alg = v; return this; }
    public Builder crv(String v)             { k.crv = v; return this; }
    public Builder kid(String v)             { k.kid = v; return this; }
    public Builder kty(KeyType v)            { k.kty = v; return this; }
    public Builder use(String v)             { k.use = v; return this; }
    public Builder keyOps(List<String> v)    { k.key_ops = v; return this; }
    public Builder x5u(String v)             { k.x5u = v; return this; }
    public Builder d(String v)               { k.d = v; return this; }
    public Builder dp(String v)              { k.dp = v; return this; }
    public Builder dq(String v)              { k.dq = v; return this; }
    public Builder e(String v)               { k.e = v; return this; }
    public Builder n(String v)               { k.n = v; return this; }
    public Builder p(String v)               { k.p = v; return this; }
    public Builder q(String v)               { k.q = v; return this; }
    public Builder qi(String v)              { k.qi = v; return this; }
    public Builder x(String v)               { k.x = v; return this; }
    public Builder y(String v)               { k.y = v; return this; }
    public Builder x5c(List<String> v)       { k.x5c = v; return this; }
    public Builder x5t(String v)             { k.x5t = v; return this; }
    public Builder x5t_256(String v)         { k.x5t_256 = v; return this; }

    /**
     * Add a custom (non-registered) JWK parameter. Registered parameters MUST
     * be set via the typed setters; calling this for a registered name throws
     * {@link JSONWebKeyBuilderException}.
     */
    public Builder parameter(String name, Object value) {
      k.add(name, value);
      return this;
    }

    public JSONWebKey build() {
      JSONWebKey out = new JSONWebKey();
      out.alg = k.alg;
      out.crv = k.crv;
      out.kid = k.kid;
      out.kty = k.kty;
      out.use = k.use;
      out.key_ops = k.key_ops;
      out.x5u = k.x5u;
      out.d = k.d;
      out.dp = k.dp;
      out.dq = k.dq;
      out.e = k.e;
      out.n = k.n;
      out.p = k.p;
      out.q = k.q;
      out.qi = k.qi;
      out.x = k.x;
      out.y = k.y;
      out.x5c = k.x5c;
      out.x5t = k.x5t;
      out.x5t_256 = k.x5t_256;
      out.other.putAll(k.other);
      return out;
    }
  }
}
