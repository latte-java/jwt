/*
 * Copyright (c) 2017-2026, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.jwks;

import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.internal.*;

/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 §4</a> and <a
 * href="https://tools.ietf.org/html/rfc7518">RFC 7518</a>.
 *
 * <p>Immutable value type. Construct via {@link #builder()} for fluent
 * construction or via {@link #fromMap(Map)} for JSON-driven construction. Read state through the typed accessors
 * ({@link #alg()}, {@link #kty()}, ...).
 *
 * <p>{@link #toString()} <strong>always</strong> redacts the private-key
 * material fields (d, dp, dq, p, q, qi) to {@code "***"}. Use {@link #toJSON()} for the full content.</p>
 *
 * @author Daniel DeGroff
 */
public final class JSONWebKey {
  /**
   * RFC 7517 / 7518 typed parameter names this class binds to its own fields.
   */
  static final Set<String> REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
      "alg", "crv", "kid", "kty", "use", "key_ops", "x5u",
      "d", "dp", "dq", "e", "n", "p", "q", "qi",
      "x", "y", "x5c", "x5t", "x5t#S256"
  )));

  private final Algorithm alg;

  private final String crv;

  private final String d;

  private final String dp;

  private final String dq;

  private final String e;
  private final List<String> key_ops;
  private final String kid;
  private final KeyType kty;
  private final String n;

  private final Map<String, Object> other;

  private final String p;

  private final String q;

  private final String qi;

  private final String use;

  private final String x;

  private final List<String> x5c;

  private final String x5t;

  private final String x5tS256;

  private final String x5u;

  private final String y;

  private JSONWebKey(Builder b) {
    this.alg = b.alg;
    this.crv = b.crv;
    this.d = b.d;
    this.dp = b.dp;
    this.dq = b.dq;
    this.e = b.e;
    this.kid = b.kid;
    this.kty = b.kty;
    this.key_ops = b.key_ops == null ? null : Collections.unmodifiableList(new java.util.ArrayList<>(b.key_ops));
    this.n = b.n;
    this.other = Collections.unmodifiableMap(new LinkedHashMap<>(b.other));
    this.p = b.p;
    this.q = b.q;
    this.qi = b.qi;
    this.use = b.use;
    this.x = b.x;
    this.x5c = b.x5c == null ? null : Collections.unmodifiableList(new java.util.ArrayList<>(b.x5c));
    this.x5t = b.x5t;
    this.x5tS256 = b.x5tS256;
    this.x5u = b.x5u;
    this.y = b.y;
  }

  // ---------- Typed accessors ----------

  public static Builder builder() {
    return new Builder();
  }

  public static JSONWebKey from(Certificate certificate) {
    return new JSONWebKeyConverter().build(certificate);
  }

  public static JSONWebKey from(PrivateKey privateKey) {
    return new JSONWebKeyConverter().build(privateKey);
  }

  public static JSONWebKey from(PublicKey publicKey) {
    return new JSONWebKeyConverter().build(publicKey);
  }

  public static JSONWebKey from(String encodedPEM) {
    return new JSONWebKeyConverter().build(encodedPEM);
  }

  /**
   * Build a {@link JSONWebKey} from a parsed JSON map. Reads {@code "x5t#S256"} into the {@code x5tS256} field and
   * {@code "key_ops"}/{@code "x5u"} into their typed fields.
   */
  @SuppressWarnings("unchecked")
  public static JSONWebKey fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) continue;
      switch (name) {
        case "alg":
          b.alg = value instanceof Algorithm a ? a : Algorithm.of(value.toString());
          break;
        case "crv":
          b.crv = value.toString();
          break;
        case "kid":
          b.kid = value.toString();
          break;
        case "kty":
          b.kty = value instanceof KeyType kt ? kt : KeyType.of(value.toString());
          break;
        case "use":
          b.use = value.toString();
          break;
        case "key_ops":
          if (!(value instanceof List<?> keyOpsList)) {
            throw new IllegalArgumentException("JWK [key_ops] must be an array of strings");
          }
          List<String> ops = new java.util.ArrayList<>();
          for (Object element : keyOpsList) {
            if (!(element instanceof String op)) {
              throw new IllegalArgumentException("JWK [key_ops] must be an array of strings");
            }
            ops.add(op);
          }
          b.key_ops = ops;
          break;
        case "x5u":
          b.x5u = value.toString();
          break;
        case "d":
          b.d = value.toString();
          break;
        case "dp":
          b.dp = value.toString();
          break;
        case "dq":
          b.dq = value.toString();
          break;
        case "e":
          b.e = value.toString();
          break;
        case "n":
          b.n = value.toString();
          break;
        case "p":
          b.p = value.toString();
          break;
        case "q":
          b.q = value.toString();
          break;
        case "qi":
          b.qi = value.toString();
          break;
        case "x":
          b.x = value.toString();
          break;
        case "y":
          b.y = value.toString();
          break;
        case "x5c":
          if (!(value instanceof List<?> x5cList)) {
            throw new IllegalArgumentException("JWK [x5c] must be an array of strings");
          }
          List<String> chain = new java.util.ArrayList<>();
          for (Object element : x5cList) {
            if (!(element instanceof String cert)) {
              throw new IllegalArgumentException("JWK [x5c] must be an array of strings");
            }
            chain.add(cert);
          }
          b.x5c = chain;
          break;
        case "x5t":
          b.x5t = value.toString();
          break;
        case "x5t#S256":
          b.x5tS256 = value.toString();
          break;
        default:
          b.other.put(name, value);
          break;
      }
    }
    return b.build();
  }

  public static PublicKey parse(JSONWebKey key) {
    return new JSONWebKeyParser().parse(key);
  }

  private static String algName(Algorithm a) {
    return a == null ? null : a.name();
  }

  private static String ktyName(KeyType k) {
    return k == null ? null : k.name();
  }

  /**
   * The {@code alg} parameter (RFC 7517 §4.4) identifies the algorithm intended for use with this key.
   */
  public Algorithm alg() {
    return alg;
  }

  /**
   * The Elliptic Curve name for EC and OKP keys. Common values:
   * <ul>
   *   <li>{@code P-256}, {@code P-384}, {@code P-521} — EC (RFC 7518 §6.2.1.1)</li>
   *   <li>{@code Ed25519}, {@code Ed448} — OKP (RFC 8037 §2)</li>
   * </ul>
   */
  public String crv() {
    return crv;
  }

  /**
   * The {@code d} parameter. For RSA (RFC 7518 §6.3.2.1) this is the private exponent. For EC (RFC 7518 §6.2.2.1) and
   * OKP (RFC 8037 §2) this is the private key value. Represented as a Base64urlUInt-encoded value for RSA/EC and a
   * base64url-encoded octet string for OKP.
   */
  public String d() {
    return d;
  }

  /**
   * The {@code dp} parameter (RFC 7518 §6.3.2.4): the first factor CRT (Chinese Remainder Theorem) exponent for the RSA
   * private key. Represented as a Base64urlUInt-encoded value.
   */
  public String dp() {
    return dp;
  }

  /**
   * The {@code dq} parameter (RFC 7518 §6.3.2.5): the second factor CRT (Chinese Remainder Theorem) exponent for the
   * RSA private key. Represented as a Base64urlUInt-encoded value.
   */
  public String dq() {
    return dq;
  }

  /**
   * The {@code e} parameter (RFC 7518 §6.3.1.2): the public exponent of the RSA public key. Represented as a
   * Base64urlUInt-encoded value.
   */
  public String e() {
    return e;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof JSONWebKey that)) return false;
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
        && Objects.equals(x5tS256, that.x5tS256)
        && Objects.equals(y, that.y)
        && Objects.equals(other, that.other);
  }

  /**
   * @return the value of {@code name}; returns the typed field for registered names or the value from the
   *     custom-parameters map.
   */
  public Object get(String name) {
    if (name == null) return null;
    switch (name) {
      case "alg":
        return alg;
      case "crv":
        return crv;
      case "kid":
        return kid;
      case "kty":
        return kty;
      case "use":
        return use;
      case "key_ops":
        return key_ops;
      case "x5u":
        return x5u;
      case "d":
        return d;
      case "dp":
        return dp;
      case "dq":
        return dq;
      case "e":
        return e;
      case "n":
        return n;
      case "p":
        return p;
      case "q":
        return q;
      case "qi":
        return qi;
      case "x":
        return x;
      case "y":
        return y;
      case "x5c":
        return x5c;
      case "x5t":
        return x5t;
      case "x5t#S256":
        return x5tS256;
      default:
        return other.get(name);
    }
  }

  @Override
  public int hashCode() {
    return Objects.hash(algName(alg), crv, d, dp, dq, e, kid, ktyName(kty), n, p, q, qi,
        use, key_ops, x5u, x, x5c, x5t, x5tS256, y, other);
  }

  /**
   * The {@code key_ops} parameter (RFC 7517 §4.3) identifying the operations this key is intended for. Values include
   * {@code sign}, {@code verify}, {@code encrypt}, {@code decrypt}, {@code wrapKey}, {@code unwrapKey},
   * {@code deriveKey}, {@code deriveBits}.
   */
  public List<String> key_ops() {
    return key_ops;
  }

  /**
   * The {@code kid} parameter (RFC 7517 §4.5): key identifier. Used to match a key to a JWS header's {@code kid}
   * parameter during signature verification.
   */
  public String kid() {
    return kid;
  }

  /**
   * The {@code kty} parameter (RFC 7517 §4.1) identifying the cryptographic family:
   * <ul>
   *   <li>{@code EC}  — Elliptic Curve (RFC 7518 §6.2)</li>
   *   <li>{@code RSA} — RSA (RFC 7518 §6.3)</li>
   *   <li>{@code OKP} — Octet Key Pair, used for Edwards curves (RFC 8037)</li>
   *   <li>{@code oct} — Octet sequence, used for symmetric keys (RFC 7518 §6.4)</li>
   * </ul>
   */
  public KeyType kty() {
    return kty;
  }

  // ---------- Thumbprints ----------

  /**
   * The {@code n} parameter (RFC 7518 §6.3.1.1): the modulus of the RSA public key. Represented as a
   * Base64urlUInt-encoded value.
   */
  public String n() {
    return n;
  }

  /**
   * Returns the unmodifiable map of custom (non-registered) JWK parameters.
   */
  public Map<String, Object> other() {
    return other;
  }

  // ---------- Custom-parameter access ----------

  /**
   * The {@code p} parameter (RFC 7518 §6.3.2.2): the first prime factor of the RSA private key. Represented as a
   * Base64urlUInt-encoded value.
   */
  public String p() {
    return p;
  }

  // ---------- Serialization ----------

  /**
   * The {@code q} parameter (RFC 7518 §6.3.2.3): the second prime factor of the RSA private key. Represented as a
   * Base64urlUInt-encoded value.
   */
  public String q() {
    return q;
  }

  /**
   * The {@code qi} parameter (RFC 7518 §6.3.2.6): the first CRT (Chinese Remainder Theorem) coefficient for the RSA
   * private key. Represented as a Base64urlUInt-encoded value.
   */
  public String qi() {
    return qi;
  }

  /**
   * Returns the SHA-1 JWK thumbprint of this key as a base64url-no-pad string. Provided for interoperability with
   * systems that still emit SHA-1 thumbprints; prefer {@link #thumbprintSHA256()} for new use.
   *
   * @return the base64url-no-pad SHA-1 thumbprint
   * @throws IllegalArgumentException if {@link #kty()} is null or unsupported
   */
  public String thumbprintSHA1() {
    return JWKThumbprint.compute("SHA-1", this);
  }

  /**
   * Returns the RFC 7638 / RFC 8037 SHA-256 JWK thumbprint of this key as a base64url-no-pad string. Suitable for use
   * as the JWS {@code kid} value.
   *
   * <p>The thumbprint is computed from the canonical JSON serialization of
   * the required member subset for {@link #kty()} (RFC 7638 §3.2 / RFC 8037 §2). Canonicalisation is independent of any
   * user-configured {@code JSONProcessor} so the bytes are stable across deployments.</p>
   *
   * @return the base64url-no-pad SHA-256 thumbprint
   * @throws IllegalArgumentException if {@link #kty()} is null or unsupported
   */
  public String thumbprintSHA256() {
    return JWKThumbprint.compute("SHA-256", this);
  }

  public String toJSON() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  // ---------- Static convenience methods ----------

  /**
   * Returns a new {@code JSONWebKey} with all private key material removed (d, dp, dq, p, q, qi). Safe to serve from a
   * public JWKS endpoint.
   */
  public JSONWebKey toPublicJSONWebKey() {
    Builder b = new Builder()
        .alg(alg)
        .crv(crv)
        .kid(kid)
        .kty(kty)
        .use(use)
        .keyOps(key_ops)
        .x5u(x5u)
        .e(e)
        .n(n)
        .x(x)
        .y(y)
        .x5c(x5c)
        .x5t(x5t)
        .x5tS256(x5tS256);
    for (Map.Entry<String, Object> entry : other.entrySet()) {
      b.parameter(entry.getKey(), entry.getValue());
    }
    return b.build();
  }

  /**
   * Parse this JWK's public-key material into a {@link PublicKey}. Equivalent to {@code JSONWebKey.parse(this)};
   * provided as an instance shorthand. Each call performs a fresh KeyFactory parse — cache the result if hot.
   *
   * @return the public key represented by this JWK
   * @throws JSONWebKeyParserException     if the key material is malformed
   * @throws UnsupportedOperationException if the JWK's {@code kty} is not RSA, EC, or OKP
   */
  public PublicKey toPublicKey() {
    return parse(this);
  }

  /**
   * Map suitable for JSON serialization. The Java field {@code x5tS256} is emitted under the wire-form key
   * {@code "x5t#S256"} per RFC 7517 §4.9.
   *
   * @apiNote The returned map is mutable and not shared with the {@code JSONWebKey} instance. Callers MUST NOT
   *     retain or mutate it -- the contract is that each call returns a fresh map intended for immediate handoff to a
   *     JSON serializer. List values ({@code key_ops}, {@code x5c}) reference the JWK's internal unmodifiable lists
   *     directly; the JSON serializer only iterates them.
   */
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
    if (x5tS256 != null) out.put("x5t#S256", x5tS256);
    for (Map.Entry<String, Object> entry : other.entrySet()) {
      if (entry.getValue() != null) {
        out.put(entry.getKey(), entry.getValue());
      }
    }
    return out;
  }

  /**
   * Debug-friendly representation. When populated, private key material fields (d, dp, dq, p, q, qi) are replaced with
   * {@code "***"}; absent fields remain absent (never materialized as {@code "***"}). Use {@link #toJSON()} for the
   * full content.
   */
  @Override
  public String toString() {
    Map<String, Object> redacted = new LinkedHashMap<>(toSerializableMap());
    for (String field : new String[]{"d", "dp", "dq", "p", "q", "qi"}) {
      if (redacted.containsKey(field)) {
        redacted.put(field, "***");
      }
    }
    return new String(new LatteJSONProcessor().serialize(redacted));
  }

  /**
   * The {@code use} parameter (RFC 7517 §4.2) identifying the intended use of the public key:
   * <ul>
   *   <li>{@code sig} — signature</li>
   *   <li>{@code enc} — encryption</li>
   * </ul>
   */
  public String use() {
    return use;
  }

  // ---------- toString / equals / hashCode ----------

  /**
   * The {@code x} parameter. For EC (RFC 7518 §6.2.1.2) this is the x coordinate of the public point,
   * Base64urlUInt-encoded. For OKP (RFC 8037 §2) this is the public key octet string, base64url-encoded.
   */
  public String x() {
    return x;
  }

  /**
   * The {@code x5c} parameter (RFC 7517 §4.7): the X.509 certificate chain. Each entry is a base64-encoded (not
   * base64url) DER-encoded X.509 certificate; the first entry holds the certificate matching this key.
   */
  public List<String> x5c() {
    return x5c;
  }

  /**
   * The {@code x5t} parameter (RFC 7517 §4.8): the base64url-encoded SHA-1 thumbprint of the DER-encoded X.509
   * certificate matching this key. Prefer {@link #x5tS256()} for new use; see RFC 6194 on SHA-1 collision resistance.
   */
  public String x5t() {
    return x5t;
  }

  /**
   * The {@code x5t#S256} parameter (RFC 7517 §4.9): the base64url-encoded SHA-256 thumbprint of the DER-encoded X.509
   * certificate matching this key.
   */
  public String x5tS256() {
    return x5tS256;
  }

  /**
   * The {@code x5u} parameter (RFC 7517 §4.6): a URI that refers to a resource for the X.509 public key certificate or
   * certificate chain.
   */
  public String x5u() {
    return x5u;
  }

  // ---------- Builder ----------

  /**
   * The {@code y} parameter (RFC 7518 §6.2.1.3): the y coordinate of the EC public point. Represented as a
   * Base64urlUInt-encoded value.
   */
  public String y() {
    return y;
  }

  /**
   * Mutable, reusable builder for {@link JSONWebKey}. After {@link #build()} is called, the builder retains its state
   * and may be further modified to produce additional independent {@link JSONWebKey} instances; each {@code build()}
   * call produces a fresh immutable instance with an independent copy of any collection fields.
   */
  public static final class Builder {
    private final Map<String, Object> other = new LinkedHashMap<>();
    private Algorithm alg;
    private String crv;
    private String d;
    private String dp;
    private String dq;
    private String e;
    private List<String> key_ops;
    private String kid;
    private KeyType kty;
    private String n;
    private String p;
    private String q;
    private String qi;
    private String use;
    private String x;
    private List<String> x5c;
    private String x5t;
    private String x5tS256;
    private String x5u;
    private String y;

    private Builder() {
    }

    /**
     * The {@code alg} parameter (RFC 7517 §4.4) identifies the algorithm intended for use with this key.
     */
    public Builder alg(Algorithm v) {
      this.alg = v;
      return this;
    }

    public JSONWebKey build() {
      return new JSONWebKey(this);
    }

    /**
     * The Elliptic Curve name for EC and OKP keys. Common values:
     * <ul>
     *   <li>{@code P-256}, {@code P-384}, {@code P-521} — EC (RFC 7518 §6.2.1.1)</li>
     *   <li>{@code Ed25519}, {@code Ed448} — OKP (RFC 8037 §2)</li>
     * </ul>
     */
    public Builder crv(String v) {
      this.crv = v;
      return this;
    }

    /**
     * The {@code d} parameter. For RSA (RFC 7518 §6.3.2.1) this is the private exponent. For EC (RFC 7518 §6.2.2.1) and
     * OKP (RFC 8037 §2) this is the private key value. Represented as a Base64urlUInt-encoded value for RSA/EC and a
     * base64url-encoded octet string for OKP.
     */
    public Builder d(String v) {
      this.d = v;
      return this;
    }

    /**
     * The {@code dp} parameter (RFC 7518 §6.3.2.4): the first factor CRT (Chinese Remainder Theorem) exponent for the
     * RSA private key. Represented as a Base64urlUInt-encoded value.
     */
    public Builder dp(String v) {
      this.dp = v;
      return this;
    }

    /**
     * The {@code dq} parameter (RFC 7518 §6.3.2.5): the second factor CRT (Chinese Remainder Theorem) exponent for the
     * RSA private key. Represented as a Base64urlUInt-encoded value.
     */
    public Builder dq(String v) {
      this.dq = v;
      return this;
    }

    /**
     * The {@code e} parameter (RFC 7518 §6.3.1.2): the public exponent of the RSA public key. Represented as a
     * Base64urlUInt-encoded value.
     */
    public Builder e(String v) {
      this.e = v;
      return this;
    }

    /**
     * The {@code key_ops} parameter (RFC 7517 §4.3) identifying the operations this key is intended for. Values include
     * {@code sign}, {@code verify}, {@code encrypt}, {@code decrypt}, {@code wrapKey}, {@code unwrapKey},
     * {@code deriveKey}, {@code deriveBits}.
     */
    public Builder keyOps(List<String> v) {
      this.key_ops = v;
      return this;
    }

    /**
     * The {@code kid} parameter (RFC 7517 §4.5): key identifier. Used to match a key to a JWS header's {@code kid}
     * parameter during signature verification.
     */
    public Builder kid(String v) {
      this.kid = v;
      return this;
    }

    /**
     * The {@code kty} parameter (RFC 7517 §4.1) identifying the cryptographic family:
     * <ul>
     *   <li>{@code EC}  — Elliptic Curve (RFC 7518 §6.2)</li>
     *   <li>{@code RSA} — RSA (RFC 7518 §6.3)</li>
     *   <li>{@code OKP} — Octet Key Pair, used for Edwards curves (RFC 8037)</li>
     *   <li>{@code oct} — Octet sequence, used for symmetric keys (RFC 7518 §6.4)</li>
     * </ul>
     */
    public Builder kty(KeyType v) {
      this.kty = v;
      return this;
    }

    /**
     * The {@code n} parameter (RFC 7518 §6.3.1.1): the modulus of the RSA public key. Represented as a
     * Base64urlUInt-encoded value.
     */
    public Builder n(String v) {
      this.n = v;
      return this;
    }

    /**
     * The {@code p} parameter (RFC 7518 §6.3.2.2): the first prime factor of the RSA private key. Represented as a
     * Base64urlUInt-encoded value.
     */
    public Builder p(String v) {
      this.p = v;
      return this;
    }

    /**
     * Add a custom (non-registered) JWK parameter. Registered parameters MUST be set via the typed setters; calling
     * this for a registered name throws {@link JSONWebKeyException}.
     */
    public Builder parameter(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (REGISTERED_PARAMETER_NAMES.contains(name)) {
        throw new JSONWebKeyException("JWK [" + name + "] is a registered parameter; set it via the typed builder method");
      }
      other.put(name, value);
      return this;
    }

    /**
     * The {@code q} parameter (RFC 7518 §6.3.2.3): the second prime factor of the RSA private key. Represented as a
     * Base64urlUInt-encoded value.
     */
    public Builder q(String v) {
      this.q = v;
      return this;
    }

    /**
     * The {@code qi} parameter (RFC 7518 §6.3.2.6): the first CRT (Chinese Remainder Theorem) coefficient for the RSA
     * private key. Represented as a Base64urlUInt-encoded value.
     */
    public Builder qi(String v) {
      this.qi = v;
      return this;
    }

    /**
     * The {@code use} parameter (RFC 7517 §4.2) identifying the intended use of the public key:
     * <ul>
     *   <li>{@code sig} — signature</li>
     *   <li>{@code enc} — encryption</li>
     * </ul>
     */
    public Builder use(String v) {
      this.use = v;
      return this;
    }

    /**
     * The {@code x} parameter. For EC (RFC 7518 §6.2.1.2) this is the x coordinate of the public point,
     * Base64urlUInt-encoded. For OKP (RFC 8037 §2) this is the public key octet string, base64url-encoded.
     */
    public Builder x(String v) {
      this.x = v;
      return this;
    }

    /**
     * The {@code x5c} parameter (RFC 7517 §4.7): the X.509 certificate chain. Each entry is a base64-encoded (not
     * base64url) DER-encoded X.509 certificate; the first entry holds the certificate matching this key.
     */
    public Builder x5c(List<String> v) {
      this.x5c = v;
      return this;
    }

    /**
     * The {@code x5t} parameter (RFC 7517 §4.8): the base64url-encoded SHA-1 thumbprint of the DER-encoded X.509
     * certificate matching this key. Prefer {@link #x5tS256(String)} for new use; see RFC 6194 on SHA-1 collision
     * resistance.
     */
    public Builder x5t(String v) {
      this.x5t = v;
      return this;
    }

    /**
     * The {@code x5t#S256} parameter (RFC 7517 §4.9): the base64url-encoded SHA-256 thumbprint of the DER-encoded X.509
     * certificate matching this key.
     */
    public Builder x5tS256(String v) {
      this.x5tS256 = v;
      return this;
    }

    /**
     * The {@code x5u} parameter (RFC 7517 §4.6): a URI that refers to a resource for the X.509 public key certificate
     * or certificate chain.
     */
    public Builder x5u(String v) {
      this.x5u = v;
      return this;
    }

    /**
     * The {@code y} parameter (RFC 7518 §6.2.1.3): the y coordinate of the EC public point. Represented as a
     * Base64urlUInt-encoded value.
     */
    public Builder y(String v) {
      this.y = v;
      return this;
    }
  }
}
