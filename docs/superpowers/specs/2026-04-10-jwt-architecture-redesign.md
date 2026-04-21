# JWT Library Architecture Redesign

**Date:** 2026-04-10
**Updated:** 2026-04-21
**Version:** 7.0.0 (major breaking change)
**Scope:** Full library -- JWT core, JWK, OAuth2 metadata, PEM/DER enhancements. JWE (JSON Web Encryption, RFC 7516) is out of scope for 7.0.
**License:** All new files use the MIT license.

## Design Goals

1. **Zero required dependencies.** Ship a built-in JSON parser. No Jackson, no Gson, nothing.
2. **Bring your own JSON.** A `JSONProcessor` strategy interface lets users plug in Jackson/Gson/etc.
3. **Spec-aligned types.** Time claims (`exp`, `nbf`, `iat`) use `Instant` instead of `ZonedDateTime`. No custom serializers needed.
4. **Performance.** The Map-based serialization path avoids reflection overhead. The built-in parser targets competitive performance with Jackson for small payloads (JWT-sized).
5. **Extensibility.** Algorithm as an interface (not enum). Strategy pattern for JSON. Clean builder APIs.
6. **Immutable models.** JWT and Header are immutable, built via builders. Builders are reusable -- calling `build()` produces an independent instance, and the builder remains valid for further modification and rebuilding. Thread-safe by construction.
7. **No private JDK classes.** Eliminate all use of `sun.*`, `com.sun.*`, and `jdk.internal.*` in production code. X.509 certificate parsing and generation uses our own DER encoder/decoder.

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│                   User Code                      │
│  JWT.builder().subject("u").expiresAt(i).build() │
│  encoder.encode(jwt, signer)                     │
│  decoder.decode(token, verifier)                 │
└──────────┬──────────────────────┬────────────────┘
           │                      │
     ┌─────▼─────┐         ┌─────▼─────┐
     │ JWTEncoder│         │ JWTDecoder│
     └─────┬─────┘         └─────┬─────┘
           │                      │
     ┌─────▼──────────────────────▼─────┐
     │         JSONProcessor            │
     │  serialize(Map) / deserialize()  │
     └─────┬──────────────────────┬─────┘
           │                      │
  ┌────────▼────────┐   ┌────────▼────────┐
  │ LatteJSONProc.  │   │ User-provided   │
  │ (built-in,      │   │ (Jackson, Gson, │
  │  zero-dep)      │   │  etc.)          │
  └─────────────────┘   └─────────────────┘
```

## Breaking Changes from 6.x

This is a major version bump. The following changes are intentionally breaking:

| Change | 6.x | 7.0 | Impact |
|--------|-----|-----|--------|
| `Algorithm` | Enum | Interface with constants | `switch` on Algorithm no longer compiles; use `algorithm.name()` or `.equals()` |
| `Algorithm.getName()` | Returns JCA string (e.g., `"SHA256withRSA"`) | `Algorithm.name()` returns JWA identifier (e.g., `"RS256"`) | Code using `getName()` for JCA lookups gets wrong values if mechanically migrated. JCA strings are now internal to Signer/Verifier implementations. |
| `KeyType` | Enum | Interface with constants | Same as Algorithm |
| `Signer.sign()` | `byte[] sign(String payload)` | `byte[] sign(byte[] message)` | All custom `Signer` implementations must update. The encoder now calls `getBytes(UTF_8)` before passing to `sign()`. |
| `Signer.getAlgorithm()` | Returns `Algorithm` enum | `algorithm()` returns `Algorithm` interface | Method rename + return type change |
| `Signer.getKid()` | Throws `UnsupportedOperationException` by default | `kid()` returns `null` by default | Behavior change: callers no longer need to catch exceptions |
| `JWT` | Mutable POJO with setters, `ZonedDateTime` fields | Immutable, builder pattern, `Instant` fields, long English names (`subject` not `getSubject`, fluent no-prefix style) | Full rewrite of construction and access patterns |
| `Header` | Mutable POJO with `set()` | Immutable, builder pattern, explicit `kid` field | Full rewrite |
| `JWT.getEncoder()` / `JWT.getDecoder()` | Static factories | Removed | Use `new JWTEncoder()` / `new JWTDecoder()` directly |
| Jackson dependency | Required (compile) | Removed | Users who need Jackson implement `JSONProcessor` |
| `Buildable<T>` interface | Used by `JSONWebKey`, `PEM` | Removed | Replaced by `Builder` inner classes |

## 1. Algorithm (Interface)

Replaces the current `Algorithm` enum. Extensible for custom algorithms.

```java
public interface Algorithm {
    /**
     * The JWA (JSON Web Algorithm) identifier as registered in the
     * IANA "JSON Web Signature and Encryption Algorithms" registry.
     * This is the value used in the JWT header "alg" parameter.
     *
     * <p>Examples: {@code "RS256"}, {@code "ES384"}, {@code "Ed25519"}</p>
     *
     * <p>This is <em>not</em> the JCA (Java Cryptography Architecture) algorithm
     * string (e.g., {@code "SHA256withRSA"}). JCA strings are internal to each
     * Signer/Verifier implementation and are not exposed by this interface.</p>
     *
     * @return the JWA algorithm name
     */
    String name();

    // Standard constants
    Algorithm HS256 = new StandardAlgorithm("HS256");
    Algorithm HS384 = new StandardAlgorithm("HS384");
    Algorithm HS512 = new StandardAlgorithm("HS512");
    Algorithm RS256 = new StandardAlgorithm("RS256");
    Algorithm RS384 = new StandardAlgorithm("RS384");
    Algorithm RS512 = new StandardAlgorithm("RS512");
    Algorithm PS256 = new StandardAlgorithm("PS256");
    Algorithm PS384 = new StandardAlgorithm("PS384");
    Algorithm PS512 = new StandardAlgorithm("PS512");
    Algorithm ES256 = new StandardAlgorithm("ES256");
    Algorithm ES384 = new StandardAlgorithm("ES384");
    Algorithm ES512 = new StandardAlgorithm("ES512");
    Algorithm Ed25519 = new StandardAlgorithm("Ed25519");
    Algorithm Ed448  = new StandardAlgorithm("Ed448");

    /**
     * Look up by JWA name. Returns the pre-built standard constant if the name matches
     * one of the 14 standard algorithms (enabling {@code ==} comparison for standard
     * algorithms). Returns a new instance for unrecognized names.
     */
    static Algorithm of(String name) { ... }
}
```

`StandardAlgorithm` is a package-private class with `equals`/`hashCode` based on `name()`.

The `Algorithm` interface is purely the JWA identifier for the header -- it carries no crypto configuration. Each Signer/Verifier implementation internally maps the JWA name to the appropriate JCA algorithm string (e.g., `RS256` → `"SHA256withRSA"`, `HS256` → `"HmacSHA256"`). This separation is intentional: the JCA string is a Java platform implementation detail, while the JWA name is the wire-format identifier that appears in JWT headers. Users interact with JWA names; the JCA mapping is an internal concern.

Custom algorithms: `Algorithm.of("MY_ALG")` or implement the interface directly.

### Algorithm Identity

`Algorithm.of(name)` returns the pre-built constant for standard algorithms, so `==` works:

```java
Algorithm.of("RS256") == Algorithm.RS256  // true -- same reference
Algorithm.of("MY_ALG") == Algorithm.of("MY_ALG")  // false -- different instances
Algorithm.of("MY_ALG").equals(Algorithm.of("MY_ALG"))  // true -- equals uses name()
```

For non-standard algorithms, use `.equals()`. Since `Algorithm` is no longer an enum, `switch` statements require `algorithm.name()`:

```java
switch (algorithm.name()) {
    case "RS256": ...
    case "ES256": ...
}
```

### Security: the "none" algorithm

No special `Algorithm.NONE` constant is defined. `Algorithm.of("none")` creates a normal instance. This is safe by design: the decoder always requires a verifier where `canVerify(algorithm)` returns true. Since no built-in verifier handles "none", the decoder throws `MissingVerifierException`. An attacker cannot exploit `alg: none` unless the application explicitly creates a verifier for it.

For decoding unsigned JWTs (e.g., inspecting claims without verification), see `JWTDecoder.decodeUnsecured()` in [Section 5](#5-encoder--decoder).

### EdDSA: Fully-Specified Algorithm Identifiers (RFC 9864)

Per [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) (October 2025), the polymorphic `"EdDSA"` algorithm identifier is **deprecated** in the IANA JOSE registry. The fully-specified replacements are `"Ed25519"` and `"Ed448"`, which this library uses as the standard constants.

No `Algorithm.EdDSA` constant is defined. If a token arrives with `"alg": "EdDSA"` in the header, `Algorithm.of("EdDSA")` creates a non-standard instance. No built-in verifier's `canVerify()` will match it, and the decoder throws `MissingVerifierException`. Users who need to handle legacy `"EdDSA"` tokens can build a custom verifier that accepts it -- that is an application-level decision, not a library concern.

The signers always emit the fully-specified identifier (`"Ed25519"` or `"Ed448"`) in the JWT header.

**Handling legacy `"EdDSA"` tokens:** The library architecture supports this without any built-in changes. A user who receives tokens with `"alg": "EdDSA"` can wrap their Ed25519 verifier to accept the legacy identifier:

```java
Verifier legacyEdDSA = new Verifier() {
    private final EdDSAVerifier delegate = new EdDSAVerifier(publicKey);

    public boolean canVerify(Algorithm algorithm) {
        return "EdDSA".equals(algorithm.name()) || delegate.canVerify(algorithm);
    }

    public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
        delegate.verify(delegate.algorithm(), message, signature);
    }
};
```

This is an application-level decision because the old `"EdDSA"` identifier is polymorphic -- it could mean Ed25519 or Ed448. The application knows which curve to expect; the library does not.

## 2. JWT (Immutable + Builder)

```java
public class JWT {
    // Registered claims -- long English names, spec-aligned types
    private final String issuer;          // "iss"
    private final String subject;         // "sub"
    private final Object audience;        // "aud": String or List<String>, preserved as-is
    private final Instant expiresAt;      // "exp"
    private final Instant notBefore;      // "nbf"
    private final Instant issuedAt;       // "iat"
    private final String id;              // "jti"
    private final Map<String, Object> customClaims;

    // Header -- populated on decode, not serialized with claims
    private final Header header;

    // --- Fluent getters (no "get" prefix, long English names) ---
    public String issuer() { ... }
    public String subject() { ... }
    public Instant expiresAt() { ... }
    public Instant notBefore() { ... }
    public Instant issuedAt() { ... }
    public String id() { ... }
    public Header header() { ... }

    // --- Audience accessors ---
    /** Returns the raw audience value: String, List<String>, or null. */
    public Object audience() { ... }
    /** Returns audience as a single string. If aud is a list, returns the first element. */
    public String audienceSingle() { ... }
    /** Returns audience as a list. If aud is a single string, wraps it in a list. */
    public List<String> audienceList() { ... }

    // --- Custom claim accessors ---
    // These look up by name, checking registered claims first, then customClaims.
    // Typed accessors convert from the underlying BigInteger/BigDecimal
    // representation as needed. If the value cannot be cast or converted to the
    // requested type, a ClassCastException is thrown.
    public String getString(String name) { ... }
    public Integer getInteger(String name) { ... }
    public Long getLong(String name) { ... }
    public Float getFloat(String name) { ... }
    public Double getDouble(String name) { ... }
    public Boolean getBoolean(String name) { ... }
    public BigDecimal getBigDecimal(String name) { ... }
    public BigInteger getBigInteger(String name) { ... }
    public Number getNumber(String name) { ... }
    public Object getObject(String name) { ... }
    public Map<String, Object> getMap(String name) { ... }

    // --- List accessors ---
    /** Returns the list value for the given claim name, or null. Elements are untyped. */
    public List<Object> getList(String name) { ... }
    /**
     * Returns the list value for the given claim name with element type checking.
     * Each element is cast to the specified type; throws ClassCastException if any
     * element does not match.
     */
    public <T> List<T> getList(String name, Class<T> elementType) { ... }

    // --- Maps ---
    /** All claims (registered + custom) merged, with raw Java types (Instant, etc.). */
    public Map<String, Object> claims() { ... }

    /** All claims with JSON-safe values (Instant -> epoch seconds). Ready for serialization. */
    public Map<String, Object> toSerializableMap() { ... }

    // --- Convenience ---
    public boolean isExpired() { ... }
    public boolean isExpired(Instant now) { ... }
    public boolean isUnavailableForProcessing() { ... }
    public boolean isUnavailableForProcessing(Instant now) { ... }

    // --- Factory ---
    /** Hydrate a JWT from a deserialized map (used by decoder). */
    public static JWT fromMap(Map<String, Object> map, Header header) { ... }

    // --- equals / hashCode / toString ---
    // equals/hashCode based on all claim fields.
    // toString() uses the built-in LatteJSONProcessor for JSON pretty-print.
    // This output is for debugging/logging; use JWTEncoder for wire-format serialization.
    // toString() does not depend on JWTConfig or any user-provided JSONProcessor.

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        public Builder issuer(String issuer) { ... }
        public Builder subject(String subject) { ... }
        public Builder audience(String audience) { ... }
        public Builder audience(List<String> audiences) { ... }
        public Builder expiresAt(Instant expiration) { ... }
        public Builder expiresAt(long epochSeconds) { ... }
        public Builder notBefore(Instant notBefore) { ... }
        public Builder notBefore(long epochSeconds) { ... }
        public Builder issuedAt(Instant issuedAt) { ... }
        public Builder issuedAt(long epochSeconds) { ... }
        public Builder id(String jwtId) { ... }

        /**
         * Add a claim. If the name matches a registered claim (iss, sub, aud, exp,
         * nbf, iat, jti), the value is routed to the corresponding typed field with
         * type coercion (see table below). Throws IllegalArgumentException if the
         * value cannot be coerced to the registered claim's type. Unrecognized names
         * are stored in customClaims. A registered claim name can never collide with
         * customClaims.
         */
        public Builder claim(String name, Object value) { ... }

        public JWT build() { ... }
    }
}
```

### Builder.claim() Coercion Rules

When `claim(name, value)` is called with a registered claim name, the value is coerced to the target type:

| Claim name | Target type | Accepted value types | Coercion |
|------------|------------|---------------------|----------|
| `iss`, `sub`, `jti` | `String` | `String` | Direct assignment |
| `iss`, `sub`, `jti` | `String` | Any other type | `IllegalArgumentException` |
| `exp`, `nbf`, `iat` | `Instant` | `Instant` | Direct assignment |
| `exp`, `nbf`, `iat` | `Instant` | `Number` (Long, Integer, BigInteger, BigDecimal, Double) | `Instant.ofEpochSecond(value.longValue())` |
| `exp`, `nbf`, `iat` | `Instant` | `ZonedDateTime` | `value.toInstant()` (eases migration from 6.x) |
| `exp`, `nbf`, `iat` | `Instant` | Any other type | `IllegalArgumentException` |
| `aud` | `Object` | `String` | Stored as `String` |
| `aud` | `Object` | `List<String>` | Stored as `List<String>` |
| `aud` | `Object` | Any other type | `IllegalArgumentException` |

Unrecognized claim names are stored as-is in `customClaims` with no type coercion.

```java
// These are equivalent:
JWT.builder().expiresAt(Instant.ofEpochSecond(1700000000)).build();
JWT.builder().claim("exp", 1700000000L).build();
JWT.builder().claim("exp", Instant.ofEpochSecond(1700000000)).build();
```

### Audience Handling

The `aud` claim is stored exactly as provided -- preserving the original form through round-trips.

- `builder.audience("single")` -> stored as `String` -> serialized as `"aud": "single"`
- `builder.audience(List.of("single"))` -> stored as `List<String>` -> serialized as `"aud": ["single"]`
- `builder.audience(List.of("a", "b"))` -> stored as `List<String>` -> serialized as `"aud": ["a", "b"]`

On deserialization, `fromMap()` preserves the JSON form: a JSON string becomes a `String`, a JSON array becomes a `List<String>`. No implicit conversion between the two forms.

The typed accessors (`audienceSingle()`, `audienceList()`) provide convenience without mutating the stored representation.

### fromMap() Resilience

`JWT.fromMap()` handles type mismatches defensively:

- Time claims (`exp`, `nbf`, `iat`): accepts any `Number` subtype (Long, Integer, BigInteger, BigDecimal, Double) and converts to `Instant` via `longValue()`. Non-numeric values for a time claim throw `InvalidJWTException`.
- String claims (`iss`, `sub`, `jti`): non-string values for these RFC-specified string claims throw `InvalidJWTException`.
- Unknown/custom claims: passed through as-is from the JSON processor into `customClaims`.

### Immutability of Returned Collections

All map and list accessors return unmodifiable views. Callers cannot mutate the JWT's internal state through returned references:

- `claims()` returns `Collections.unmodifiableMap(...)` (shallow copy)
- `toSerializableMap()` returns an unmodifiable map (new map, not a view of internals)
- `audienceList()` returns `Collections.unmodifiableList(...)`
- `Header.parameters()` and `Header.toSerializableMap()` same pattern
- `JSONWebKey.parameters()`, `JSONWebKey.x5c()` same pattern

This is a shallow guarantee -- map values that are mutable objects (e.g., nested `Map` or `List` from custom claims) are not defensively copied. For JWT-sized payloads with standard JSON types this is sufficient.

### toSerializableMap() Behavior

Registered claims are written first (using `LinkedHashMap` to preserve insertion order), then custom claims. Since `Builder.claim()` routes registered names to their typed fields (never to `customClaims`), no collision between registered and custom claims is possible in `toSerializableMap()`. Null-valued claims are omitted.

### Key changes from current

| Aspect | Current (6.x) | New (7.0) |
|--------|---------------|-----------|
| Fields / accessors | `subject`, `issuer`, `expiration` (with `get`/`set` prefix) | `subject()`, `issuer()`, `expiresAt()` (fluent, no prefix) |
| Time type | `ZonedDateTime` | `Instant` (+ `long` builder overloads) |
| Mutability | Mutable POJO with setters | Immutable, builder pattern (reusable builders) |
| Annotations | `@JsonProperty`, `@JsonSerialize`, etc. | None |
| Serialization | Jackson ObjectMapper directly | `toSerializableMap()` -> `JSONProcessor` |
| Custom claims map | `otherClaims` | `customClaims` (not directly exposed) |
| Audience | `Object` with no typed accessors | `Object` with `audienceSingle()` / `audienceList()` accessors |
| Static factories | `JWT.getEncoder()`, `JWT.getDecoder()` | Removed -- construct `new JWTEncoder()` / `new JWTDecoder()` directly |
| `toString()` | Uses `Mapper.prettyPrint()` (Jackson) | Uses built-in `LatteJSONProcessor` always |

## 3. Header (Immutable + Builder)

```java
public class Header {
    private final Algorithm alg;
    private final String typ;       // default "JWT"
    private final String kid;
    private final Map<String, Object> customParameters;

    // Fluent getters
    public Algorithm alg() { ... }
    public String typ() { ... }
    public String kid() { ... }

    // Custom parameter access
    public Object get(String name) { ... }
    public String getString(String name) { ... }

    // Maps
    /** All parameters (alg, typ, kid, custom) merged. */
    public Map<String, Object> parameters() { ... }
    public Map<String, Object> toSerializableMap() { ... }

    // Factory
    public static Header fromMap(Map<String, Object> map) { ... }

    // equals / hashCode / toString (toString uses built-in LatteJSONProcessor)

    public static Builder builder() { ... }

    public static class Builder {
        public Builder alg(Algorithm algorithm) { ... }
        public Builder typ(String type) { ... }
        public Builder kid(String keyId) { ... }
        public Builder parameter(String name, Object value) { ... }
        public Header build() { ... }
    }
}
```

Header uses RFC 7515 terminology: "parameters" (not "claims"). Custom parameter storage is `customParameters` internally, accessed via `get(name)` and `parameters()` (which merges all parameters into a single map).

### Header.fromMap() Behavior

`Header.fromMap()` converts the `"alg"` string value to an `Algorithm` instance via `Algorithm.of()`. If `"alg"` is missing from the map, `fromMap()` throws `InvalidJWTException` -- the `alg` parameter is REQUIRED per RFC 7515 Section 4.1.1.

### Critical Header Parameter (`crit`) — RFC 7515 Section 4.1.11

Per RFC 7515, if a JWT header contains a `"crit"` array, the recipient MUST understand and process every header parameter name listed, or reject the JWS. Failing to enforce this is an active CVE category (CVE-2026-32597, CVE-2026-35042, GHSA-9ggr-2464-2j32) -- libraries that silently accept tokens with unrecognized `crit` entries enable split-brain verification in heterogeneous systems.

**Behavior:** The decoder checks for `"crit"` in the parsed header. If present and non-empty, every name in the array must appear in the decoder's set of understood critical parameters. If any name is unrecognized, the decoder throws `InvalidJWTException`. Since this library does not natively process any extension header parameters, the default set is empty -- meaning any token with a non-empty `crit` array is rejected unless the caller explicitly opts in.

**Configuration:** `JWTDecoder` accepts an optional `Set<String>` of understood critical header parameter names:

```java
// Default -- rejects any token with crit (safe default)
JWTDecoder decoder = new JWTDecoder();

// Opt in to specific critical headers
JWTDecoder decoder = new JWTDecoder.Builder()
    .criticalHeaders(Set.of("b64", "http://openbanking.org.uk/iat"))
    .build();
```

The decoder validates that the listed names are present; the application is responsible for actually processing the extension semantics. This follows the same pattern as JJWT's `critical().add(...)` API.

## 4. JSONProcessor (Strategy Interface)

```java
public interface JSONProcessor {
    /** Throws JSONProcessingException on serialization failure. */
    byte[] serialize(Map<String, Object> object) throws JSONProcessingException;

    /** Throws JSONProcessingException on deserialization failure. */
    Map<String, Object> deserialize(byte[] json) throws JSONProcessingException;
}
```

`JSONProcessingException` extends `JWTException` (unchecked). The `throws` clause is documentary -- it tells implementors what to throw. The encoder/decoder catch and propagate these directly.

### Configuration

Three ways to configure, in order of precedence:

1. **Constructor injection** (highest): `new JWTEncoder(myProcessor)`
2. **Global default**: `JWTConfig.setDefaultJSONProcessor(myProcessor)`
3. **Built-in fallback** (lowest): `LatteJSONProcessor` -- always available, zero dependencies

```java
// Simplest usage -- built-in parser, zero config
JWTEncoder encoder = new JWTEncoder();
JWTDecoder decoder = new JWTDecoder();

// Global override -- set once at startup
JWTConfig.setDefaultJSONProcessor(new JacksonJSONProcessor());

// Per-instance override -- takes precedence over global
JWTEncoder encoder = new JWTEncoder(new GsonJSONProcessor());
```

**No SPI / ServiceLoader.** The explicit configuration above covers all use cases without the debugging pain and classpath ambiguity that ServiceLoader introduces. JJWT uses ServiceLoader and has documented issues with fat JARs and runtime performance. We avoid this.

### JWTConfig

```java
public final class JWTConfig {
    private static volatile JSONProcessor defaultJSONProcessor;

    public static void setDefaultJSONProcessor(JSONProcessor processor) { ... }
    public static JSONProcessor getDefaultJSONProcessor() { ... }

    // Package-private: resolves constructor-provided > global > built-in
    static JSONProcessor resolve(JSONProcessor instanceLevel) { ... }
}
```

Global state is stored in a `volatile` field for thread-safe reads without synchronization.

### Built-in Implementation

`LatteJSONProcessor` -- a hand-rolled JSON reader + writer.

**Writer:** Iterates map entries, writes JSON with proper string escaping, handles nested maps/lists recursively. No intermediate allocations beyond the output buffer.

**Reader:** Recursive descent parser. Dispatches on first character: `{` (object), `[` (array), `"` (string), digit/`-` (number), `t`/`f` (boolean), `n` (null).

**Number handling:** Always `BigInteger` for integer values, always `BigDecimal` for decimal values. This matches the current Jackson configuration (`USE_BIG_INTEGER_FOR_INTS` + `USE_BIG_DECIMAL_FOR_FLOATS`) and ensures no precision loss for custom claims. The typed accessors on JWT (`getLong()`, `getInteger()`) handle conversion from BigInteger.

**JSON type mapping:**

| JSON | Java |
|------|------|
| object | `LinkedHashMap<String, Object>` |
| array | `ArrayList<Object>` |
| string | `String` |
| integer number | `BigInteger` |
| decimal number | `BigDecimal` |
| boolean | `Boolean` |
| null | `null` |

**Target size:** ~500-800 lines across `JsonReader` + `JsonWriter`.

### User-provided Example (Jackson)

```java
public class JacksonJSONProcessor implements JSONProcessor {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public byte[] serialize(Map<String, Object> object) {
        try {
            return mapper.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            throw new JSONProcessingException("JSON serialization failed", e);
        }
    }

    @Override
    public Map<String, Object> deserialize(byte[] json) {
        try {
            return mapper.readValue(json, new TypeReference<>() {});
        } catch (IOException e) {
            throw new JSONProcessingException("JSON deserialization failed", e);
        }
    }
}
```

## 5. Encoder / Decoder

```java
public class JWTEncoder {
    private final JSONProcessor jsonProcessor;

    public JWTEncoder() { /* resolves via JWTConfig.resolve(null) */ }
    public JWTEncoder(JSONProcessor jsonProcessor) { ... }

    public String encode(JWT jwt, Signer signer) { ... }
    public String encode(JWT jwt, Signer signer, Consumer<Header.Builder> consumer) { ... }
}

public class JWTDecoder {
    private final JSONProcessor jsonProcessor;
    private final Duration clockSkew;
    private final Set<String> criticalHeaders;

    public JWTDecoder() { ... }
    public JWTDecoder(JSONProcessor jsonProcessor) { ... }
    public JWTDecoder(Duration clockSkew) { ... }
    public JWTDecoder(JSONProcessor jsonProcessor, Duration clockSkew) { ... }

    /** Single verifier. */
    public JWT decode(String encodedJWT, Verifier verifier) { ... }

    /** Multiple verifiers keyed by kid (looked up from header). */
    public JWT decode(String encodedJWT, Map<String, Verifier> verifiers) { ... }

    /** Full control -- function receives the Header, returns the Verifier to use. */
    public JWT decode(String encodedJWT, Function<Header, Verifier> verifierResolver) { ... }

    // --- Overloads with post-decode validation ---
    public JWT decode(String encodedJWT, Verifier verifier,
                      Consumer<JWT> validator) { ... }
    public JWT decode(String encodedJWT, Map<String, Verifier> verifiers,
                      Consumer<JWT> validator) { ... }
    public JWT decode(String encodedJWT, Function<Header, Verifier> verifierResolver,
                      Consumer<JWT> validator) { ... }

    // --- Unsecured decode (no signature verification) ---
    /**
     * Decode a JWT payload without verifying the signature. For inspection/debugging only.
     * Returns a JWT with the header populated.
     */
    public JWT decodeUnsecured(String encodedJWT) { ... }
}
```

`JWTDecoder` and `JWTEncoder` are lightweight objects intended to be instantiated per-use. All fields are `final`. The decoder is not designed for shared/long-lived use, but its immutability means there is no thread-safety hazard if it is shared.

For advanced configuration (critical headers, etc.), use the builder:

```java
JWTDecoder decoder = new JWTDecoder.Builder()
    .jsonProcessor(myProcessor)
    .clockSkew(Duration.ofSeconds(30))
    .criticalHeaders(Set.of("b64"))
    .build();
```

The constructors remain for the common cases; the builder adds access to the full configuration surface.

### TimeMachineJWTDecoder

For testing time-dependent JWT validation logic. Overrides the `now()` used for `exp`/`nbf` checks.

```java
public class TimeMachineJWTDecoder extends JWTDecoder {
    public TimeMachineJWTDecoder(Instant now) { ... }
    public TimeMachineJWTDecoder(Instant now, JSONProcessor jsonProcessor) { ... }
    public TimeMachineJWTDecoder(Instant now, JSONProcessor jsonProcessor, Duration clockSkew) { ... }
}
```

### Unsecured JWT Decoding

Moved from `JWTUtils.decodePayload()` and `JWT.decodeUnsecured()` to `JWTDecoder.decodeUnsecured()`. This keeps the `JWT` class as a pure model/POJO with no infrastructure dependencies. The method is explicitly named to make the security implications clear. It parses the payload without any signature verification -- for inspection/debugging only.

```java
JWT claims = new JWTDecoder().decodeUnsecured(token);
```

The returned JWT has its `header()` populated, so a separate header-only decode method is unnecessary.

### Encode Flow

1. Build `Header` -- the encoder pre-populates `alg` from `signer.algorithm()` and `kid` from `signer.kid()` (null if the signer has no kid):
   - `encode(jwt, signer)`: uses signer defaults directly
   - `encode(jwt, signer, consumer)`: passes a pre-populated `Header.Builder` to the consumer, who can add extra parameters (e.g., `x5t`, `cty`) or override/remove `kid` by setting it to `null`. The `alg` is always set from the signer and cannot be overridden -- this prevents accidental mismatches between the header algorithm and the actual signing algorithm.
2. `header.toSerializableMap()` -> `jsonProcessor.serialize()` -> Base64URL encode (no padding, per RFC 7515 Section 2)
3. `jwt.toSerializableMap()` -> `jsonProcessor.serialize()` -> Base64URL encode (no padding)
4. Concatenate `encodedHeader.encodedPayload`
5. Convert the concatenated string to `byte[]` via `getBytes(UTF_8)`, then `signer.sign(bytes)` -> Base64URL encode
6. Return `encodedHeader.encodedPayload.encodedSignature`

### Decode Flow

1. Split on `.` -- requires exactly 3 segments. Fewer than 3 (missing signature) throws `MissingSignatureException`. More than 3 (e.g., a JWE compact serialization with 5 parts) throws `InvalidJWTException`. This is existing 6.x behavior preserved in 7.0.
2. Base64URL decode header -> `jsonProcessor.deserialize()` -> `Header.fromMap()`. Missing `alg` throws `InvalidJWTException`.
3. If `crit` is present in the header, validate all listed parameter names against the decoder's `criticalHeaders` set. Unrecognized names throw `InvalidJWTException`.
4. Select verifier:
   - Single verifier: use directly (after `canVerify` check). If `canVerify` returns false, throw `MissingVerifierException`.
   - Map: look up by `header.kid()`. If the header has no `kid`, or the `kid` does not match any key in the map, throw `MissingVerifierException`.
   - Function: call `verifierResolver.apply(header)` -- caller has full access to the header for any selection strategy. If the function returns null, throw `MissingVerifierException`.
5. Verify signature against `headerB64.payloadB64`
6. Base64URL decode payload -> `jsonProcessor.deserialize()` -> `JWT.fromMap()`
   - `fromMap()` converts `Number` values in `exp`/`nbf`/`iat` to `Instant`
7. Validate `exp`/`nbf` with clock skew
8. If a `validator` was provided, call `validator.accept(jwt)` -- the validator throws any `JWTException` subclass to reject the token
9. Return `JWT`

### Post-decode Validation

The optional `Consumer<JWT> validator` parameter runs after signature verification and built-in time validation. The contract: throw any `JWTException` subclass to reject the token. The decoder does not wrap or catch these -- they propagate directly to the caller.

```java
decoder.decode(token, verifier, jwt -> {
    if (!"expected-issuer".equals(jwt.issuer()))
        throw new InvalidJWTException("Unexpected issuer: " + jwt.issuer());
    if (!jwt.audienceList().contains("my-service"))
        throw new InvalidJWTException("Token not intended for this service");
});
```

This is optional. The existing single-argument decode methods work without it.

## 6. Signer / Verifier

```java
public interface Signer {
    /**
     * Returns the JWA algorithm for this signer.
     *
     * @return the algorithm
     */
    Algorithm algorithm();

    /**
     * Sign the provided message and return the signature.
     *
     * @param message The message bytes to sign (header.payload encoded as UTF-8).
     * @return The signature bytes.
     */
    byte[] sign(byte[] message);

    /**
     * Returns the key ID for this signer, or null if no key ID is set.
     * The encoder uses this to populate the "kid" header parameter.
     *
     * @return the kid, or null
     */
    default String kid() {
        return null;
    }
}

public interface Verifier {
    boolean canVerify(Algorithm algorithm);
    void verify(Algorithm algorithm, byte[] message, byte[] signature);
}
```

Implementations keep the same factory method patterns:

```java
HMACSigner.newSHA256Signer(String secret)
HMACSigner.newSHA256Signer(String secret, String kid)
RSASigner.newSHA256Signer(String pemPrivateKey)
// etc.
```

### Signers / Verifiers Utility Classes

A `Signers` utility class provides dynamic algorithm-to-signer lookup for the built-in algorithms. This eliminates the switch statement users currently need when they have an `Algorithm` value at runtime (e.g., from a JWK or config file).

```java
public final class Signers {
    /**
     * Create a signer for the given algorithm using a PEM-encoded private key (for
     * asymmetric algorithms) or a secret string (for HMAC algorithms). The algorithm
     * determines interpretation: HS* algorithms treat the string as an HMAC secret;
     * all other algorithms treat it as a PEM-encoded private key.
     */
    public static Signer forAlgorithm(Algorithm algorithm, String keyMaterial) { ... }
    public static Signer forAlgorithm(Algorithm algorithm, String keyMaterial, String kid) { ... }

    /** Create a signer for an asymmetric algorithm using a PrivateKey. */
    public static Signer forAlgorithm(Algorithm algorithm, PrivateKey key) { ... }
    public static Signer forAlgorithm(Algorithm algorithm, PrivateKey key, String kid) { ... }
}

public final class Verifiers {
    /**
     * Create a verifier for the given algorithm using a PEM-encoded public key (for
     * asymmetric algorithms) or a secret string (for HMAC algorithms).
     */
    public static Verifier forAlgorithm(Algorithm algorithm, String keyMaterial) { ... }

    /** Create a verifier for an asymmetric algorithm using a PublicKey. */
    public static Verifier forAlgorithm(Algorithm algorithm, PublicKey key) { ... }

    /**
     * Returns a composite Verifier that tries each delegate in order, using the first
     * where canVerify() returns true. This replaces the varargs Verifier... parameter
     * from the 6.x JWTDecoder.decode() method.
     *
     * <p><strong>Fail-fast semantics:</strong> {@code canVerify()} answers "does this
     * verifier understand this algorithm?" -- not "is the signature valid." The first
     * verifier where {@code canVerify()} returns true gets one shot at
     * {@code verify()}. If {@code verify()} throws (e.g., invalid signature), the
     * exception propagates immediately -- subsequent verifiers are not tried. The
     * intended usage is that no two verifiers in the list should return
     * {@code canVerify() == true} for the same algorithm.</p>
     *
     * <p>If no verifier's {@code canVerify()} returns true, throws
     * {@code MissingVerifierException}.</p>
     */
    public static Verifier anyOf(Verifier... verifiers) { ... }
}
```

These cover the 14 standard algorithms only. Custom algorithm implementors construct their `Signer`/`Verifier` directly -- no registry or extension mechanism is provided at this time. The existing type-safe factory methods on each class (e.g., `HMACSigner.newSHA256Signer()`) are preserved for discoverability and compile-time safety.

### Migration from 6.x varargs decode

```java
// 6.x: varargs verifiers
decoder.decode(token, rsaVerifier, hmacVerifier);

// 7.0: composite verifier
decoder.decode(token, Verifiers.anyOf(rsaVerifier, hmacVerifier));
```

## 7. KeyType (Interface)

Same pattern as Algorithm -- replaces the current `KeyType` enum with an interface for extensibility.

```java
public interface KeyType {
    /** JWK "kty" parameter value. */
    String name();

    KeyType RSA = new StandardKeyType("RSA");
    KeyType EC  = new StandardKeyType("EC");
    KeyType OKP = new StandardKeyType("OKP");
    KeyType OCT = new StandardKeyType("oct");

    /** Look up by name. Returns a standard constant if matched, otherwise a new instance. */
    static KeyType of(String name) { ... }
}
```

`StandardKeyType` is a package-private class with `equals`/`hashCode` based on `name()`, same pattern as `StandardAlgorithm`. `KeyType.of()` interns standard constants the same way `Algorithm.of()` does.

`KeyType.OCT` represents symmetric keys per RFC 7517 Section 6.4. This ensures the JWK parser does not choke on `"kty": "oct"` entries in a JWKS response. Full symmetric JWK support (building/parsing `oct` keys) may be added in a future release, but the `KeyType` constant is defined now for forward compatibility.

**RSA-PSS keys:** No separate `KeyType.RSA_PSS` is defined. The IANA "JSON Web Key Types" registry does not include `"RSASSA-PSS"` as a `kty` value -- RSA-PSS keys use `"kty": "RSA"` on the wire, the same as PKCS#1 v1.5 keys. The algorithm distinction is in the `"alg"` parameter (e.g., `"PS256"`), not in `kty`. Internally, Java's `KeyFactory` uses `"RSASSA-PSS"` as an algorithm identifier for PSS-specific keys -- the `JSONWebKeyBuilder` and `JSONWebKeyParser` handle this distinction without exposing it through `KeyType`.

## 8. JWK / OAuth2

Same pattern as JWT -- remove Jackson annotations, use `Map<String, Object>` + `JSONProcessor`.

### JSONWebKey

```java
public class JSONWebKey {
    private final Algorithm alg;
    private final String crv;
    private final String kid;
    private final KeyType kty;
    private final String use;
    private final String d, dp, dq, e, n, p, q, qi;
    private final String x, y;
    private final List<String> x5c;
    private final String x5t;
    private final String x5t_256;
    private final Map<String, Object> customParameters;

    // Fluent getters for all fields
    public Algorithm alg() { ... }
    public String crv() { ... }
    public String kid() { ... }
    public KeyType kty() { ... }
    public String use() { ... }
    public String d() { ... }
    // ... etc. for all key material fields
    public List<String> x5c() { ... }
    public String x5t() { ... }
    public String x5t_256() { ... }

    // Custom parameter access
    public Object get(String name) { ... }
    public String getString(String name) { ... }
    /** All parameters (known + custom) merged. */
    public Map<String, Object> parameters() { ... }

    // --- Serialization ---
    /**
     * toSerializableMap() handles the x5t#S256 mapping explicitly:
     * the Java field is x5t_256, but the serialized map key is "x5t#S256"
     * per the JWK spec (RFC 7517 Section 4.9).
     */
    public Map<String, Object> toSerializableMap() { ... }

    /**
     * fromMap() reads "x5t#S256" from the map and stores it in x5t_256.
     */
    public static JSONWebKey fromMap(Map<String, Object> map) { ... }

    public String toJSON() { ... }

    // --- Static convenience methods (preserved from 6.x) ---
    /** Build a JSON Web Key from an encoded PEM. */
    public static JSONWebKey build(String encodedPEM) { ... }
    /** Build a JSON Web Key from a certificate. */
    public static JSONWebKey build(Certificate certificate) { ... }
    /** Build a JSON Web Key from a private key. */
    public static JSONWebKey build(PrivateKey privateKey) { ... }
    /** Build a JSON Web Key from a public key. */
    public static JSONWebKey build(PublicKey publicKey) { ... }
    /** Parse a JSON Web Key to extract the public key. */
    public static PublicKey parse(JSONWebKey key) { ... }

    // equals / hashCode / toString

    public static Builder builder() { ... }

    public static class Builder {
        public Builder alg(Algorithm algorithm) { ... }
        public Builder crv(String curve) { ... }
        public Builder kid(String keyId) { ... }
        public Builder kty(KeyType keyType) { ... }
        public Builder use(String use) { ... }
        public Builder d(String d) { ... }
        public Builder dp(String dp) { ... }
        public Builder dq(String dq) { ... }
        public Builder e(String e) { ... }
        public Builder n(String n) { ... }
        public Builder p(String p) { ... }
        public Builder q(String q) { ... }
        public Builder qi(String qi) { ... }
        public Builder x(String x) { ... }
        public Builder y(String y) { ... }
        public Builder x5c(List<String> x5c) { ... }
        public Builder x5t(String x5t) { ... }
        public Builder x5t_256(String x5t_256) { ... }
        public Builder parameter(String name, Object value) { ... }
        public JSONWebKey build() { ... }
    }
}
```

### JSONWebKeyBuilder / JSONWebKeyParser

Currently use Jackson for JSON operations. Updated to use `JSONProcessor` via `JWTConfig.resolve()`, same pattern as encoder/decoder.

### JSONWebKeySetHelper

Currently uses `JsonNode` for HTTP response tree parsing. Switches to `JSONProcessor.deserialize()` returning `Map<String, Object>`, then navigates with standard map operations:

```java
// Before (Jackson JsonNode)
JsonNode response = Mapper.deserialize(is, JsonNode.class);
JsonNode jwksUri = response.at("/jwks_uri");

// After (Map)
Map<String, Object> response = jsonProcessor.deserialize(bytes);
String jwksUri = (String) response.get("jwks_uri");
```

### AuthorizationServerMetaData / OpenIDConnect

Same pattern -- builder, `fromMap()`, `toSerializableMap()`, no annotations.

## 9. PEM/DER Enhancements: X.509 Without Private Classes

### Goal

Parse and generate X.509 certificates using our own DER encoder/decoder, eliminating the dependency on `java.security.cert.CertificateFactory` where possible. This gives us full control over the certificate structure and removes reliance on JDK internals.

### Current State

- The DER infrastructure (`DerInputStream`, `DerOutputStream`, `DerValue`, `Tag`, `ObjectIdentifier`) is mature and handles key encoding/decoding well.
- `PEMDecoder` handles X.509 certificate PEM blocks but delegates to `CertificateFactory.getInstance("X.509")` for the actual parsing.
- `PEMEncoder` can encode certificates in PEM format.
- `ObjectIdentifier` already defines OIDs for common algorithms (RSA, EC, EdDSA).

### Prior Art: moreDerEncoding branch

The `moreDerEncoding` branch on `fusionauth/fusionauth-jwt` contains incomplete but directionally correct work on this. Key pieces to carry forward:

**DerValue factory methods** (partially implemented, need porting):
```java
DerValue.newBitString(byte[] bytes)        // wraps with 0x00 padding byte
DerValue.newGeneralizedTime(Date date)     // "yyyyMMddHHmmss'Z'" format
DerValue.newUTCTime(Date date)             // "yyMMddHHmmss'Z'" format
DerValue.newNull()                         // Tag.Null with empty body
DerValue.newASCIIString(String s)          // Tag.PrintableString
DerValue.newUTF8String(String s)           // Tag.UTFString (0x0C)
DerValue.getBitStringBytes()               // strips padding byte, returns raw bytes
```

**Tag constants** (need adding):
```java
Tag.UTFString = 12          // UTF-8 string
Tag.GeneralizedTime = 24    // GeneralizedTime (dates >= 2050)
// Set and Sequence already exist but need constructed-form bit set:
Tag.Set = 17 | 0b00100000      // always constructed
Tag.Sequence = 16 | 0b00100000 // always constructed
```

**ObjectIdentifier.encode(String)** -- converts dot-notation OID string to DER byte array. The branch implementation handles the first two components (40*a + b encoding) and multi-byte encoding for components >= 128. Needs review for components >= 16384 (three-byte encoding).

**New OIDs needed:**
```java
ObjectIdentifier.X_520_DN_COMMON_NAME = "2.5.4.3"  // CN
// Plus for broader DN support:
// 2.5.4.6   (C - Country)
// 2.5.4.7   (L - Locality)
// 2.5.4.8   (ST - State)
// 2.5.4.10  (O - Organization)
// 2.5.4.11  (OU - Organizational Unit)
```

**X.509 Certificate Generation** (from `KeyUtils.generateX509CertificateFromKey`):

The branch builds TBSCertificate as a DER SEQUENCE following RFC 5280:

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}

TBSCertificate ::= SEQUENCE {
    version         [0] EXPLICIT Version DEFAULT v1,     -- context tag 0xA0
    serialNumber        CertificateSerialNumber,         -- INTEGER
    signature           AlgorithmIdentifier,             -- SEQUENCE { OID, NULL }
    issuer              Name,                            -- SEQUENCE { SET { SEQUENCE { OID, PrintableString } } }
    validity            Validity,                        -- SEQUENCE { UTCTime, UTCTime }
    subject             Name,                            -- same as issuer for self-signed
    subjectPublicKeyInfo SubjectPublicKeyInfo            -- raw bytes from PublicKey.getEncoded()
}
```

The branch constructs this with nested `DerOutputStream` calls. The approach is correct but incomplete:
- Signing works (uses `java.security.Signature`) but the algorithm is hardcoded
- Time encoding uses UTCTime for dates before 2050, GeneralizedTime after (per RFC 5280)
- The result is passed back through `CertificateFactory` to get an `X509Certificate` object -- this is acceptable since CertificateFactory is standard JDK, not private API. The goal is to avoid private classes for *construction*, not necessarily for the return type.
- Missing: EC-specific algorithm identifier sequences (EC uses the curve OID alongside the algorithm OID, not NULL)
- Missing: EdDSA support
- Missing: Extensions (v3 certificates)

### Enhancements

**DER Infrastructure (port from moreDerEncoding + new work):**

| Class | Enhancement |
|-------|-------------|
| `DerValue` | Add factory methods: `newBitString()`, `newUTCTime()`, `newGeneralizedTime()`, `newNull()`, `newASCIIString()`, `newUTF8String()`. Add `getBitStringBytes()`. Add constructor `DerValue(Tag, DerOutputStream)`. Use `Instant` instead of `Date` for time methods (align with the rest of 7.0). |
| `DerOutputStream` | Add `writeValue(byte[])` for raw byte injection (needed for `PublicKey.getEncoded()` passthrough). |
| `DerInputStream` | Handle zero-length values gracefully (the branch fixed a bug where `length == 0` caused a read failure). |
| `Tag` | Add `GeneralizedTime = 24`, `UTFString = 12`. Verify `Set` and `Sequence` constants have the constructed bit set. |
| `ObjectIdentifier` | Add `encode(String)` for dot-notation to DER bytes. Add `X_520_DN_COMMON_NAME` and other DN attribute OIDs. Review multi-byte encoding for large component values. |

**X.509 Certificate Generation:**

Build self-signed or CA-signed certificates from components. API:

```java
public class X509CertificateBuilder {
    public X509CertificateBuilder serialNumber(BigInteger serial) { ... }
    public X509CertificateBuilder issuer(String commonName) { ... }
    public X509CertificateBuilder subject(String commonName) { ... }
    public X509CertificateBuilder validity(Instant notBefore, Instant notAfter) { ... }
    public X509CertificateBuilder publicKey(PublicKey key) { ... }

    /** Build the DER-encoded certificate, sign it, return PEM string. */
    public String buildPEM(PrivateKey signingKey, Algorithm signatureAlgorithm) { ... }

    /** Build and return an X509Certificate object via CertificateFactory. */
    public X509Certificate build(PrivateKey signingKey, Algorithm signatureAlgorithm) { ... }
}
```

Supported signature algorithms: RS256, RS384, RS512, ES256, ES384, ES512, Ed25519, Ed448, PS256, PS384, PS512.

The `build()` method constructs TBSCertificate DER, signs with `java.security.Signature`, wraps in the outer Certificate SEQUENCE, and optionally parses via `CertificateFactory` to return `X509Certificate`. Using CertificateFactory for the return type is acceptable -- it's standard JDK API, not private.

**X.509 Certificate Parsing (DER -> structured fields):**

Parse TBSCertificate fields from DER-encoded certificate bytes without `CertificateFactory`:

- Version, serial number, signature algorithm
- Issuer and subject distinguished names
- Validity period (notBefore, notAfter)
- Subject public key info -> `PublicKey` (via `KeyFactory` + `X509EncodedKeySpec`, standard JDK)

Primary use case: extracting the public key and metadata from PEM-encoded certificates in environments where `CertificateFactory` may not be desirable or for round-trip fidelity.

### Scope

The goal is to handle the common X.509 use cases in JWT/JWK workflows -- generating self-signed certificates, extracting public keys from certificates, and `x5c` chain handling. Full PKIX path validation, CRL/OCSP checking, and v3 extensions are out of scope for 7.0 but the DER infrastructure should be extensible enough to add them later.

## 10. JWTUtils

`JWTUtils` remains as a utility class. Two methods move, the rest stay:

**Moved:**
- `decodePayload(String)` -> `JWTDecoder.decodeUnsecured(String)` (see [Section 5](#5-encoder--decoder))
- `decodeHeader(String)` -> `JWTDecoder.decodeUnsecured(String)` returns a JWT with the header populated, making a separate header-only decode unnecessary.

**Stays in JWTUtils (updated to use JSONProcessor where needed):**
- Key generation: `generate2048_RSAKeyPair()`, `generate3072_RSAKeyPair()`, `generate4096_RSAKeyPair()`, `generate2048_RSAPSSKeyPair()`, `generate3072_RSAPSSKeyPair()`, `generate4096_RSAPSSKeyPair()`, `generate256_ECKeyPair()`, `generate384_ECKeyPair()`, `generate521_ECKeyPair()`, `generate_ed25519_EdDSAKeyPair()`, `generate_ed448_EdDSAKeyPair()`
- HMAC secret generation: `generateSHA256_HMACSecret()`, `generateSHA384_HMACSecret()`, `generateSHA512_HMACSecret()`
- JWK thumbprints: `generateJWS_kid()`, `generateJWS_kid_S256()` -- these currently use `Mapper.serialize()` internally and must be updated to use `JSONProcessor` via `JWTConfig.resolve()`
- X.509 thumbprints: `generateJWS_x5t()` (4 overloads) -- pure byte/hash operations, no JSON changes needed
- Fingerprint conversion: `convertFingerprintToThumbprint()`, `convertThumbprintToFingerprint()` -- no changes needed
- Random generation: `generateSecureRandom()` -- no changes needed

## 11. Exception Hierarchy

The existing exception hierarchy is preserved. One new exception is added:

| Exception | Parent | Purpose |
|-----------|--------|---------|
| `JSONProcessingException` | `JWTException` | JSON serialization/deserialization failures. Thrown by `JSONProcessor` implementations. |

All existing exceptions remain unchanged:

- `JWTException` (base, extends `RuntimeException`)
- `InvalidJWTException`, `InvalidJWTSignatureException`, `InvalidKeyLengthException`, `InvalidKeyTypeException`
- `JWTExpiredException`, `JWTUnavailableForProcessingException`
- `JWTSigningException`, `JWTVerifierException`
- `MissingSignatureException`, `MissingVerifierException`
- `MissingPrivateKeyException`, `MissingPublicKeyException`
- `ResponseTooLargeException`
- `DerDecodingException`, `DerEncodingException`
- `PEMDecoderException`, `PEMEncoderException`
- `JSONWebKeyBuilderException`, `JSONWebKeyParserException`

`equals`/`hashCode` on JWT and Header should be verified after field/type changes but the existing implementations carry forward with updated field names and types.

## 12. Migration Summary

### Files to rewrite

| File | Change |
|------|--------|
| `Algorithm.java` | Enum -> Interface + `StandardAlgorithm` |
| `KeyType.java` | Enum -> Interface + `StandardKeyType` |
| `JWT.java` | Remove annotations, immutable builder, `Instant` times, long English names (fluent, no `get`/`set` prefix), remove `getEncoder()`/`getDecoder()`, remove `decodeUnsecured()` |
| `Header.java` | Remove annotations, immutable builder, `parameters()` naming |
| `JWTUtils.java` | Move decode methods to `JWTDecoder`, update `generateJWS_kid` to use `JSONProcessor` |
| `JWTEncoder.java` | Use `JSONProcessor` via `JWTConfig.resolve()` instead of `Mapper` |
| `JWTDecoder.java` | Use `JSONProcessor`, `Instant` for time validation, `Duration` for clock skew, constructor-based config (final fields), add `decodeUnsecured()`, simplified overloads, optional validator, `crit` header validation, builder for advanced config |
| `TimeMachineJWTDecoder.java` | Update to use `Instant` instead of `ZonedDateTime` |
| `JSONWebKey.java` | Remove annotations, immutable builder, `customParameters` naming, explicit `x5t#S256` map handling, remove `Buildable<T>` |
| `JSONWebKeyBuilder.java` | Use `JSONProcessor` instead of `Mapper` |
| `JSONWebKeyParser.java` | Use `JSONProcessor` instead of `Mapper` |
| `JSONWebKeySetHelper.java` | Use `JSONProcessor` instead of `JsonNode` |
| `AuthorizationServerMetaData.java` | Remove annotations, immutable builder |
| `OpenIDConnect.java` | Remove annotations, update for new patterns |
| `ServerMetaDataHelper.java` | Use `JSONProcessor` |
| All Signer/Verifier classes | Use `Algorithm` interface instead of enum, `sign(byte[])` instead of `sign(String)` |
| `PEMDecoder.java` | Add DER-based X.509 certificate parsing, reduce `CertificateFactory` dependency |
| `PEMEncoder.java` | Add DER-based X.509 certificate generation |
| DER classes | Enhancements for X.509 structure support (time types, context tags, etc.) |

### New files

| File | Purpose |
|------|---------|
| `JSONProcessor.java` | Strategy interface |
| `JSONProcessingException.java` | Exception for JSON processing failures |
| `LatteJSONProcessor.java` | Built-in JSON reader/writer |
| `JWTConfig.java` | Global configuration (default JSON processor) |
| `StandardAlgorithm.java` | Package-private `Algorithm` implementation |
| `StandardKeyType.java` | Package-private `KeyType` implementation |
| `Signers.java` | Dynamic signer factory for built-in algorithms |
| `Verifiers.java` | Dynamic verifier factory for built-in algorithms, `anyOf()` composite |
| `X509CertificateBuilder.java` | Build X.509 certificates via DER without private JDK classes |

### Deleted files

| File | Reason |
|------|--------|
| `json/Mapper.java` | Replaced by `JSONProcessor` |
| `json/JacksonModule.java` | No longer needed |
| `json/ZonedDateTimeSerializer.java` | No longer needed |
| `json/ZonedDateTimeDeserializer.java` | No longer needed |
| `Buildable.java` | Replaced by `Builder` inner classes on JWT, Header, JSONWebKey |

### Dependency changes

**pom.xml:** Remove `jackson-core`, `jackson-databind`, `jackson-annotations` from compile dependencies. Jackson becomes test-only if we want to test the `JSONProcessor` integration path.

## 13. Performance Considerations

- **Map intermediary overhead:** Building a `LinkedHashMap` with ~7-10 entries is cheap (hundreds of nanoseconds). The trade-off vs. Jackson's reflection-based annotation processing is likely neutral or favorable for small payloads.
- **Built-in parser:** No reflection, no annotation processing, no module system. For JWT-sized payloads (~200-500 bytes of JSON), a hand-rolled parser can match or beat Jackson.
- **BigInteger/BigDecimal overhead:** Slightly more allocation than Long/Double, but negligible for JWT-sized payloads. The consistency benefit outweighs the cost.
- **Crypto dominates:** Signature operations (RSA, EC, HMAC) are orders of magnitude slower than JSON serialization. The JSON layer is not the bottleneck.
- **Benchmark plan:** Once implemented, benchmark against the current Jackson-based version and against other JWT libraries (JJWT, auth0, nimbus) for encode/decode throughput.

## 14. Test Plan

All tests should include a use-case comment at the top describing the scenario: `// Use case: <description>`.

### Unit Tests

**LatteJSONProcessor (critical -- new code):**
- // Use case: Round-trip serialization of every JSON type (object, array, string, integer, decimal, boolean, null)
- // Use case: Nested structures (objects within arrays within objects)
- // Use case: Unicode string escaping (multi-byte characters, control characters, surrogate pairs)
- // Use case: Empty objects and arrays
- // Use case: Large numbers (BigInteger beyond Long.MAX_VALUE, BigDecimal with high precision)
- // Use case: Malformed JSON input (unterminated strings, trailing commas, invalid escapes, truncated input)
- // Use case: JSON with duplicate keys (last-wins or reject -- decide and test)
- // Use case: Deeply nested structures (stack depth boundary)

**StandardAlgorithm / StandardKeyType:**
- // Use case: equals/hashCode contract -- two instances with the same name are equal
- // Use case: of() returns interned constant for standard names (reference equality with ==)
- // Use case: of() returns new instance for unknown names
- // Use case: Case sensitivity -- "rs256" vs "RS256" (decide behavior and test)

**JWT.Builder:**
- // Use case: Builder reusability -- build(), modify, build() again produces independent instances
- // Use case: claim("exp", numericValue) routes to exp field with type coercion
- // Use case: claim("exp", "not-a-number") throws IllegalArgumentException
- // Use case: claim("iss", stringValue) routes to iss field
- // Use case: claim("custom", value) stores in customClaims
- // Use case: Null claim values are omitted from build result

**JWT.fromMap():**
- // Use case: Time claim with Long value converts to Instant
- // Use case: Time claim with Integer value converts to Instant
- // Use case: Time claim with BigDecimal value converts to Instant
- // Use case: Time claim with String value throws InvalidJWTException
- // Use case: Unknown claims pass through to customClaims as-is
- // Use case: String claims (iss, sub, jti) with non-string values throw InvalidJWTException

**JWT.toSerializableMap():**
- // Use case: Instant values serialize to epoch seconds (long)
- // Use case: Null claims are omitted
- // Use case: Custom claims merge after registered claims, no collisions

**JWT claim accessors:**
- // Use case: getInteger() on BigInteger value returns narrowed int
- // Use case: getFloat() on BigDecimal value returns narrowed float
- // Use case: getNumber() on BigInteger returns the BigInteger directly (no coercion)
- // Use case: getObject() returns the raw value without coercion
- // Use case: getList("name", String.class) with all-String list returns typed List<String>
- // Use case: getList("name", String.class) with mixed-type list throws ClassCastException
- // Use case: getList("name") returns List<Object>
- // Use case: Accessor for missing claim returns null

**Header.Builder:**
- // Use case: parameter("alg", ...) or parameter("typ", ...) behavior (reject or override -- decide and test)
- // Use case: Custom parameters accessible via get() and parameters()

**Verifiers.anyOf():**
- // Use case: First matching verifier is used (ordered delegation)
- // Use case: No matching verifier throws MissingVerifierException
- // Use case: Single verifier behaves identically to direct use
- // Use case: Fail-fast -- first canVerify() match that fails verify() propagates exception, does not try next verifier

### Integration Tests

**Round-trip encode/decode for every algorithm:**
- // Use case: HS256/384/512 -- build JWT, encode with HMACSigner, decode with HMACVerifier, verify all claims preserved
- // Use case: RS256/384/512 -- same with RSA key pair
- // Use case: PS256/384/512 -- same with RSA-PSS key pair
- // Use case: ES256/384/512 -- same with EC key pair (P-256, P-384, P-521)
- // Use case: Ed25519 -- same with Ed25519 key pair
- // Use case: Ed448 -- same with Ed448 key pair

**Cross-processor compatibility:**
- // Use case: Encode with LatteJSONProcessor, decode with JacksonJSONProcessor -- claims match
- // Use case: Encode with JacksonJSONProcessor, decode with LatteJSONProcessor -- claims match
- // Use case: Custom claims with BigInteger/BigDecimal survive cross-processor round-trip

**Verifier selection strategies:**
- // Use case: Single verifier -- canVerify() checked, signature verified
- // Use case: Map<String, Verifier> -- kid-based lookup from header
- // Use case: Function<Header, Verifier> -- custom resolver using any header parameter
- // Use case: Verifiers.anyOf() -- composite with multiple algorithm types

**Post-decode validation:**
- // Use case: Validator that checks issuer -- accepted when correct, InvalidJWTException when wrong
- // Use case: Validator that checks audience -- accepted when present, rejected when missing

**Signers/Verifiers factory:**
- // Use case: Signers.forAlgorithm(HS256, secret) creates HMACSigner
- // Use case: Signers.forAlgorithm(RS256, pemString) creates RSASigner from PEM
- // Use case: Signers.forAlgorithm(ES256, privateKey) creates ECSigner from PrivateKey
- // Use case: Verifiers.forAlgorithm(RS256, publicKey) creates RSAVerifier

**Unsecured decode:**
- // Use case: decodeUnsecured() parses claims and header without signature verification
- // Use case: decodeUnsecured() on a signed token returns claims (signature ignored)
- // Use case: decodeUnsecured() on malformed input throws InvalidJWTException

### Security Tests

- // Use case: Algorithm "none" attack -- token with alg:none rejected with MissingVerifierException
- // Use case: Algorithm confusion -- RSA public key material used as HMAC secret (must reject)
- // Use case: Missing signature segment -- two-part token rejected with MissingSignatureException
- // Use case: Tampered payload -- valid header/signature with modified payload fails verification
- // Use case: Expired token rejected with JWTExpiredException
- // Use case: Not-yet-valid token rejected with JWTUnavailableForProcessingException
- // Use case: Clock skew allows slightly expired token when configured
- // Use case: Token with crit header listing unknown parameter -- rejected with InvalidJWTException
- // Use case: Token with crit header listing parameter registered via criticalHeaders -- accepted
- // Use case: Token with empty crit array -- accepted (no critical parameters to check)
- // Use case: Map<String, Verifier> with missing kid in header -- rejected with MissingVerifierException
- // Use case: Map<String, Verifier> with unrecognized kid -- rejected with MissingVerifierException

### Wire-format Compatibility Tests

- // Use case: Token encoded by 6.x library decoded by 7.0 -- wire format is unchanged
- // Use case: Tokens from other libraries (JJWT, auth0, nimbus) decode correctly
- // Use case: RFC 7515 Appendix A test vectors verify correctly
- // Use case: JWT re-serialized from decoded claims produces identical payload JSON

### JSONWebKey Tests

- // Use case: JSONWebKey round-trip -- build from PEM, serialize to JSON, parse back
- // Use case: x5t#S256 field maps to "x5t#S256" key in serialized JSON
- // Use case: fromMap() with "x5t#S256" key populates x5t_256 field
- // Use case: JWKS endpoint response with mixed key types (RSA, EC, oct) parses without error
- // Use case: KeyType.OCT entries in JWKS response parse the kty field correctly

### X.509 / DER Tests

- // Use case: X509CertificateBuilder generates valid self-signed cert for each supported algorithm
- // Use case: Generated certificate parses back via CertificateFactory
- // Use case: DerValue factory methods round-trip (newBitString -> getBitStringBytes)
- // Use case: newUTCTime for dates before 2050, newGeneralizedTime for dates after 2050
- // Use case: OID encoding for single-byte, two-byte, and three-byte component values
- // Use case: Zero-length DER values handled gracefully by DerInputStream
