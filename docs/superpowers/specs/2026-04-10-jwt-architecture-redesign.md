# JWT Library Architecture Redesign

**Date:** 2026-04-10
**Version:** 7.0.0 (major breaking change)
**Scope:** Full library -- JWT core, JWK, OAuth2 metadata

## Design Goals

1. **Zero required dependencies.** Ship a built-in JSON parser. No Jackson, no Gson, nothing.
2. **Bring your own JSON.** A `JsonProcessor` strategy interface lets users plug in Jackson/Gson/etc.
3. **Spec-aligned types.** Time claims (`exp`, `nbf`, `iat`) use `Instant` instead of `ZonedDateTime`. No custom serializers needed.
4. **Performance.** The Map-based serialization path avoids reflection overhead. The built-in parser targets competitive performance with Jackson for small payloads (JWT-sized).
5. **Extensibility.** Algorithm as an interface (not enum). Strategy pattern for JSON. Clean builder APIs.
6. **Immutable models.** JWT and Header are immutable, built via builders. Thread-safe by construction.

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                   User Code                      │
│  JWT.builder().sub("user").exp(instant).build()  │
│  encoder.encode(jwt, signer)                     │
│  decoder.decode(token, verifier)                 │
└──────────┬──────────────────────┬────────────────┘
           │                      │
     ┌─────▼─────┐         ┌─────▼─────┐
     │ JWTEncoder │         │ JWTDecoder │
     └─────┬─────┘         └─────┬─────┘
           │                      │
     ┌─────▼──────────────────────▼─────┐
     │         JsonProcessor             │
     │  serialize(Map) / deserialize()   │
     └─────┬──────────────────────┬─────┘
           │                      │
  ┌────────▼────────┐   ┌────────▼────────┐
  │ LatteJsonProc.  │   │ User-provided   │
  │ (built-in,      │   │ (Jackson, Gson, │
  │  zero-dep)      │   │  etc.)          │
  └─────────────────┘   └─────────────────┘
```

## 1. Algorithm (Interface)

Replaces the current `Algorithm` enum. Extensible for custom algorithms.

```java
public interface Algorithm {
    /** JWA algorithm name, used in the JWT header "alg" field. */
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

    /** Look up by name. Returns a standard constant if matched, otherwise a new instance. */
    static Algorithm of(String name) { ... }
}
```

`StandardAlgorithm` is a package-private class with `equals`/`hashCode` based on `name()`.

Signer/Verifier implementations internally know their JCA algorithm strings. The `Algorithm` interface is purely the JWA identifier for the header -- it carries no crypto configuration.

Custom algorithms: `Algorithm.of("MY_ALG")` or implement the interface directly.

## 2. JWT (Immutable + Builder)

```java
public class JWT {
    // Registered claims -- spec names, spec-aligned types
    private final String iss;        // Issuer
    private final String sub;        // Subject
    private final Object aud;        // Audience: String or List<String>
    private final Instant exp;       // Expiration Time
    private final Instant nbf;       // Not Before
    private final Instant iat;       // Issued At
    private final String jti;        // JWT ID
    private final Map<String, Object> otherClaims;

    // Header -- populated on decode, not serialized with claims
    private final Header header;

    // --- Fluent getters (no "get" prefix) ---
    public String iss() { ... }
    public String sub() { ... }
    public Object aud() { ... }
    public Instant exp() { ... }
    public Instant nbf() { ... }
    public Instant iat() { ... }
    public String jti() { ... }
    public Header header() { ... }

    // --- Custom claim accessors ---
    public String getString(String name) { ... }
    public Integer getInteger(String name) { ... }
    public Long getLong(String name) { ... }
    public Boolean getBoolean(String name) { ... }
    public Double getDouble(String name) { ... }
    public BigDecimal getBigDecimal(String name) { ... }
    public <T> List<T> getList(String name) { ... }
    public Map<String, Object> getMap(String name) { ... }
    public Object get(String name) { ... }

    // --- Maps ---
    /** All claims (registered + custom) with raw Java types (Instant, etc.). */
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

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        public Builder iss(String issuer) { ... }
        public Builder sub(String subject) { ... }
        public Builder aud(Object audience) { ... }
        public Builder exp(Instant expiration) { ... }
        public Builder exp(long epochSeconds) { ... }
        public Builder nbf(Instant notBefore) { ... }
        public Builder nbf(long epochSeconds) { ... }
        public Builder iat(Instant issuedAt) { ... }
        public Builder iat(long epochSeconds) { ... }
        public Builder jti(String jwtId) { ... }
        public Builder claim(String name, Object value) { ... }
        public JWT build() { ... }
    }
}
```

### Key changes from current

| Aspect | Current (6.x) | New (7.0) |
|--------|---------------|-----------|
| Fields | `subject`, `issuer`, `expiration` | `sub`, `iss`, `exp` |
| Time type | `ZonedDateTime` | `Instant` (+ `long` builder overloads) |
| Mutability | Mutable POJO with setters | Immutable, builder pattern |
| Annotations | `@JsonProperty`, `@JsonSerialize`, etc. | None |
| Serialization | Jackson ObjectMapper directly | `toSerializableMap()` -> `JsonProcessor` |

## 3. Header (Immutable + Builder)

```java
public class Header {
    private final Algorithm alg;
    private final String typ;       // default "JWT"
    private final String kid;
    private final Map<String, Object> properties;  // additional header params

    // Fluent getters
    public Algorithm alg() { ... }
    public String typ() { ... }
    public String kid() { ... }
    public Object get(String name) { ... }

    // Maps
    public Map<String, Object> claims() { ... }
    public Map<String, Object> toSerializableMap() { ... }

    // Factory
    public static Header fromMap(Map<String, Object> map) { ... }

    public static Builder builder() { ... }

    public static class Builder {
        public Builder alg(Algorithm algorithm) { ... }
        public Builder typ(String type) { ... }
        public Builder kid(String keyId) { ... }
        public Builder property(String name, Object value) { ... }
        public Header build() { ... }
    }
}
```

## 4. JsonProcessor (Strategy Interface)

```java
public interface JsonProcessor {
    byte[] serialize(Map<String, Object> object);
    Map<String, Object> deserialize(byte[] json);
}
```

### Configuration

Three ways to configure, in order of precedence:

1. **Constructor injection** (highest): `new JWTEncoder(myProcessor)`
2. **Global default**: `JWT.setDefaultJsonProcessor(myProcessor)`
3. **Built-in fallback** (lowest): `LatteJsonProcessor` -- always available, zero dependencies

```java
// Simplest usage -- built-in parser, zero config
JWTEncoder encoder = new JWTEncoder();
JWTDecoder decoder = new JWTDecoder();

// Global override -- set once at startup
JWT.setDefaultJsonProcessor(new JacksonJsonProcessor());

// Per-instance override -- takes precedence over global
JWTEncoder encoder = new JWTEncoder(new GsonJsonProcessor());
```

### Built-in Implementation

`LatteJsonProcessor` -- a hand-rolled JSON reader + writer.

**Writer:** Iterates map entries, writes JSON with proper string escaping, handles nested maps/lists recursively. No intermediate allocations beyond the output buffer.

**Reader:** Recursive descent parser. Dispatches on first character: `{` (object), `[` (array), `"` (string), digit/`-` (number), `t`/`f` (boolean), `n` (null).

**Number handling:** Parse as `Long` if no decimal point and fits in long range. Otherwise `BigDecimal`. Preserves precision for custom claims.

**JSON type mapping:**

| JSON | Java |
|------|------|
| object | `LinkedHashMap<String, Object>` |
| array | `ArrayList<Object>` |
| string | `String` |
| integer number | `Long` |
| decimal number | `BigDecimal` |
| boolean | `Boolean` |
| null | `null` |

**Target size:** ~500-800 lines across `JsonReader` + `JsonWriter`.

### User-provided Example (Jackson)

```java
public class JacksonJsonProcessor implements JsonProcessor {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public byte[] serialize(Map<String, Object> object) {
        try {
            return mapper.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            throw new JWTException("JSON serialization failed", e);
        }
    }

    @Override
    public Map<String, Object> deserialize(byte[] json) {
        try {
            return mapper.readValue(json, new TypeReference<>() {});
        } catch (IOException e) {
            throw new JWTException("JSON deserialization failed", e);
        }
    }
}
```

## 5. Encoder / Decoder

```java
public class JWTEncoder {
    private final JsonProcessor jsonProcessor;

    public JWTEncoder() { /* resolves: constructor-provided > global > built-in */ }
    public JWTEncoder(JsonProcessor jsonProcessor) { ... }

    public String encode(JWT jwt, Signer signer) { ... }
    public String encode(JWT jwt, Signer signer, Header header) { ... }
    public String encode(JWT jwt, Signer signer, Consumer<Header.Builder> consumer) { ... }
}

public class JWTDecoder {
    private final JsonProcessor jsonProcessor;
    private int clockSkew;

    public JWTDecoder() { ... }
    public JWTDecoder(JsonProcessor jsonProcessor) { ... }

    public JWTDecoder withClockSkew(int seconds) { ... }

    public JWT decode(String encodedJWT, Verifier... verifiers) { ... }
    public JWT decode(String encodedJWT, Map<String, Verifier> verifiers) { ... }
    public JWT decode(String encodedJWT, Function<String, Verifier> fn) { ... }
}
```

### Encode Flow

1. Build `Header` from Signer's algorithm + kid (+ user customization)
2. `header.toSerializableMap()` → `jsonProcessor.serialize()` → Base64URL encode
3. `jwt.toSerializableMap()` → `jsonProcessor.serialize()` → Base64URL encode
4. Concatenate `encodedHeader.encodedPayload`
5. `signer.sign(message)` → Base64URL encode
6. Return `encodedHeader.encodedPayload.encodedSignature`

### Decode Flow

1. Split on `.` → `[headerB64, payloadB64, signatureB64]`
2. Base64URL decode header → `jsonProcessor.deserialize()` → `Header.fromMap()`
3. Select verifier (by algorithm, kid, or function)
4. Verify signature against `headerB64.payloadB64`
5. Base64URL decode payload → `jsonProcessor.deserialize()` → `JWT.fromMap()`
   - `fromMap()` converts `Number` values in `exp`/`nbf`/`iat` to `Instant`
6. Validate `exp`/`nbf` with clock skew
7. Return `JWT`

## 6. Signer / Verifier

```java
public interface Signer {
    Algorithm algorithm();
    byte[] sign(byte[] payload);
    default String kid() {
        throw new UnsupportedOperationException();
    }
}

public interface Verifier {
    boolean canVerify(Algorithm algorithm);
    void verify(Algorithm algorithm, byte[] message, byte[] signature);
}
```

Implementations keep the same factory method patterns for now:

```java
HMACSigner.newSHA256Signer(String secret)
HMACSigner.newSHA256Signer(String secret, String kid)
RSASigner.newSHA256Signer(String pemPrivateKey)
// etc.
```

> **REVISIT: Signer/Verifier Factory API**
>
> The current factory method pattern (`HMACSigner.newSHA256Signer()`, `RSASigner.newSHA384Signer()`, etc.) has maintenance and usability problems:
>
> - **Maintenance burden:** Every new algorithm variant requires new factory methods across signer + verifier + tests. The combinatorial explosion of `new<Hash>Signer(secret)`, `new<Hash>Signer(secret, kid)`, `new<Hash>Signer(byte[])`, `new<Hash>Signer(byte[], kid)` is tedious.
> - **Dynamic usage is awkward:** If a user has an `Algorithm` value at runtime (e.g., from a config file or JWK), they can't pass it to a factory -- they need a switch statement to select the right `newSHA*Signer()` method.
> - **Discoverability:** New users must know which class to look at and which factory method to call.
>
> **Potential alternatives to explore:**
> - **Unified factory:** `Signer.forAlgorithm(Algorithm.HS256, secret)` or `Signer.builder().algorithm(Algorithm.RS256).privateKey(pem).kid("key1").build()`
> - **How other libraries do it:** JJWT uses `Jwts.SIG.RS256.keyPair().build()` for key generation and the algorithm object directly for signing. Auth0 uses `Algorithm.RSA256(publicKey, privateKey)`. Nimbus separates key management from algorithm selection entirely.
> - **Goal:** A user with an `Algorithm` value and key material should be able to construct the right signer in one call without a switch statement.
>
> This should be investigated and designed as part of implementation planning.

## 7. JWK / OAuth2

Same pattern as JWT -- remove Jackson annotations, use `Map<String, Object>` + `JsonProcessor`.

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
    private final Map<String, Object> other;

    public Map<String, Object> claims() { ... }
    public Map<String, Object> toSerializableMap() { ... }
    public static JSONWebKey fromMap(Map<String, Object> map) { ... }
    public static Builder builder() { ... }
}
```

### JSONWebKeySetHelper

Currently uses `JsonNode` for HTTP response tree parsing. Switches to `JsonProcessor.deserialize()` returning `Map<String, Object>`, then navigates with standard map operations:

```java
// Before (Jackson JsonNode)
JsonNode response = Mapper.deserialize(is, JsonNode.class);
JsonNode jwksUri = response.at("/jwks_uri");

// After (Map)
Map<String, Object> response = jsonProcessor.deserialize(bytes);
String jwksUri = (String) response.get("jwks_uri");
```

### AuthorizationServerMetaData

Same pattern -- builder, `fromMap()`, no annotations.

## 8. Migration Summary

### Files to rewrite

| File | Change |
|------|--------|
| `Algorithm.java` | Enum → Interface + `StandardAlgorithm` |
| `JWT.java` | Remove annotations, immutable builder, `Instant` times, spec field names |
| `Header.java` | Remove annotations, immutable builder |
| `Mapper.java` | **Delete** -- replaced by `JsonProcessor` |
| `JacksonModule.java` | **Delete** -- no longer needed |
| `ZonedDateTimeSerializer.java` | **Delete** -- `Instant` + `toSerializableMap()` handles this |
| `ZonedDateTimeDeserializer.java` | **Delete** -- `fromMap()` handles this |
| `JWTEncoder.java` | Use `JsonProcessor` instead of `Mapper` |
| `JWTDecoder.java` | Use `JsonProcessor` instead of `Mapper`, `Instant` for time validation |
| `TimeMachineJWTDecoder.java` | Update to use `Instant` instead of `ZonedDateTime` |
| `JSONWebKey.java` | Remove annotations, immutable builder |
| `JSONWebKeySetHelper.java` | Use `JsonProcessor` instead of `JsonNode` |
| `AuthorizationServerMetaData.java` | Remove annotations, immutable builder |
| `ServerMetaDataHelper.java` | Use `JsonProcessor` |
| All Signer/Verifier classes | Use `Algorithm` interface instead of enum |

### New files

| File | Purpose |
|------|---------|
| `JsonProcessor.java` | Strategy interface |
| `LatteJsonProcessor.java` | Built-in JSON reader/writer |
| `StandardAlgorithm.java` | Package-private `Algorithm` implementation |

### Deleted files

| File | Reason |
|------|--------|
| `json/Mapper.java` | Replaced by `JsonProcessor` |
| `json/JacksonModule.java` | No longer needed |
| `json/ZonedDateTimeSerializer.java` | No longer needed |
| `json/ZonedDateTimeDeserializer.java` | No longer needed |

### Dependency changes

**pom.xml:** Remove `jackson-core`, `jackson-databind`, `jackson-annotations` from compile dependencies. Jackson becomes test-only if we want to test the `JsonProcessor` integration path.

## 9. Performance Considerations

- **Map intermediary overhead:** Building a `LinkedHashMap` with ~7-10 entries is cheap (hundreds of nanoseconds). The trade-off vs. Jackson's reflection-based annotation processing is likely neutral or favorable for small payloads.
- **Built-in parser:** No reflection, no annotation processing, no module system. For JWT-sized payloads (~200-500 bytes of JSON), a hand-rolled parser can match or beat Jackson.
- **Crypto dominates:** Signature operations (RSA, EC, HMAC) are orders of magnitude slower than JSON serialization. The JSON layer is not the bottleneck.
- **Benchmark plan:** Once implemented, benchmark against the current Jackson-based version and against other JWT libraries (JJWT, auth0, nimbus) for encode/decode throughput.
