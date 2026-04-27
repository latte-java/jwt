## Java JWT ![semver 2.0.0 compliant](https://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square) [![Tests](https://github.com/latte-java/jwt/actions/workflows/test.yml/badge.svg)](https://github.com/latte-java/jwt/actions/workflows/test.yml)
Java JWT is intended to be fast and easy to use. It has zero external runtime dependencies — no Jackson, no Bouncy Castle, no Apache Commons, no Guava. Pure Java — just add a VM.

## Features
 - JWT signing using the following algorithms
   - `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES256K`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `Ed25519`, `Ed448`
     - `Ed25519` and `Ed448` use fully-specified JOSE names; the legacy `EdDSA` header value is not accepted out of the box. See [Ed25519 and Ed448 interop notes](#ed25519-and-ed448-interop-notes) below.
 - Support for Bouncy Castle JCE or other third party providers.   
 - PEM decoding / encoding
   - Decode PEM files to PrivateKey or PublicKey
     - Decode private EC keys un-encapsulated in PKCS#8, returned PEM will be in PKCS#8 form.
     - Both public and private keys will be returned when encoded in the private PEM
   - Encode PrivateKey or PublicKey to PEM
 - JSON Web Key 
   - Build JWK from Private Key
   - Build JWK from Public Key
   - Build JWK from PEM
   - Parse public keys from a JSON Web Key
   - Retrieve JWK from JWKS endpoints
 - X.509 Certificates
   - Build self-signed or CA-signed X.509 (v3) certificates
   - Parse certificates via the standard JDK `CertificateFactory`
 - Helpers
   - Generate RSA Key Pairs in `2048`, `3072` or `4096` bit sizes
   - Generate RSA PSS Key Pairs in `2048`, `3072` or `4096` bit sizes
   - Generate EC Key Pairs in `256`, `384` and `521` bit sizes
   - Generate EdDSA Key Pairs for `Ed25519` and `Ed448` curves
   - Generate `x5t` and `x5t#S256` values from X.509 Certificates
   - Generate JWK thumbprint using `SHA-1` or `SHA-256` 
   - Generate ideal HMAC secret lengths for `SHA-256`, `SHA-384` and `SHA-512`
   - Generate the `at_hash` and `c_hash` claims for OpenID Connect

## Get it

### Maven
 ```xml
<dependency>
  <groupId>org.lattejava</groupId>
  <artifactId>latte-jwt</artifactId>
  <version>1.0.0</version>
</dependency>
 ```

### Gradle
```groovy
implementation 'org.lattejava:latte-jwt:1.0.0'
```

### Gradle Kotlin
```kotlin
implementation("org.lattejava:latte-jwt:1.0.0")
```

### Savant 
```groovy
dependency(id: "org.lattejava:latte-jwt:1.0.0")
```
 
## Performance

`latte-jwt` is the fastest pure-Java JWT library while remaining zero-dependency. Decoding and verifying an `RS256` token — the dominant cost in real OAuth/OIDC services — is the most-quoted comparison:

<!-- README:PERFORMANCE:START -->
### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 41204 | 100.0 % | 104.7 % |
| 2 | vertx-auth-jwt | 39737 | 96.4 % | 100.9 % |
| 3 | latte-jwt | 39366 | 95.5 % | 100.0 % |
| 4 | nimbus-jose-jwt | 36041 | 87.5 % | 91.6 % |
| 5 | jjwt | 33505 | 81.3 % | 85.1 % |
| 6 | fusionauth-jwt | 33476 | 81.2 % | 85.0 % |
| 7 | jose4j | 33355 | 81.0 % | 84.7 % |
| | _baseline (JCA)_ | _42100_ | _102.2 %_ | _106.9 %_ |
<!-- README:PERFORMANCE:END -->

Full methodology and per-algorithm leaderboards in [`benchmarks/BENCHMARKS.md`](benchmarks/BENCHMARKS.md).

## Example Code:

### JWT Signing and Verifying

The recommended entry points are the `Signers` and `Verifiers` factories. They take an `Algorithm` constant plus key material, and reject the wrong key type for the wrong family (e.g. passing a private key to `forHMAC`) so a misplaced key can't be silently coerced into the wrong algorithm family. A `Signer` or `Verifier` is safe to reuse and safe to share across threads.

JWTs are built with an immutable fluent builder and serialized by a `JWTEncoder`. Decoding is done by a `JWTDecoder`, which takes a `VerifierResolver` — use `VerifierResolver.byKid(Map<String, Verifier>)` for a `kid`-indexed keyring, or `VerifierResolver.of(verifier)` to wrap a single verifier.

For the happy path, `JWT.decode(encodedJWT, verifier)` (and an `(encodedJWT, verifier, validator)` overload) routes through a shared default `JWTDecoder` so you don't have to construct one. The same overloads accept a `VerifierResolver` when you have a keyring. Build your own `JWTDecoder` with `JWTDecoder.builder()` when you need non-default settings — a custom `JSONProcessor`, `clockSkew`, allowed algorithms, `fixedTime`, etc. — and pass it to the `JWT.decode(encodedJWT, decoder, verifier)` overload (or call `decoder.decode(...)` directly).

#### Sign and encode a JWT using HMAC
```java
// Generate and persist a secret; the verifier needs the same value.
String secret = HMACSecrets.generateSHA256();

// Build an HMAC signer for HS256
Signer signer = Signers.forHMAC(Algorithm.HS256, secret);

// Build a JWT with issuer (iss), issued-at (iat), subject (sub) and expiration (exp)
JWT jwt = JWT.builder()
             .issuer("www.acme.com")
             .issuedAt(Instant.now())
             .subject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
             .expiresAt(Instant.now().plusSeconds(3600))
             .build();

// Sign and encode the JWT to its compact JWS string representation
String encodedJWT = new JWTEncoder().encode(jwt, signer);
```

A higher-strength hash can be used by passing a different algorithm. Use the matching generator so the secret matches the digest size. The encoding and decoding steps are unchanged.
```java
String secret384 = HMACSecrets.generateSHA384();
Signer signer384 = Signers.forHMAC(Algorithm.HS384, secret384);

String secret512 = HMACSecrets.generateSHA512();
Signer signer512 = Signers.forHMAC(Algorithm.HS512, secret512);
```

Alternate: `HMACSigner.newSHA256Signer(secret)` is the family-specific static factory.

#### Verify and decode a JWT using HMAC
```java
// Build an HMAC verifier using the same secret that was used to sign the JWT
Verifier verifier = Verifiers.forHMAC(Algorithm.HS256, secret);

// Verify and decode the encoded string JWT to a rich object
JWT jwt = JWT.decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject(), "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

For a `kid`-indexed keyring or any other multi-key arrangement, pass a `VerifierResolver` instead — `JWT.decode(encodedJWT, VerifierResolver.byKid(Map<String, Verifier>))`.

Alternate: `HMACVerifier.newVerifier(secret)` produces the same verifier.

#### Sign and encode a JWT using RSA
```java
// Build an RSA signer from a PEM-encoded private key. A PrivateKey object may be passed instead.
String pemPrivateKey = Files.readString(Paths.get("private_key.pem"));
Signer signer = Signers.forAsymmetric(Algorithm.RS256, pemPrivateKey);

JWT jwt = JWT.builder()
             .issuer("www.acme.com")
             .issuedAt(Instant.now())
             .subject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
             .expiresAt(Instant.now().plusSeconds(3600))
             .build();

String encodedJWT = new JWTEncoder().encode(jwt, signer);
```

A higher-strength hash can be used by passing a different algorithm. The encoding and decoding steps are unchanged.
```java
Signer signer384 = Signers.forAsymmetric(Algorithm.RS384, pemPrivateKey);
Signer signer512 = Signers.forAsymmetric(Algorithm.RS512, pemPrivateKey);
```

Alternate: `RSASigner.newSHA256Signer(pemPrivateKey)` (and the `SHA384` / `SHA512` variants) produce the same signer. PSS signatures are exposed as `Algorithm.PS256` / `PS384` / `PS512` through `Signers.forAsymmetric`, or via `RSAPSSSigner.newSHA256Signer(...)`.

#### Verify and decode a JWT using RSA
```java
// Build an RSA verifier from a PEM-encoded public key. A PublicKey object may be passed instead.
String pemPublicKey = Files.readString(Paths.get("public_key.pem"));
Verifier verifier = Verifiers.forAsymmetric(Algorithm.RS256, pemPublicKey);

// Verify and decode the encoded string JWT to a rich object
JWT jwt = JWT.decode(encodedJWT, verifier);

// Assert the subject of the JWT is as expected
assertEquals(jwt.subject(), "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

Alternate: `RSAVerifier.newVerifier(Paths.get("public_key.pem"))` is the family-specific factory.

#### Sign and encode a JWT using EC
```java
// Build an EC signer from a PEM-encoded private key. A PrivateKey object may be passed instead.
String pemPrivateKey = Files.readString(Paths.get("private_key.pem"));
Signer signer = Signers.forAsymmetric(Algorithm.ES256, pemPrivateKey);

JWT jwt = JWT.builder()
             .issuer("www.acme.com")
             .issuedAt(Instant.now())
             .subject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
             .expiresAt(Instant.now().plusSeconds(3600))
             .build();

String encodedJWT = new JWTEncoder().encode(jwt, signer);
```

A higher-strength hash can be used by passing a different algorithm. The encoding and decoding steps are unchanged.
```java
Signer signer384 = Signers.forAsymmetric(Algorithm.ES384, pemPrivateKey);
Signer signer512 = Signers.forAsymmetric(Algorithm.ES512, pemPrivateKey);
```

Alternate: `ECSigner.newSHA256Signer(pemPrivateKey)` (and the `SHA384` / `SHA512` variants) produce the same signer.

#### Verify and decode a JWT using EC
```java
// Build an EC verifier from a PEM-encoded public key. A PublicKey object may be passed instead.
String pemPublicKey = Files.readString(Paths.get("public_key.pem"));
Verifier verifier = Verifiers.forAsymmetric(Algorithm.ES256, pemPublicKey);

JWT jwt = JWT.decode(encodedJWT, verifier);

assertEquals(jwt.subject(), "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

Alternate: `ECVerifier.newVerifier(Paths.get("public_key.pem"))`.

#### Build your own JWTDecoder

The `JWT.decode(...)` static helpers route through a shared default decoder that uses the bundled zero-dependency `LatteJSONProcessor`. Build your own when you need a different `JSONProcessor` or any other non-default setting — `clockSkew`, `expectedAlgorithms`, `expectedType`, `criticalHeaders`, `maxInputBytes`, `fixedTime`, etc. The clock-skew and time-pinning examples below use the same builder.

`JSONProcessor` is a strategy interface — `serialize(Map)` / `deserialize(byte[])` — and **the library does not bundle a Jackson, Gson, or other third-party adapter**. To use one, write a small class that implements `JSONProcessor` and delegates to your JSON library of choice. Implementations must be stateless and thread-safe; the encoder and decoder may call them concurrently.

```java
// MyJacksonJSONProcessor is YOUR class -- a thin adapter you write that implements
// JSONProcessor and delegates to Jackson (or Gson, or any other JSON library).
// This library does not ship one; keeping it user-supplied is what lets the core
// stay zero-dependency at runtime.
JSONProcessor jsonProcessor = new MyJacksonJSONProcessor();

JWTDecoder decoder = JWTDecoder.builder()
                               .jsonProcessor(jsonProcessor)
                               .expectedAlgorithms(Set.of(Algorithm.RS256))
                               .build();

// Either pass the decoder to the JWT.decode helper:
JWT jwt = JWT.decode(encodedJWT, decoder, verifier);

// ...or call decoder.decode(...) directly. Both forms are equivalent (the
// decoder.decode instance method takes a VerifierResolver -- wrap with
// VerifierResolver.of(verifier) when you only have a single verifier).
```

#### Verify a JWT adjusting for Clock Skew
```java
Verifier verifier = Verifiers.forAsymmetric(Algorithm.ES256,
    Files.readString(Paths.get("public_key.pem")));

// Allow up to 60 seconds of clock skew when asserting 'exp' and 'nbf'.
JWTDecoder decoder = JWTDecoder.builder()
                               .clockSkew(Duration.ofSeconds(60))
                               .build();

JWT jwt = decoder.decode(encodedJWT, VerifierResolver.of(verifier));

assertEquals(jwt.subject(), "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```

A shorter equivalent: `new JWTDecoder(Duration.ofSeconds(60))`.

#### Verify tokens against a remote JWKS

For OIDC issuers that publish a JWKS, use `JWKS` to manage caching, refresh, and rotation:

```java
try (JWKS jwks = JWKS.fromIssuer("https://idp.example.com/").build()) {
    JWT jwt = JWT.decode(encodedJWT, jwks);
}
```

`JWKS` implements `VerifierResolver`, performs an initial synchronous load on `build()` (bounded by `refreshTimeout`), and refreshes on `kid` cache miss (singleflight-coalesced) or on a virtual-thread scheduler tick when `scheduledRefresh(true)` is set. Honors `Cache-Control: max-age` and `Retry-After` from the JWKS endpoint. Implements `AutoCloseable`; call `close()` in shutdown hooks or use try-with-resources.

Other entry points:
- `JWKS.fromWellKnown(url)` — fully-qualified discovery URL (e.g. `/.well-known/openid-configuration`).
- `JWKS.fromJWKS(url)` — direct JWKS endpoint, no discovery.
- `JWKS.fromConfiguration(cfg)` — use a pre-fetched `OpenIDConnectConfiguration`.
- `JWKS.of(jwk1, jwk2, ...)` — static in-memory keys (no HTTP, no scheduler).
- `JWKS.fetch(url)` — one-shot `List<JSONWebKey>` from a JWKS URL.

#### OIDC discovery

`OpenIDConnect.discover(issuer)` fetches the OpenID Connect Provider Metadata for a given issuer and returns a typed `OpenIDConnectConfiguration`:

```java
OpenIDConnectConfiguration cfg = OpenIDConnect.discover("https://accounts.google.com");
String jwksURI      = cfg.jwksURI();
String tokenEndpoint = cfg.tokenEndpoint();
List<String> sigAlgs = cfg.idTokenSigningAlgValuesSupported();
// cfg.otherClaims() holds any non-standard fields the provider returned
```

`discover(issuer)` enforces OIDC Discovery 1.0 §4.3 issuer-equality validation: the response's `issuer` field must match the input issuer (after single-trailing-slash normalization). If the issuers don't match, `OpenIDConnectException` is thrown.

For RFC 8414 OAuth-only servers — or when you already have the full well-known URL — use `OpenIDConnect.discoverFromWellKnown(wellKnownURL)`. Note that this overload does not perform issuer-equality validation, which is a security downgrade relative to `discover(issuer)`.

#### Per-instance hardening with FetchLimits

By default, `JWKS` and `OpenIDConnect.discover` apply conservative limits on response size, redirect count, and JSON parsing. You can tighten them per instance with `FetchLimits`:

```java
FetchLimits tight = FetchLimits.builder()
    .maxResponseBytes(64 * 1024)
    .maxRedirects(1)
    .build();

try (JWKS jwks = JWKS.fromIssuer("https://idp.example.com/").fetchLimits(tight).build()) {
    JWT jwt = JWT.decode(encodedJWT, jwks);
}
```

By default, redirects are confined to the same origin (scheme + host + port). Cross-origin redirects are rejected unless `FetchLimits.builder().allowCrossOriginRedirects(true)` is set — that opt-in is a deliberate security trade-off.

#### Fail-fast at boot

If you want the application to fail at startup when the initial JWKS fetch cannot complete, use `failFast(true)`:

```java
// Throws OpenIDConnectException (discovery failure) or JWKSFetchException (JWKS fetch failure) if the initial fetch fails.
JWKS jwks = JWKS.fromIssuer("https://idp.example.com/").failFast(true).build();
```

Without `failFast`, a failed initial fetch is silently tolerated and the `JWKS` starts with an empty key set, retrying on the next refresh tick or `kid` miss.

#### Verify an expired JWT by going back in time
Please only use this for testing or if you happen to be a time traveler.

If you have a hard-coded JWT in a test case that you want to validate, you can pin the decoder's notion of "now" to any `Instant` — past or future. Ideally you would generate a fresh JWT per test run so the expiration check passes naturally; this option exists when that isn't practical.

```java
Verifier verifier = Verifiers.forAsymmetric(Algorithm.ES256,
    Files.readString(Paths.get("public_key.pem")));

// Pin the decoder to a specific instant. Use ONLY in tests — never in production.
Instant thePast = Instant.parse("2019-01-01T00:00:00Z");
JWTDecoder timeMachine = JWTDecoder.builder()
                                   .fixedTime(thePast)
                                   .build();

JWT jwt = timeMachine.decode(encodedJWT, VerifierResolver.of(verifier));

assertEquals(jwt.subject(), "f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3");
```


### Enable a third party JCE provider sucha s Bouncy Castle

Once you have enabled an additional provider no change should be necessary to your code. 
 
```java
// Insert the provider ahead of the JCA.
Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
```

### FIPS observability for SHAKE256

The Ed448 OpenID Connect `at_hash` / `c_hash` paths use FIPS 202 SHAKE256. On the first call, the library probes the JCE for a registered `SHAKE256` service and runs an internal known-answer test against it; on success the provider is cached and used for subsequent calls, otherwise the library falls back to a bundled FIPS 202 implementation. The bundled implementation is functionally correct but is not a FIPS-approved module.

Operators running under a FIPS-approved JCE can confirm which path is in use:

```java
import org.lattejava.jwt.internal.SHAKE256;

String name = SHAKE256.providerName();
// non-null  → name of the JCE provider that satisfied the KAT (e.g. "BCFIPS")
// null      → the bundled implementation is in use; not a FIPS-approved code path
```

This call triggers the one-time probe on first invocation, so the result is stable for the lifetime of the VM.

### Ed25519 and Ed448 interop notes

When using `Ed25519` or `Ed448`, the `alg` JWT header and the JWK `alg` property will be equal to the algorithm name. The legacy `EdDSA` value has been deprecated in JOSE in favor of the fully-specified algorithm names `Ed25519` and `Ed448`, and this library will not accept a JWT with `alg: EdDSA` out of the box.

If you need to interoperate with a producer that still emits `alg: EdDSA`, you can support it by implementing your own `Verifier`. The interface has just two methods — `canVerify(Algorithm)` and `verify(byte[], byte[])` — so a small delegating shim that accepts `EdDSA` and dispatches to the appropriate `Ed25519` or `Ed448` verifier is straightforward to write.

Wrap an `EdDSAVerifier` (which is already bound 1:1 to a single curve via its public key) and broaden `canVerify` to also recognize the `EdDSA` header value:

```java
import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.Verifier;
import org.lattejava.jwt.algorithm.ed.EdDSAVerifier;

// Accepts the legacy JOSE header value [alg: EdDSA] and delegates to the
// wrapped verifier. The wrapped EdDSAVerifier is locked to one curve at
// construction time (Ed25519 or Ed448, derived from the public key), so
// the shim cannot be coerced into using the wrong curve.
public final class EdDSAAliasVerifier implements Verifier {
  private final EdDSAVerifier delegate;

  public EdDSAAliasVerifier(EdDSAVerifier delegate) {
    this.delegate = delegate;
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return algorithm != null
        && ("EdDSA".equals(algorithm.name()) || delegate.canVerify(algorithm));
  }

  @Override
  public void verify(byte[] message, byte[] signature) {
    delegate.verify(message, signature);
  }
}
```

Use it the same way as any other `Verifier`:

```java
String pemPublicKey = Files.readString(Paths.get("ed25519_public_key.pem"));
Verifier verifier = new EdDSAAliasVerifier(EdDSAVerifier.newVerifier(pemPublicKey));

JWT jwt = JWT.decode(encodedJWT, verifier);
```

The shim accepts both the legacy `EdDSA` and the fully-specified `Ed25519` / `Ed448` header values. Tokens that carry an `alg` other than those three (or that are signed with the wrong curve) still fail at the JCA verify step.

## JSON Web Keys

### Retrieve JSON Web Keys from a JWKS endpoint

For a one-shot fetch (no caching, no refresh), use `JWKS.fetch`:

```java
// One-shot fetch from a known JWKS endpoint
List<JSONWebKey> keys = JWKS.fetch("https://www.googleapis.com/oauth2/v3/certs");

// One-shot fetch via OIDC Discovery — discover the JWKS URI, then fetch
OpenIDConnectConfiguration cfg = OpenIDConnect.discover("https://accounts.google.com");
List<JSONWebKey> discoveredKeys = JWKS.fetch(cfg.jwksURI());
```

For self-refreshing key management, use the `JWKS` builder API described above.

### Convert a Public Key to JWK

```java
JSONWebKey jwk = JSONWebKey.from(publicKey);
String json = jwk.toJSON();
```

```json
{
  "e": "AQAB",
  "kty": "RSA",
  "n": "Auchby3lZKHbiAZrTkJh79hJvgC3W7STSS4y6UZEhhxx3m3W2hD8qCyw6BEyrciPpwou-vmeDN7qBSk2QKqTTjlg5Pkf8O4z8d9HAlBTUDg4p98qLFOF2EFWWTiFbQwAP2qODOIv9WCAM2rkXEPwGiF962XAoOwiSmldeDu7Uo5A-bnTi0z3oNu4qm_48kv90o9CMiELszE9jsfoH32WE71HDqhsRjVNddDJ81e5zxBN8UEmaR-gmWqa63laON2KANPugJP7PrYJ_PC9ilQfV3F1rDpqbvlFQkshohJ39VrVpEtSRmJ12nqTFuspXLApekOyic3J9jo6ZI7o3IdQmy3bpnJIT_U",
  "use": "sig"
}
```

### Extract the Public Key from a JWK

```json
{
  "e": "AQAB",
  "kty": "RSA",
  "n": "Auchby3lZKHbiAZrTkJh79hJvgC3W7STSS4y6UZEhhxx3m3W2hD8qCyw6BEyrciPpwou-vmeDN7qBSk2QKqTTjlg5Pkf8O4z8d9HAlBTUDg4p98qLFOF2EFWWTiFbQwAP2qODOIv9WCAM2rkXEPwGiF962XAoOwiSmldeDu7Uo5A-bnTi0z3oNu4qm_48kv90o9CMiELszE9jsfoH32WE71HDqhsRjVNddDJ81e5zxBN8UEmaR-gmWqa63laON2KANPugJP7PrYJ_PC9ilQfV3F1rDpqbvlFQkshohJ39VrVpEtSRmJ12nqTFuspXLApekOyic3J9jo6ZI7o3IdQmy3bpnJIT_U",
  "use": "sig"
}
```

```java
String json = "{ ... example above ... }";
byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

// Any JSONProcessor can parse the bytes to a map; the bundled LatteJSONProcessor
// is used internally and has zero dependencies.
Map<String, Object> map = new LatteJSONProcessor().deserialize(bytes);
JSONWebKey jwk = JSONWebKey.fromMap(map);

PublicKey publicKey = JSONWebKey.parse(jwk);
```

### Convert a Private Key to JWK

```java
JSONWebKey jwk = JSONWebKey.from(privateKey);
String json = jwk.toJSON();
```

```json
{
  "p": "9dy6wUxA0eOHopUP-E5QjDzuW8rXdaQMR566oDJ1qL0iD0koQAB9X3hboB-2Rru0aATu6WDW-jd4mgtYnXO8ow",
  "kty": "RSA",
  "q": "6Nfc6c8meTRkVRAHCF24LB5GLfsjoMB0tOeEO9w9Ous1a4o-D24bAePMUImAp3woFoNDRfWtlNktOqLel5Pjew",
  "d": "C0G3QGI6OQ6tvbCNYGCqq043YI_8MiBl7C5dqbGZmx1ewdJBhMNJPStuckhskURaDwk4-8VBW9SlvcfSJJrnZhgFMjOYSSsBtPGBIMIdM5eSKbenCCjO8Tg0BUh_xa3CHST1W4RQ5rFXadZ9AeNtaGcWj2acmXNO3DVETXAX3x0",
  "e": "AQAB",
  "use": "sig",
  "qi": "XLE5O360x-MhsdFXx8Vwz4304-MJg-oGSJXCK_ZWYOB_FGXFRTfebxCsSYi0YwJo-oNu96bvZCuMplzRI1liZw",
  "dp": "32QGgDmjr9GX3N6p2wh1YWa_gMHmUSqUScLseUA_7eijeNYU70pCoCtAvVXzDYPhoJ3S4lQuIL2kI_tpMe8GFw",
  "dq": "21tJjqeN-k-mWhCwX2xTbpTSzsyy4uWMzUTy6aXxtUkTWY2yK70yClS-Df2MS70G0za0MPtjnUAAgSYhB7HWcw",
  "n": "359ZykLITko_McOOKAtpJRVkjS5itwZxzjQidW2X6tBEOYCH4LZbwfj8fGGvlUtzpyuwnYuIlNX8TvZLTenOk45pphXr5PMCMKi7YZgkhd6_t_oeHnXY-4bnDLF1r9OUFKwj6C-mFFM-woKc-62tuK6QJiuc-5bFfn9wRL15K1E"
}
```

### Add a custom property to a JWK

`JSONWebKey` is immutable; custom (non-registered) parameters are added through the builder using `parameter(name, value)`. Registered parameters (`kty`, `crv`, `alg`, `x`, `y`, `d`, `n`, `e`, etc.) must use their typed setters.

```java
JSONWebKey jwk = JSONWebKey.builder()
                           .kty(KeyType.EC)
                           .crv("P-256")
                           .alg(Algorithm.ES256)
                           .use("sig")
                           .x("NIWpsIea0qzB22S0utDG8dGFYqEInv9C7ZgZuKtwjno")
                           .y("iVFFtTgiInz_fjh-n1YqbibnUb2vtBZFs3wPpQw3mc0")
                           .parameter("boom", "goes the dynamite")
                           .parameter("more", "cowbell")
                           .build();
String json = jwk.toJSON();
```

```json
{
  "alg" : "ES256",
  "boom" : "goes the dynamite",
  "crv" : "P-256",
  "kty" : "EC",
  "more" : "cowbell",
  "use" : "sig",
  "x" : "NIWpsIea0qzB22S0utDG8dGFYqEInv9C7ZgZuKtwjno",
  "y" : "iVFFtTgiInz_fjh-n1YqbibnUb2vtBZFs3wPpQw3mc0"
}
```

## X.509 Certificates

Build an X.509 (v3) certificate. `X509.builder()` DER-encodes the certificate fields per RFC 5280, signs them with a `java.security.Signature` matching the requested JWA algorithm, and hands back a parsed `X509Certificate` via the standard JDK `CertificateFactory`.

Supported signature algorithms: `RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`, `ES256`/`ES384`/`ES512`, `Ed25519`, `Ed448`.

```java
// A self-signed EC certificate, valid for one year.
KeyPair keyPair = KeyPairs.generateEC_256();

X509Certificate cert = X509.builder()
                           .serialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                           .issuer("CN=www.acme.com, O=Acme, C=US")
                           .subject("CN=www.acme.com, O=Acme, C=US")
                           .validity(Instant.now(), Instant.now().plus(Duration.ofDays(365)))
                           .publicKey(keyPair.publicKey)
                           .signingKey(keyPair.privateKey)
                           .signatureAlgorithm(Algorithm.ES256)
                           .build();
```

For a CA-signed certificate, set `subject` to the subject DN, `issuer` to the CA's subject DN, `publicKey` to the subject's public key, and `signingKey` to the CA's private key.

Distinguished names are accepted as a comma-separated list of `ATTR=value` pairs (`CN`, `C`, `L`, `ST`, `O`, `OU`); full RFC 4514 DN parsing is not supported.

## License

Latte JWT is MIT licensed. Code derived from [fusionauth-jwt](https://github.com/FusionAuth/fusionauth-jwt) retains its Apache 2.0 license.

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT).

## Building

This project is built with [Savant](http://savantbuild.org/). The Maven coordinate above is for *consuming* the artifact — the build itself does not use Maven.

### Savant

```bash
$ sb int
```

**Note:** If you do not yet have Savant build tool installed, use the following instructions.

```bash
mkdir ~/savant
cd ~/savant
wget http://savant.inversoft.org/org/savantbuild/savant-core/2.0.2/savant-2.0.2.tar.gz
tar xvfz savant-2.0.2.tar.gz
ln -s ./savant-2.0.2 current
export PATH=$PATH:~/savant/current/bin/
```

For more information, checkout [savantbuild.org](http://savantbuild.org/).
