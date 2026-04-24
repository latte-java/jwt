# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build system

This project is built with the Latte CLI (`latte`), not Maven and not Savant. Ignore `.github/workflows/test.yml` — it references `mvn verify` but is stale; the authoritative build is `project.latte`. Compile target is Java 21.

Common targets (run from the repo root):

```
latte clean      # delete build/
latte build      # compile + jar
latte test       # build, then run TestNG twice: once with JCA default, once with BouncyCastle FIPS
latte test --jca    # JCA only (skip the FIPS pass)
latte test --fips   # FIPS only (skip the JCA pass)
latte doc        # Javadoc
latte int        # local integration publish (depends on test)
latte idea       # regenerate the IntelliJ .iml module file
latte --listTargets   # list all build targets
```

`latte test` runs the full TestNG suite twice to cover both provider modes. The toggle is `-Dtest.fips=true|false`, which `BaseTest#beforeSuite` reads — FIPS mode inserts `BouncyCastleFipsProvider` at position 1 and sets `org.bouncycastle.fips.approved_only=true`. Any new test that asserts provider-specific behavior must tolerate both modes.

Run a single test class with `latte test --test=ExampleTest` (pass the simple class name, not the fully qualified name). Combine with `--jca` / `--fips` to scope the provider mode, e.g. `latte test --test=JWTDecoderTest --jca`. From IntelliJ, running a single TestNG class or method works too — pass `-Dtest.fips=true` in the run-config VM options to exercise the FIPS path.

Other Latte CLI commands worth knowing: `latte install <artifact-id> [version] [group]` adds a dependency, `latte upgrade <parameter>` upgrades runtime/plugins/dependencies. But remember: this project is deliberately zero-dep at compile scope — don't `latte install` into the `compile` group without a discussion.

## Runtime dependencies

There are **zero** compile dependencies — this is a point of pride, not an accident. Every `group(name: "compile")` line is empty. Do not add a runtime dependency without a discussion; adding one breaks the central value proposition in the README. Jackson and BouncyCastle appear only in `test-compile` — they exist to validate interop (`jacksontest/JacksonJSONProcessor` verifies the pluggable `JSONProcessor` strategy works with a real Jackson adapter, and BC-FIPS drives the FIPS test pass).

## Architecture (7.0 redesign)

The library is undergoing a full architectural redesign for 7.0. The design is documented in `specs/7.0-architecture.md` (status: Under Review, pass 4). Read that spec before making any non-trivial change to public API surface — it contains the rationale for the decisions summarized below and often names specific behaviors that look wrong but are intentional (e.g. strict `Ed25519`/`Ed448` acceptance with no `EdDSA` alias, rejection of numeric `exp`/`nbf`/`iat` outside `Instant` bounds).

Key architectural choices:

- **`Algorithm` is an interface, not an enum.** `StandardAlgorithm` provides the 15 IANA JWA constants (`HS256`…`Ed448`, `ES256K`). `Algorithm.of(name)` returns the interned constant so `==` works for standard values; unknown names return a fresh `StandardAlgorithm`. Do not assume `Algorithm` maps to a JCA string — that mapping is internal to each `Signer`/`Verifier`. `Algorithm.fromName` is a temporary 6.x back-compat shim that also accepts legacy JCA names (`SHA256withRSA` etc.); new code uses `Algorithm.of`.
- **`JSONProcessor` is a strategy interface.** The bundled `LatteJSONProcessor` is a zero-dependency implementation used by default. Users plug in Jackson/Gson/etc. by implementing `serialize(Map)`/`deserialize(byte[])`. Implementations must be stateless and thread-safe — the encoder/decoder call them concurrently.
- **`JWT` and `Header` are immutable**, built via fluent `Builder` inner classes. Time claims (`exp`, `nbf`, `iat`) are `Instant`, not `ZonedDateTime`. `build()` on a builder returns a fresh instance; builders are reusable but not thread-safe.
- **`Signer` / `Verifier` are the two crypto interfaces.** `Signers.forHMAC` / `Signers.forAsymmetric` (and the `Verifiers` equivalents) are the recommended factories — the split exists so a private key passed to `forHMAC` (or a shared secret to `forAsymmetric`) is rejected with `IllegalArgumentException` at construction, preventing the wrong-key-wrong-family coercion class of vulnerability. Family-specific factories (`HMACSigner.newSHA256Signer`, `RSASigner.newSHA256Signer`, `ECVerifier.newVerifier`, `EdDSASigner`, `RSAPSSSigner`, etc.) still exist under `algorithm/{hmac,rsa,ec,ed}/`. Built signers/verifiers are thread-safe and reusable.
- **Decoding uses a `VerifierResolver`.** `VerifierResolver.of(verifier)` for a single key; `VerifierResolver.byKid(Map)` for a `kid`-indexed keyring. `JWTDecoder.builder().clockSkew(Duration).fixedTime(Instant).build()` configures clock skew and the decoder's notion of "now" (the latter replaces the old "time machine decoder" from 6.x — keep `fixedTime` test-only).
- **No `sun.*`, `com.sun.*`, or `jdk.internal.*` in production code.** X.509 generation and parsing go through our own `der/` package (`DerInputStream`, `DerOutputStream`, `DerValue`, `ObjectIdentifier`, `Tag`, `TagClass`). `X509.builder()` DER-encodes per RFC 5280 and hands the bytes back to the JDK `CertificateFactory` for the final parse. PEM decode/encode lives in `pem/`. The one exception is `com.sun.net.httpserver.HttpServer` used in **tests only**.
- **Zero-dep internals.** `internal/LatteJSONProcessor.java` (in `jwt/` package) is the default JSON. `internal/SHAKE256.java` provides SHAKE256 for Ed448 OIDC hashing (no BC required at runtime). `internal/CanonicalJSONWriter` implements RFC 7638 canonical JWK thumbprint. `internal/MessageSanitizer` controls what reaches exception messages (do not leak untrusted input into throw sites without running it through this).

### Package map (production)

```
org.lattejava.jwt                      core: JWT, Header, JWTEncoder, JWTDecoder, Signer/Verifier interfaces, Signers/Verifiers factories, Algorithm, LatteJSONProcessor, exception hierarchy
org.lattejava.jwt.algorithm.{hmac,rsa,ec,ed}   per-family Signer/Verifier implementations + Family helpers
org.lattejava.jwt.der                  DER encoder/decoder used by x509 and jwks
org.lattejava.jwt.pem                  PEM read/write (PKCS#8, SEC1, SPKI, X.509)
org.lattejava.jwt.jwks                 JSONWebKey, JWK parser/converter, JWKS endpoint retrieval
org.lattejava.jwt.x509                 X509.builder()
org.lattejava.jwt.oauth2               OpenID Connect discovery helpers
org.lattejava.jwt.internal             SHAKE256, canonical JSON, thumbprint, message sanitizer, key utilities
```

### Exception hierarchy

Top-level `JWTException` (unchecked) with specific subtypes (`InvalidJWTException`, `InvalidJWTSignatureException`, `JWTExpiredException`, `MissingVerifierException`, etc.). Per the 7.0 spec §11, exception messages use `[value]` delimiters for runtime values and never include untrusted input directly — funnel through `MessageSanitizer` first. Cause chaining is mandatory when wrapping — do not swallow the underlying exception.

## Code conventions

Project-specific conventions are in `.claude/rules/`:
- `code-conventions.md` — acronym casing (`JSONProcessor` not `JsonProcessor`), alphabetization rules, import ordering, class-member ordering, Javadoc style.
- `error-messages.md` — runtime values in exception/log messages use `[value]`, not `'value'` or `"value"`.

Follow both without being asked. They are not advisory.

## Specs

`specs/` is not a scratchpad — see `specs/README.md` for the spec lifecycle. Only long-lived designs (architecture redesigns, cross-cutting features, security-relevant decisions) belong there. Short-term work goes in PR descriptions. When implementing against `specs/7.0-architecture.md`, treat it as authoritative; if the code and spec disagree, update the spec rather than quietly deviating.

## License headers

Two license regimes coexist: files derived from [fusionauth-jwt](https://github.com/FusionAuth/fusionauth-jwt) keep the Apache-2.0 header and original `@author`; brand-new files in 7.0 use the MIT header `Copyright (c) 2026, The Latte Project`. Do not rewrite an Apache-2.0 header to MIT on an inherited file — check `git log` if you're unsure which regime applies.
