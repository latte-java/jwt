# Library versions

Pinned at adapter-authoring time. Bump manually via the per-library `project.latte`.

| Library         | Group : Artifact                              | Version |
|-----------------|-----------------------------------------------|---------|
| JMH             | org.openjdk.jmh:jmh-core                      | 1.37    |
| JMH (annproc)   | org.openjdk.jmh:jmh-generator-annprocess      | 1.37    |
| auth0/java-jwt  | com.auth0:java-jwt                            | 4.5.0   |
| jose4j          | org.bitbucket.b_c:jose4j                      | 0.9.6   |
| nimbus-jose-jwt | com.nimbusds:nimbus-jose-jwt                  | 10.3    |
| jjwt-api        | io.jsonwebtoken:jjwt-api                      | 0.12.6  |
| jjwt-impl       | io.jsonwebtoken:jjwt-impl                     | 0.12.6  |
| jjwt-jackson    | io.jsonwebtoken:jjwt-jackson                  | 0.12.6  |
| fusionauth-jwt  | io.fusionauth:fusionauth-jwt                  | 5.3.3   |
| vertx-auth-jwt  | io.vertx:vertx-auth-jwt                       | 4.5.14  |

## Dropped libraries

| Library      | Group : Artifact                        | Version | Reason |
|--------------|-----------------------------------------|---------|--------|
| inverno-jose | io.inverno.mod:inverno-security-jose    | 1.13.0  | No compatible non-CDI API (see below) |

### inverno-security-jose (dropped)

`inverno-security-jose` 1.13.0 does not expose a public synchronous factory for its `JWSService` or
`JWTService`. The two viable entry points were investigated and ruled out:

1. **`Jose.Builder` (from test/Readme.java):** Uses `@Bean`/`@Wrapper` annotations from
   `io.inverno.core.annotation` and requires `io.inverno.core.v1.Application` for module bootstrap.
   This is the full Inverno CDI container — not a standalone path.

2. **Internal `Generic*` classes (`GenericJWSService`, `GenericJWKService`, etc.):** Constructable
   without CDI, as demonstrated by the library's own unit tests (`GenericJWSServiceTest`). However,
   these are in `io.inverno.mod.security.jose.internal.*` — not public API — and wiring them up
   manually requires instantiating eight factory/resolver/validator classes plus Jackson and
   Project Reactor. Every operation returns a `Mono<T>` that would need `.block()` on the hot
   path, making the benchmark a measurement of reactive dispatch overhead rather than JWT
   throughput. That is not a meaningful comparison with the other seven synchronous libraries in
   this suite.

The artifact exists at 1.13.0 on Maven Central and is technically functional. It was dropped from
the benchmark suite purely because there is no public synchronous API surface compatible with
`JwtBenchmarkAdapter` without pulling in the full Inverno module runtime or reaching into
internal implementation classes.
