# Specs

This directory holds long-lived design specifications for major changes to the JWT library — architecture redesigns, breaking API changes, cross-cutting features, and any other work that benefits from written-down design rationale and explicit review.

Short-term work (single-feature proposals, bug-fix design notes, one-off RFC reads) does not belong here; use a PR description or an issue instead. A spec earns its place in `specs/` when at least one of the following is true:

- The work spans multiple releases or touches most of the public API surface.
- The design decisions will need to be re-derived or re-defended after the author forgets why they were made.
- The rationale is material to security review, compliance (e.g., FIPS, RFC 8725), or downstream integrators.

## Index

| Spec | Status | Last updated | Owner | Summary |
|------|--------|--------------|-------|---------|
| [architecture.md](architecture.md) | Under Review | 2026-04-21 (review pass 4) | Daniel DeGroff | Library architecture: Algorithm as interface, zero-dep JSON with pluggable strategy, immutable builders, `Instant`-typed time claims, RFC 8725 alignment, RFC 7638 canonical thumbprint, internal SHAKE256 for OIDC Ed448, DER-based X.509. Pass-4 adds explicit crypto contracts (ECDSA DER↔JOSE, RSASSA-PSS parameters, EC on-curve validation), Signer/Verifier thread-safety contract, `maxNumberLength` parse-DoS defense, JWKS `maxResponseBytes`/`maxRedirects` defaults, and `jku`/`x5u`/`jwk` no-dereference guarantee. |
| [jwks-source.md](jwks-source.md) | In Progress (PR [#3](https://github.com/latte-java/jwt/pull/3)) | 2026-04-25 (rev 3) | Daniel DeGroff | Self-refreshing JWK cache (`JWKSource`) implementing `VerifierResolver` + `AutoCloseable`. Builder API, factories for issuer / well-known / JWKS URLs, virtual-thread scheduler, singleflight refresh, unified `nextDueAt` watermark, exponential backoff with `Retry-After` floor, `CacheControlPolicy` honoring (`CLAMP`/`IGNORE`), pluggable `Logger` (mirroring `lattejava.http` plus `warn`). Adds public `Verifiers.fromJWK(JSONWebKey)`, `JSONWebKey.toPublicKey()`, `HTTPResponseException`, and the `org.lattejava.jwt.log` package. |
| [discovery-and-jwks-simplification.md](discovery-and-jwks-simplification.md) | Implemented | 2026-04-26 (rev 3) | Daniel DeGroff | Promote OIDC discovery to a first-class type (`OpenIDConnectConfiguration`, `OpenIDConnect.discover(...)`); rename `JWKSource` → `JWKS` with raw-JWK lookup (`get`/`keys`/`keyIds`), `fromConfiguration(...)`, static `JWKS.of(...)`, and one-shot `JWKS.fetch(...)`; replace static hardening config with per-instance `FetchLimits`; delete `AuthorizationServerMetaData`, `ServerMetaDataHelper`, `JSONWebKeySetHelper`, and the `oauth2` package. |

## Spec lifecycle

| Status | Meaning |
|--------|---------|
| **Draft** | Actively being written. Not ready for external review. |
| **Under Review** | Author believes the spec is complete; inviting review comments and iterating on feedback. No implementation work should start yet. |
| **Approved** | Review is closed and the design is accepted. Implementation may begin. Further changes require a new review pass and a note in the spec's change log. |
| **In Progress** | Implementation has started. The spec remains authoritative; discrepancies found during implementation are resolved by updating the spec (or explicitly noting deviations). |
| **Implemented** | All spec'd work has shipped in the target release. The spec is frozen — future changes go into a new spec that supersedes this one. |
| **Superseded** | Replaced by a later spec. The superseding spec is linked in the status cell. Historical record only; do not base new work on a superseded spec. |

A spec advances through statuses by updating the row in this README and adding a dated note near the top of the spec file.

## Contributing a new spec

1. Create a new file named `<topic>.md` (e.g., `jwe-support.md`). Long-lived design specs are not version-tagged; the spec describes the design, and the repo at any commit reflects the implementation state.
2. Start with a header block containing at minimum: title, date, version or scope, owner, and one-paragraph problem statement.
3. Set the initial status to **Draft**; add a row to the index above.
4. When ready for review, flip the status to **Under Review** and open a PR against `main` containing the spec change only (no implementation). Request reviewers explicitly.
5. Capture non-trivial review feedback inline in the spec — future readers need to know *why*, not just *what*.
6. On approval, the spec row moves to **Approved** and implementation PRs may reference the spec by path + anchor.

## Change log conventions

Each spec should maintain its own change log at or near the top of the file. Use dated entries, short bullets, and link to the PR or issue that drove the change where applicable. The README index tracks overall status transitions; the spec file tracks the substantive design changes within a status.
