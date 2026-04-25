# Specs

This directory holds long-lived design specifications for major changes to the JWT library — architecture redesigns, breaking API changes, cross-cutting features, and any other work that benefits from written-down design rationale and explicit review.

Short-term work (single-feature proposals, bug-fix design notes, one-off RFC reads) does not belong here; use a PR description or an issue instead. A spec earns its place in `specs/` when at least one of the following is true:

- The work spans multiple releases or touches most of the public API surface.
- The design decisions will need to be re-derived or re-defended after the author forgets why they were made.
- The rationale is material to security review, compliance (e.g., FIPS, RFC 8725), or downstream integrators.

## Index

| Spec | Version | Status | Last updated | Owner | Summary |
|------|---------|--------|--------------|-------|---------|
| [7.0-architecture.md](7.0-architecture.md) | 7.0.0 | Under Review | 2026-04-21 (review pass 4) | Daniel DeGroff | Full architecture redesign: Algorithm as interface, zero-dep JSON with pluggable strategy, immutable builders, `Instant`-typed time claims, RFC 8725 alignment, RFC 7638 canonical thumbprint, internal SHAKE256 for OIDC Ed448, DER-based X.509. Pass-4 adds explicit crypto contracts (ECDSA DER↔JOSE, RSASSA-PSS parameters, EC on-curve validation), Signer/Verifier thread-safety contract, `maxNumberLength` parse-DoS defense, JWKS `maxResponseBytes`/`maxRedirects` defaults, and `jku`/`x5u`/`jwk` no-dereference guarantee. |
| [jwks-source.md](jwks-source.md) | 7.x (additive) | Draft | 2026-04-25 (rev 2) | Daniel DeGroff | New `JWKSource` type — a self-refreshing JWK cache that implements `VerifierResolver`. Synchronous initial load in `build()`, opt-in scheduled refresh on a `minRefreshInterval`-rate tick dispatching to virtual threads, refresh-on-cache-miss with singleflight + unified `nextDueAt` gate, exponential-backoff failure handling with `Retry-After` honoring on 429/503, `Cache-Control: max-age` honoring with `CacheControlPolicy.CLAMP`/`IGNORE`, serve-stale-on-failure for availability, `AutoCloseable`, optional `org.lattejava.jwt.log.Logger` (matching `lattejava.http` convention). Strict JWK ingest (requires `alg`, requires `kid`, rejects symmetric keys). |

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

1. Create a new file named `<version>-<topic>.md` (e.g., `8.0-jwe-support.md`) or, for non-versioned work, `<topic>.md`.
2. Start with a header block containing at minimum: title, date, version or scope, owner, and one-paragraph problem statement.
3. Set the initial status to **Draft**; add a row to the index above.
4. When ready for review, flip the status to **Under Review** and open a PR against `main` containing the spec change only (no implementation). Request reviewers explicitly.
5. Capture non-trivial review feedback inline in the spec — future readers need to know *why*, not just *what*.
6. On approval, the spec row moves to **Approved** and implementation PRs may reference the spec by path + anchor.

## Change log conventions

Each spec should maintain its own change log at or near the top of the file. Use dated entries, short bullets, and link to the PR or issue that drove the change where applicable. The README index tracks overall status transitions; the spec file tracks the substantive design changes within a status.
