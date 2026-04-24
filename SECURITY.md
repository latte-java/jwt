# Security

## Reporting a vulnerability

Report suspected vulnerabilities privately. Please open a GitHub security
advisory at <https://github.com/latte-java/jwt/security/advisories/new>
rather than a public issue. Include a minimal reproduction (key material,
token, and expected vs actual behaviour) so we can confirm and triage
quickly.

## Supported versions

Only the latest minor release on the current major line receives
security fixes.

## Known deviations from JWT best-current-practice

This section documents places where the library's runtime behaviour
knowingly differs from the letter of a spec, and the reasoning. Each
deviation is a deliberate trade-off — they are listed here so integrators
can make an informed decision about whether the behaviour is acceptable
for their threat model.

### RSA modulus minimum: 2047 bits (RFC 8725 §3.5)

**What the spec says.** RFC 8725 §3.5 ("JSON Web Token Best Current
Practices") requires that RSA keys used with JWS be at least **2048
bits**.

**What we do.** `RSAFamily.assertMinimumModulus` accepts any modulus of
**2047 bits or more**. See
`src/main/java/org/lattejava/jwt/algorithm/rsa/RSAFamily.java`.

**Why.** Real-world RSA key generators occasionally emit a modulus one
bit shy of the nominal size (`bitLength()` returns 2047 instead of 2048)
because the top bit of the modulus happens to be zero. These keys are
cryptographically equivalent to a 2048-bit key for signing / verification
purposes — the "missing" bit is structural, not entropic. Rejecting
2047-bit keys would break interoperability with otherwise valid
deployments. The practical security margin of a 2047-bit modulus vs a
2048-bit modulus is negligible (one bit of search space in a problem
that is already infeasible to attack by brute force).

**What this means for you.** If your threat model requires a strict
2048-bit floor, generate keys with a generator that guarantees a set top
bit, or add a caller-side `bitLength() >= 2048` check on the public key
before handing it to `RSAVerifier` / `RSASigner`.
