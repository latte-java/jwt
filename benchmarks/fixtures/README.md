# Fixtures — DO NOT USE IN PRODUCTION

These keys are test fixtures used to make benchmark inputs reproducible. They are not, and have never been, used to sign anything outside this benchmark suite. Do not use them in production. Do not paste their public keys into JWKS endpoints.

## Files

- `hmac-256.key` — 32 random bytes (raw) for HS256.
- `rsa-2048-private.pem`, `rsa-2048-public.pem` — RSA-2048 key pair (PKCS#8 / SPKI).
- `ec-p256-private.pem`, `ec-p256-public.pem` — EC P-256 key pair (PKCS#8 / SPKI).
- `claims.json` — canonical 10-claim payload (~270 bytes serialized). `iat` is a fixed historical timestamp; `exp` is `iat + 1 hour`.

## Time handling at decode

The `decode_verify_validate` benchmarks override the decoder's notion of "now" to 30 minutes after `iat` to guarantee `nbf` passes and `exp` doesn't throw, on every run, regardless of wall-clock time. For libraries whose decoder API doesn't allow externally-fixed time, the adapter regenerates the token in `prepare()` with `iat = now()` and `exp = now() + 1h`.
