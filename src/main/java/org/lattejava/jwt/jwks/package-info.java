/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

/**
 * JSON Web Key (JWK) and JSON Web Key Set (JWKS) types and the {@link org.lattejava.jwt.jwks.JWKS} self-refreshing
 * cache.
 *
 * <h2>When to use what</h2>
 * <ul>
 *   <li>{@link org.lattejava.jwt.jwks.JWKS} — the high-level API. A
 *       self-refreshing {@code VerifierResolver} that drops directly into
 *       {@link org.lattejava.jwt.JWTDecoder}. Handles caching, refresh,
 *       singleflight coalescing, {@code Cache-Control}/{@code Retry-After}
 *       honoring, and rotation. Construct via {@code fromIssuer},
 *       {@code fromWellKnown}, {@code fromJWKS}, {@code fromConfiguration},
 *       or {@code of(...)} for in-memory keys. Use {@code fetch(...)}
 *       for a one-shot fetch returning a {@code List<JSONWebKey>}.</li>
 *   <li>{@link org.lattejava.jwt.jwks.JSONWebKey} — the JWK type itself. Use
 *       {@link org.lattejava.jwt.jwks.JSONWebKey#toPublicKey()} or
 *       {@link org.lattejava.jwt.Verifiers#fromJWK(org.lattejava.jwt.jwks.JSONWebKey)}
 *       when wiring a custom resolver.</li>
 * </ul>
 */
package org.lattejava.jwt.jwks;
