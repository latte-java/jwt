/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.internal;

import java.security.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.jwks.*;

/**
 * RFC 7638 / RFC 8037 JWK Thumbprint computation routed through the internal {@link CanonicalJSONWriter} (NOT the
 * user-pluggable {@code JSONProcessor}).
 *
 * <p>Internal entry point used by {@link JSONWebKey#thumbprintSHA256()} and
 * {@link JSONWebKey#thumbprintSHA1()}. {@link CanonicalJSONWriter} itself remains package-private so no user-pluggable
 * JSON serializer can influence thumbprint bytes.
 *
 * @author Daniel DeGroff
 */
public final class JWKThumbprint {

  private JWKThumbprint() {
  }

  /**
   * Returns the base64URL-encoded JWK thumbprint of {@code key} using the given JCA digest algorithm name (e.g.
   * {@code "SHA-1"} or {@code "SHA-256"}).
   *
   * @param algorithm the JCA digest algorithm name; non-null
   * @param key       the JWK; non-null and {@code key.kty} must be set
   * @return the base64URL-encoded thumbprint without padding
   * @throws IllegalArgumentException if {@code key.kty} is null or unsupported, or if {@code algorithm} is unknown
   */
  public static String compute(String algorithm, JSONWebKey key) {
    if (algorithm == null) {
      throw new IllegalArgumentException("Algorithm is null");
    }
    if (key == null) {
      throw new IllegalArgumentException("Key is null");
    }
    if (key.kty() == null) {
      throw new IllegalArgumentException("JWK [kty] is null");
    }

    Map<String, Object> members = canonicalMembers(key);
    byte[] canonical = CanonicalJSONWriter.write(members);

    MessageDigest md;
    try {
      md = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("No such algorithm [" + algorithm + "]", e);
    }
    return Base64URL.encodeToString(md.digest(canonical));
  }

  /**
   * Builds the RFC 7638 §3.2 / RFC 8037 §2 required member subset for the given key, in lex order. Insertion order
   * matches lex order so a downstream sort is a no-op (defensive: {@link CanonicalJSONWriter} sorts regardless).
   */
  private static Map<String, Object> canonicalMembers(JSONWebKey key) {
    Map<String, Object> m = new LinkedHashMap<>(4);
    KeyType kty = key.kty();
    String ktyName = kty.name();
    switch (ktyName) {
      case "EC":
        m.put("crv", key.crv());
        m.put("kty", ktyName);
        m.put("x", key.x());
        m.put("y", key.y());
        return m;
      case "RSA":
        m.put("e", key.e());
        m.put("kty", ktyName);
        m.put("n", key.n());
        return m;
      case "OKP":
        m.put("crv", key.crv());
        m.put("kty", ktyName);
        m.put("x", key.x());
        return m;
      case "oct":
        Object kVal = key.other() == null ? null : key.other().get("k");
        m.put("k", kVal);
        m.put("kty", ktyName);
        return m;
      default:
        throw new IllegalArgumentException("Unsupported key type [" + kty + "]");
    }
  }
}
