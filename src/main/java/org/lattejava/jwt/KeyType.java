/*
 * Copyright (c) 2016-2026, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.lattejava.jwt;

import java.util.Objects;

import static org.lattejava.jwt.der.ObjectIdentifier.EC_ENCRYPTION;
import static org.lattejava.jwt.der.ObjectIdentifier.EdDSA_25519;
import static org.lattejava.jwt.der.ObjectIdentifier.EdDSA_448;
import static org.lattejava.jwt.der.ObjectIdentifier.RSASSA_PSS_ENCRYPTION;
import static org.lattejava.jwt.der.ObjectIdentifier.RSA_ENCRYPTION;

/**
 * The JSON Web Key (JWK) {@code "kty"} parameter value as registered in the
 * IANA "JSON Web Key Types" registry per RFC 7517 §4.1.
 *
 * <p>Standard constants (e.g., {@link #RSA}, {@link #EC}, {@link #OKP},
 * {@link #OCT}) are interned: {@code KeyType.of("RSA") == KeyType.RSA}.
 * For custom key types, use {@link #of(String)} or implement this interface.</p>
 *
 * @author Daniel DeGroff
 */
public interface KeyType {
  /**
   * The JWK {@code "kty"} parameter value.
   *
   * @return the kty name, e.g. {@code "RSA"}, {@code "EC"}, {@code "OKP"}, {@code "oct"}
   */
  String name();

  /**
   * RSA keys (RFC 7518 §6.3). Used for RS256/384/512 and PS256/384/512 alike.
   */
  KeyType RSA = new StandardKeyType("RSA");

  /**
   * Elliptic Curve keys (RFC 7518 §6.2). Used for ES256/384/512 and ES256K.
   */
  KeyType EC = new StandardKeyType("EC");

  /**
   * Octet Key Pair (RFC 8037 §2). Used for Ed25519 and Ed448.
   */
  KeyType OKP = new StandardKeyType("OKP");

  /**
   * Symmetric ("octet sequence") keys (RFC 7517 §6.4). Used for HS256/384/512.
   * Note the lowercase {@code "oct"} per the registry.
   */
  KeyType OCT = new StandardKeyType("oct");

  /**
   * Look up a KeyType by name. Returns the pre-built standard constant if the
   * name matches one of the 4 standard key types (enabling {@code ==}
   * comparison for standard key types). Returns a new instance for
   * unrecognized names.
   *
   * <p>Lookup is exact-case. {@code KeyType.of("rsa")} is <em>not</em> the
   * same as {@code KeyType.RSA}.</p>
   *
   * @param name the kty value; must not be null
   * @return the interned constant or a new instance
   * @throws NullPointerException if {@code name} is null
   */
  static KeyType of(String name) {
    Objects.requireNonNull(name, "name");
    return switch (name) {
      case "RSA" -> RSA;
      case "EC" -> EC;
      case "OKP" -> OKP;
      case "oct" -> OCT;
      default -> new StandardKeyType(name);
    };
  }

  /**
   * @return a fresh array of all 4 standard {@code KeyType} constants.
   */
  static KeyType[] standardValues() {
    return new KeyType[]{RSA, EC, OKP, OCT};
  }

  /**
   * Resolve a {@code KeyType} from a known cryptographic OID. Returns
   * {@code null} for unknown OIDs. Used by {@code PEMDecoder} to map a
   * DER-encoded algorithm identifier to a JCA key family.
   *
   * <p>Note: {@code RSASSA_PSS_ENCRYPTION} maps to {@link #RSA} because
   * RSA-PSS keys use {@code "kty": "RSA"} on the wire. Internal callers that
   * need to know the OID is PSS-specific should branch on the OID directly,
   * not on the returned {@code KeyType}.</p>
   *
   * @param oid the OID dotted-decimal string
   * @return the matching standard {@code KeyType} or {@code null}
   */
  static KeyType forOid(String oid) {
    Objects.requireNonNull(oid);
    return switch (oid) {
      case EC_ENCRYPTION -> EC;
      case EdDSA_448, EdDSA_25519 -> OKP;
      case RSA_ENCRYPTION, RSASSA_PSS_ENCRYPTION -> RSA;
      default -> null;
    };
  }
}
