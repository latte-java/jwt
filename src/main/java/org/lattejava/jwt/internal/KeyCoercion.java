/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt.internal;

import java.security.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.internal.pem.*;

/**
 * Shared coercion helpers used by the asymmetric signer/verifier implementations. Each helper validates the key's
 * runtime type and casts to the caller's expected subtype, producing consistent error messages across algorithm
 * families.
 *
 * @author Daniel DeGroff
 */
public final class KeyCoercion {
  private KeyCoercion() {
  }

  /**
   * Cast {@code key} to {@code expected}. Throws {@link InvalidKeyTypeException} with a uniform message when the
   * runtime type does not match.
   */
  public static <T extends PrivateKey> T asPrivate(PrivateKey key, Class<T> expected) {
    if (!expected.isInstance(key)) {
      throw new InvalidKeyTypeException("Expected private key of type [" + expected.getSimpleName()
          + "] but found [" + key.getClass().getSimpleName() + "]");
    }
    return expected.cast(key);
  }

  /**
   * Cast {@code key} to {@code expected}. Throws {@link InvalidKeyTypeException} with a uniform message when the
   * runtime type does not match.
   */
  public static <T extends PublicKey> T asPublic(PublicKey key, Class<T> expected) {
    if (!expected.isInstance(key)) {
      throw new InvalidKeyTypeException("Expected public key of type [" + expected.getSimpleName()
          + "] but found [" + key.getClass().getSimpleName() + "]");
    }
    return expected.cast(key);
  }

  /**
   * Decode the PEM string, ensure a private key is present, and cast it to {@code expected}.
   */
  public static <T extends PrivateKey> T privateFromPem(String pemPrivateKey, Class<T> expected) {
    PEM pem = PEM.decode(pemPrivateKey);
    PrivateKey privateKey = pem.getPrivateKey();
    if (privateKey == null) {
      throw new MissingPrivateKeyException(
          "PEM did not contain a private key; expected [" + expected.getSimpleName() + "]");
    }
    return asPrivate(privateKey, expected);
  }

  /**
   * Decode the PEM string, ensure a public key is present, and cast it to {@code expected}.
   */
  public static <T extends PublicKey> T publicFromPem(String pemPublicKey, Class<T> expected) {
    PEM pem = PEM.decode(pemPublicKey);
    PublicKey publicKey = pem.getPublicKey();
    if (publicKey == null) {
      throw new MissingPublicKeyException(
          "PEM did not contain a public key; expected [" + expected.getSimpleName() + "]");
    }
    return asPublic(publicKey, expected);
  }
}
