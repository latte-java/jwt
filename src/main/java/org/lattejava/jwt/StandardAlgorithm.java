/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;

/**
 * Package-private default {@link Algorithm} implementation. Equality and hash code are keyed on {@link #name()}, so two
 * instances with the same JWA name compare equal regardless of how they were constructed.
 *
 * <p>Implemented as a final class (not a record) because the file ships a
 * {@code toString()} that is intentionally minimal -- just the JWA name -- rather than the
 * {@code StandardAlgorithm[name=...]} record default.</p>
 *
 * @author Daniel DeGroff
 */
record StandardAlgorithm(String name) implements Algorithm {
  StandardAlgorithm(String name) {
    this.name = Objects.requireNonNull(name, "name");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof StandardAlgorithm other)) {
      return false;
    }
    return name.equals(other.name);
  }

  @Override
  public String toString() {
    return name;
  }
}
