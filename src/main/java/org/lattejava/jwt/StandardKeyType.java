/*
 * Copyright (c) 2026 The Latte Project
 * SPDX-License-Identifier: MIT
 */

package org.lattejava.jwt;

import java.util.*;

/**
 * Package-private default {@link KeyType} implementation. Equality and hash code are keyed on {@link #name()}, so two
 * instances with the same kty value compare equal regardless of how they were constructed.
 *
 * @author Daniel DeGroff
 */
record StandardKeyType(String name) implements KeyType {
  StandardKeyType(String name) {
    this.name = Objects.requireNonNull(name, "name");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof StandardKeyType other)) {
      return false;
    }
    return name.equals(other.name);
  }

  @Override
  public String toString() {
    return name;
  }
}
