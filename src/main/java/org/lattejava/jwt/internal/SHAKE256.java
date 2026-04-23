/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.lattejava.jwt.internal;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;

/**
 * Internal FIPS 202 SHAKE256 implementation used exclusively by
 * {@code OpenIDConnect} for the Ed448 {@code at_hash} / {@code c_hash} path.
 *
 * <p>Self-contained Keccak-f[1600] sponge (rate=1088 bits, capacity=512 bits,
 * domain separator {@code 0x1F}) per FIPS 202 §3 / §6.2. Not registered as a
 * JCA service. Not part of the public API; serves exactly one internal caller.
 *
 * <p><b>Provider preference (FIPS-aware).</b> The first call to
 * {@link #digest(byte[], int)} probes for a JCA-registered {@code SHAKE256}
 * provider. The probe runs a one-shot KAT against a known input/output pair
 * and only caches the provider on a successful self-test (this protects
 * against partial or broken provider registrations). On any failure (no
 * provider, getInstance error, KAT mismatch, exception) the bundled
 * implementation is used and the result of the probe is cached for the
 * lifetime of the VM.
 *
 * <p><b>Provenance.</b> The bundled implementation is derived from the public
 * domain Keccak / FIPS 202 reference (XKCP / tiny_sha3 style). It is
 * deterministically equivalent to any FIPS 202 conformant implementation.
 *
 * @author The Latte Project
 */
public final class SHAKE256 {

  // FIPS 202 §3.2.5 round constants for Keccak-f[1600].
  private static final long[] RC = {
      0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
      0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
      0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
      0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
      0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
      0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
      0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
      0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
  };

  // FIPS 202 §3.2.2 rho rotation offsets, indexed by lane index 0..24
  // (row-major: i = x + 5*y).
  private static final int[] R = {
      0,  1,  62, 28, 27,
      36, 44, 6,  55, 20,
      3,  10, 43, 25, 39,
      41, 45, 15, 21,  8,
      18,  2, 61, 56, 14
  };

  // SHAKE256 sponge: rate r = 1088 bits = 136 bytes; capacity c = 512 bits.
  private static final int RATE_BYTES = 136;

  // KAT: empty input → first 64 SHAKE256 output bytes. Used by the probe
  // self-test. This is a NIST CAVP-equivalent vector. We use 64 because some
  // JCE providers (notably BC-FIPS) expose SHAKE256 only via the fixed-output
  // MessageDigest.digest() API (returning 64 bytes); the variable-length
  // digest(buf, off, len) is not surfaced through JCA.
  private static final byte[] KAT_INPUT = new byte[0];
  private static final int KAT_OUT_LEN = 64;
  private static final byte[] KAT_EXPECTED = hexToBytes(
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
          + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

  // Provider cache. `probed` becomes true after the first probe attempt;
  // `cachedProvider` is non-null only on a successful KAT self-test.
  private static volatile boolean probed = false;
  private static volatile Provider cachedProvider = null;
  private static final Object PROBE_LOCK = new Object();

  private SHAKE256() {
  }

  /**
   * Returns {@code outputBytes} of SHAKE256 output for {@code input}.
   *
   * <p>Prefers a JCE-registered {@code SHAKE256} provider that passes an
   * internal KAT self-test; otherwise falls back to the bundled FIPS 202
   * implementation. The provider/bundled decision is cached for the VM
   * lifetime after the first call.
   *
   * @param input       the message to hash; must be non-null
   * @param outputBytes the desired output length in bytes; must be > 0
   * @return a freshly-allocated array of length {@code outputBytes}
   */
  public static byte[] digest(byte[] input, int outputBytes) {
    Objects.requireNonNull(input, "input");
    if (outputBytes <= 0) {
      throw new IllegalArgumentException("outputBytes must be > 0");
    }

    Provider p = resolveProvider();
    if (p != null) {
      byte[] out = tryProvider(p, input, outputBytes);
      if (out != null) {
        return out;
      }
      // Cached provider could not satisfy this length (e.g. BC-FIPS exposes
      // a fixed 64-byte output and outputBytes > 64): fall through to bundled.
    }
    return bundledShake256(input, outputBytes);
  }

  /**
   * Attempts to compute SHAKE256({@code input}) of {@code outputBytes} via
   * the given provider. Returns {@code null} if the provider cannot satisfy
   * the request (e.g., its JCA service exposes only a fixed-length output
   * shorter than {@code outputBytes}, or any other failure).
   */
  private static byte[] tryProvider(Provider p, byte[] input, int outputBytes) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHAKE256", p);
      md.update(input);
      // Try the variable-length API first; some providers support it.
      try {
        byte[] out = new byte[outputBytes];
        int written = md.digest(out, 0, outputBytes);
        if (written == outputBytes) {
          return out;
        }
      } catch (Exception ignore) {
        // API-variant probe: not every provider implements the variable-length digest(buf, off, len) API
        // for SHAKE256. Any failure (UnsupportedOperationException, DigestException, provider-specific
        // RuntimeExceptions) means this API path isn't available and we fall through to the fixed-length
        // digest() below. md is now in an indeterminate state after a partial digest attempt; rebuild.
        md = MessageDigest.getInstance("SHAKE256", p);
        md.update(input);
      }
      // Try the fixed-length API. Useful for providers that expose SHAKE256
      // only as a fixed 64-byte output (e.g., BC-FIPS via JCA).
      byte[] full = md.digest();
      if (full.length >= outputBytes) {
        if (full.length == outputBytes) {
          return full;
        }
        byte[] sliced = new byte[outputBytes];
        System.arraycopy(full, 0, sliced, 0, outputBytes);
        return sliced;
      }
      return null;
    } catch (Exception e) {
      return null;
    }
  }

  private static Provider resolveProvider() {
    if (probed) {
      return cachedProvider;
    }
    synchronized (PROBE_LOCK) {
      if (probed) {
        return cachedProvider;
      }
      Provider candidate = null;
      try {
        // Discover the highest-priority provider for SHAKE256, then run an
        // end-to-end KAT against it via the same code path the runtime uses.
        MessageDigest probe = MessageDigest.getInstance("SHAKE256");
        Provider probeProvider = probe.getProvider();
        byte[] result = tryProvider(probeProvider, KAT_INPUT, KAT_OUT_LEN);
        if (result != null && MessageDigest.isEqual(result, KAT_EXPECTED)) {
          candidate = probeProvider;
        }
      } catch (NoSuchAlgorithmException e) {
        // No provider; bundled path
      } catch (Exception e) {
        // Any other failure; bundled path
      }
      cachedProvider = candidate;
      probed = true;
      return candidate;
    }
  }

  /**
   * Test-only hook to clear the cached provider state so a subsequent call
   * re-runs the probe. Public for cross-package test access; not part of the
   * supported public API.
   */
  public static void resetProviderCacheForTesting() {
    synchronized (PROBE_LOCK) {
      probed = false;
      cachedProvider = null;
    }
  }

  /** Test-only hook reporting whether a provider is currently cached. */
  public static boolean hasCachedProviderForTesting() {
    return cachedProvider != null;
  }

  /** Test-only hook returning the cached provider name (or null). */
  public static String cachedProviderNameForTesting() {
    Provider p = cachedProvider;
    return p == null ? null : p.getName();
  }

  // ---------------------------------------------------------------------
  // Bundled FIPS 202 SHAKE256 implementation
  // ---------------------------------------------------------------------

  private static byte[] bundledShake256(byte[] input, int outputBytes) {
    long[] state = new long[25];

    // Absorb full RATE-byte blocks.
    int offset = 0;
    int remaining = input.length;
    while (remaining >= RATE_BYTES) {
      xorBlockIntoState(state, input, offset);
      keccakF1600(state);
      offset += RATE_BYTES;
      remaining -= RATE_BYTES;
    }

    // Pad final block: append the remaining bytes, then domain-separator
    // 0x1F (SHAKE), then trailing 0x80 (final-bit). pad10*1 in FIPS 202 §B.2.
    byte[] last = new byte[RATE_BYTES];
    System.arraycopy(input, offset, last, 0, remaining);
    last[remaining] = (byte) 0x1F;
    last[RATE_BYTES - 1] |= (byte) 0x80;
    xorBlockIntoState(state, last, 0);
    keccakF1600(state);

    // Squeeze.
    byte[] out = new byte[outputBytes];
    int produced = 0;
    while (produced < outputBytes) {
      int chunk = Math.min(RATE_BYTES, outputBytes - produced);
      extractBlockFromState(state, out, produced, chunk);
      produced += chunk;
      if (produced < outputBytes) {
        keccakF1600(state);
      }
    }
    return out;
  }

  private static void xorBlockIntoState(long[] state, byte[] in, int off) {
    // RATE_BYTES = 136 = 17 lanes (8 bytes each).
    for (int i = 0; i < 17; i++) {
      state[i] ^= readLane(in, off + i * 8);
    }
  }

  private static void extractBlockFromState(long[] state, byte[] out, int off, int len) {
    int laneCount = len / 8;
    for (int i = 0; i < laneCount; i++) {
      writeLane(state[i], out, off + i * 8);
    }
    int rem = len & 7;
    if (rem > 0) {
      long lane = state[laneCount];
      for (int b = 0; b < rem; b++) {
        out[off + laneCount * 8 + b] = (byte) ((lane >>> (8 * b)) & 0xFF);
      }
    }
  }

  private static long readLane(byte[] in, int off) {
    return ((long) (in[off] & 0xFF))
        | ((long) (in[off + 1] & 0xFF)) << 8
        | ((long) (in[off + 2] & 0xFF)) << 16
        | ((long) (in[off + 3] & 0xFF)) << 24
        | ((long) (in[off + 4] & 0xFF)) << 32
        | ((long) (in[off + 5] & 0xFF)) << 40
        | ((long) (in[off + 6] & 0xFF)) << 48
        | ((long) (in[off + 7] & 0xFF)) << 56;
  }

  private static void writeLane(long lane, byte[] out, int off) {
    out[off]     = (byte) (lane);
    out[off + 1] = (byte) (lane >>> 8);
    out[off + 2] = (byte) (lane >>> 16);
    out[off + 3] = (byte) (lane >>> 24);
    out[off + 4] = (byte) (lane >>> 32);
    out[off + 5] = (byte) (lane >>> 40);
    out[off + 6] = (byte) (lane >>> 48);
    out[off + 7] = (byte) (lane >>> 56);
  }

  /**
   * Keccak-f[1600] permutation per FIPS 202 §3.2. State is 25 lanes
   * organized as a 5x5 matrix (column-major: lane(x,y) = state[x + 5*y]).
   */
  private static void keccakF1600(long[] s) {
    long[] C = new long[5];
    long[] B = new long[25];
    for (int round = 0; round < 24; round++) {
      // θ
      for (int x = 0; x < 5; x++) {
        C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
      }
      for (int x = 0; x < 5; x++) {
        long d = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);
        for (int y = 0; y < 25; y += 5) {
          s[x + y] ^= d;
        }
      }
      // ρ + π
      for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
          int srcIdx = x + 5 * y;
          int dstX = y;
          int dstY = (2 * x + 3 * y) % 5;
          B[dstX + 5 * dstY] = Long.rotateLeft(s[srcIdx], R[srcIdx]);
        }
      }
      // χ
      for (int y = 0; y < 25; y += 5) {
        long b0 = B[y];
        long b1 = B[y + 1];
        long b2 = B[y + 2];
        long b3 = B[y + 3];
        long b4 = B[y + 4];
        s[y]     = b0 ^ ((~b1) & b2);
        s[y + 1] = b1 ^ ((~b2) & b3);
        s[y + 2] = b2 ^ ((~b3) & b4);
        s[y + 3] = b3 ^ ((~b4) & b0);
        s[y + 4] = b4 ^ ((~b0) & b1);
      }
      // ι
      s[0] ^= RC[round];
    }
  }

  private static byte[] hexToBytes(String hex) {
    int n = hex.length();
    byte[] out = new byte[n / 2];
    for (int i = 0; i < n; i += 2) {
      out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
          | Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
  }
}
