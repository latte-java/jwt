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

package org.lattejava.jwt;

/**
 * Per-instance hardening limits for HTTP fetches and JSON parsing performed
 * by {@link org.lattejava.jwt.jwks.JWKSource} and discovery operations.
 *
 * <p>Instances are immutable. {@link #defaults()} returns a shared singleton.
 * Defaults match historical behavior exactly for the carried-forward fields;
 * {@link #allowCrossOriginRedirects()} is new in 7.0 and defaults to
 * {@code false} (stricter than 6.x, which had no origin check).</p>
 *
 * <p>The response cap and JSON parser caps cannot be disabled — the
 * corresponding setters reject zero or negative values. {@link #maxRedirects()}
 * is the exception: zero is permitted and disables redirect following.</p>
 */
public final class FetchLimits {
  private static final FetchLimits DEFAULTS = new FetchLimits(new Builder());
  private final boolean allowCrossOriginRedirects;
  private final boolean allowDuplicateJSONKeys;
  private final int maxArrayElements;
  private final int maxNestingDepth;
  private final int maxNumberLength;
  private final int maxObjectMembers;
  private final int maxRedirects;
  private final int maxResponseBytes;

  private FetchLimits(Builder b) {
    this.allowCrossOriginRedirects = b.allowCrossOriginRedirects;
    this.allowDuplicateJSONKeys = b.allowDuplicateJSONKeys;
    this.maxArrayElements = b.maxArrayElements;
    this.maxNestingDepth = b.maxNestingDepth;
    this.maxNumberLength = b.maxNumberLength;
    this.maxObjectMembers = b.maxObjectMembers;
    this.maxRedirects = b.maxRedirects;
    this.maxResponseBytes = b.maxResponseBytes;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static FetchLimits defaults() {
    return DEFAULTS;
  }

  public boolean allowCrossOriginRedirects() { return allowCrossOriginRedirects; }

  public boolean allowDuplicateJSONKeys() { return allowDuplicateJSONKeys; }

  public int maxArrayElements() { return maxArrayElements; }

  public int maxNestingDepth() { return maxNestingDepth; }

  public int maxNumberLength() { return maxNumberLength; }

  public int maxObjectMembers() { return maxObjectMembers; }

  public int maxRedirects() { return maxRedirects; }

  public int maxResponseBytes() { return maxResponseBytes; }

  /**
   * Reusable, mutable builder. Each {@link #build()} returns a fresh
   * immutable {@link FetchLimits}.
   */
  public static final class Builder {
    private boolean allowCrossOriginRedirects = false;
    private boolean allowDuplicateJSONKeys = false;
    private int maxArrayElements = 10_000;
    private int maxNestingDepth = 16;
    private int maxNumberLength = 1000;
    private int maxObjectMembers = 1000;
    private int maxRedirects = 3;
    private int maxResponseBytes = 1024 * 1024;

    private Builder() {}

    /**
     * Permits redirects whose (scheme, host, port) differ from the original
     * request. Default: {@code false}. Setting this to {@code true} is a
     * deliberate security trade-off — a DNS hijack or CDN takeover targeting
     * the original host can silently swap the verifier's keys via a 302 to
     * attacker-controlled infrastructure. Real OIDC providers rarely require
     * cross-origin redirects mid-fetch.
     *
     * @param allow {@code true} to permit cross-origin redirects.
     * @return this builder.
     */
    public Builder allowCrossOriginRedirects(boolean allow) {
      this.allowCrossOriginRedirects = allow;
      return this;
    }

    /**
     * Permits duplicate keys in parsed JSON objects. Default: {@code false}.
     *
     * @param allow {@code true} to permit duplicate JSON keys.
     * @return this builder.
     */
    public Builder allowDuplicateJSONKeys(boolean allow) {
      this.allowDuplicateJSONKeys = allow;
      return this;
    }

    /**
     * @return a new immutable {@link FetchLimits} from the current builder state.
     */
    public FetchLimits build() {
      return new FetchLimits(this);
    }

    /**
     * Sets the maximum number of elements permitted in any JSON array. Must be &gt; 0.
     *
     * @param n the limit.
     * @return this builder.
     * @throws IllegalArgumentException if {@code n} is zero or negative.
     */
    public Builder maxArrayElements(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxArrayElements must be > 0 but found [" + n + "]");
      this.maxArrayElements = n;
      return this;
    }

    /**
     * Sets the maximum JSON nesting depth. Must be &gt; 0.
     *
     * @param n the limit.
     * @return this builder.
     * @throws IllegalArgumentException if {@code n} is zero or negative.
     */
    public Builder maxNestingDepth(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxNestingDepth must be > 0 but found [" + n + "]");
      this.maxNestingDepth = n;
      return this;
    }

    /**
     * Sets the maximum character length of any JSON number. Must be &gt; 0.
     *
     * @param n the limit.
     * @return this builder.
     * @throws IllegalArgumentException if {@code n} is zero or negative.
     */
    public Builder maxNumberLength(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxNumberLength must be > 0 but found [" + n + "]");
      this.maxNumberLength = n;
      return this;
    }

    /**
     * Sets the maximum number of members permitted in any JSON object. Must be &gt; 0.
     *
     * @param n the limit.
     * @return this builder.
     * @throws IllegalArgumentException if {@code n} is zero or negative.
     */
    public Builder maxObjectMembers(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxObjectMembers must be > 0 but found [" + n + "]");
      this.maxObjectMembers = n;
      return this;
    }

    /**
     * Sets the maximum number of HTTP redirects to follow. Zero disables redirect following.
     * Must be &gt;= 0.
     *
     * @param n the limit.
     * @return this builder.
     * @throws IllegalArgumentException if {@code n} is negative.
     */
    public Builder maxRedirects(int n) {
      if (n < 0) throw new IllegalArgumentException("maxRedirects must be >= 0 but found [" + n + "]");
      this.maxRedirects = n;
      return this;
    }

    /**
     * Sets the maximum number of bytes read from an HTTP response body. Must be &gt; 0;
     * the response cap cannot be disabled.
     *
     * @param n the limit.
     * @return this builder.
     * @throws IllegalArgumentException if {@code n} is zero or negative.
     */
    public Builder maxResponseBytes(int n) {
      if (n <= 0) throw new IllegalArgumentException("maxResponseBytes must be > 0 but found [" + n + "] (the response cap cannot be disabled)");
      this.maxResponseBytes = n;
      return this;
    }
  }
}
