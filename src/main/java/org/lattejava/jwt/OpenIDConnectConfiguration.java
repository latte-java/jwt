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

import java.util.*;

/**
 * Models the commonly-deployed subset of OpenID Connect Discovery 1.0 Provider Metadata and RFC 8414 Authorization
 * Server Metadata. Every typed field is nullable — a pure-OAuth response will have null OIDC-specific fields, and an
 * OIDC response without RFC 8414 extras will have null introspection / revocation fields.
 *
 * <p>The typed surface is deliberately a subset, not a superset, of the full
 * metadata. Promoting an {@link #otherClaims()} key to a typed accessor in a future 7.x release is a non-breaking
 * addition. Construct via {@link #builder()}; the only network entry point is {@code OpenIDConnect.discover(String)} /
 * {@code OpenIDConnect.discoverFromWellKnown(String)}.</p>
 *
 * <p>Instances are immutable. List-typed accessors and {@link #otherClaims()}
 * return unmodifiable views.</p>
 */
public final class OpenIDConnectConfiguration {
  private static final Set<String> REGISTERED = Set.of(
      "acr_values_supported",
      "authorization_endpoint",
      "claims_supported",
      "code_challenge_methods_supported",
      "end_session_endpoint",
      "grant_types_supported",
      "id_token_signing_alg_values_supported",
      "introspection_endpoint",
      "issuer",
      "jwks_uri",
      "registration_endpoint",
      "request_parameter_supported",
      "request_uri_parameter_supported",
      "require_request_uri_registration",
      "response_modes_supported",
      "response_types_supported",
      "revocation_endpoint",
      "scopes_supported",
      "subject_types_supported",
      "token_endpoint",
      "token_endpoint_auth_methods_supported",
      "token_endpoint_auth_signing_alg_values_supported",
      "userinfo_endpoint"
  );
  private final List<String> acrValuesSupported;
  private final String authorizationEndpoint;
  private final List<String> claimsSupported;
  private final List<String> codeChallengeMethodsSupported;
  private final String endSessionEndpoint;
  private final List<String> grantTypesSupported;
  private final List<String> idTokenSigningAlgValuesSupported;
  private final String introspectionEndpoint;
  private final String issuer;
  private final String jwksURI;
  private final Map<String, Object> otherClaims;
  private final String registrationEndpoint;
  private final Boolean requestParameterSupported;
  private final Boolean requestURIParameterSupported;
  private final Boolean requireRequestURIRegistration;
  private final List<String> responseModesSupported;
  private final List<String> responseTypesSupported;
  private final String revocationEndpoint;
  private final List<String> scopesSupported;
  private final List<String> subjectTypesSupported;
  private final String tokenEndpoint;
  private final List<String> tokenEndpointAuthMethodsSupported;
  private final List<String> tokenEndpointAuthSigningAlgValuesSupported;
  private final String userinfoEndpoint;

  private OpenIDConnectConfiguration(Builder b) {
    this.acrValuesSupported = immutableCopy(b.acrValuesSupported);
    this.authorizationEndpoint = b.authorizationEndpoint;
    this.claimsSupported = immutableCopy(b.claimsSupported);
    this.codeChallengeMethodsSupported = immutableCopy(b.codeChallengeMethodsSupported);
    this.endSessionEndpoint = b.endSessionEndpoint;
    this.grantTypesSupported = immutableCopy(b.grantTypesSupported);
    this.idTokenSigningAlgValuesSupported = immutableCopy(b.idTokenSigningAlgValuesSupported);
    this.introspectionEndpoint = b.introspectionEndpoint;
    this.issuer = b.issuer;
    this.jwksURI = b.jwksURI;
    this.otherClaims = Collections.unmodifiableMap(new LinkedHashMap<>(b.otherClaims));
    this.registrationEndpoint = b.registrationEndpoint;
    this.requestParameterSupported = b.requestParameterSupported;
    this.requestURIParameterSupported = b.requestURIParameterSupported;
    this.requireRequestURIRegistration = b.requireRequestURIRegistration;
    this.responseModesSupported = immutableCopy(b.responseModesSupported);
    this.responseTypesSupported = immutableCopy(b.responseTypesSupported);
    this.revocationEndpoint = b.revocationEndpoint;
    this.scopesSupported = immutableCopy(b.scopesSupported);
    this.subjectTypesSupported = immutableCopy(b.subjectTypesSupported);
    this.tokenEndpoint = b.tokenEndpoint;
    this.tokenEndpointAuthMethodsSupported = immutableCopy(b.tokenEndpointAuthMethodsSupported);
    this.tokenEndpointAuthSigningAlgValuesSupported = immutableCopy(b.tokenEndpointAuthSigningAlgValuesSupported);
    this.userinfoEndpoint = b.userinfoEndpoint;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Package-private routing helper used by {@code OpenIDConnect.discover(String)}. Walks {@code map} dispatching
   * recognized snake_case keys to typed setters and unrecognized keys to {@link Builder#claim(String, Object)}. Rejects
   * a non-string element in any string-array typed field with {@link IllegalArgumentException}.
   */
  static OpenIDConnectConfiguration fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) continue;
      switch (name) {
        case "acr_values_supported":
          b.acrValuesSupported = stringList(value, name);
          break;
        case "authorization_endpoint":
          b.authorizationEndpoint = value.toString();
          break;
        case "claims_supported":
          b.claimsSupported = stringList(value, name);
          break;
        case "code_challenge_methods_supported":
          b.codeChallengeMethodsSupported = stringList(value, name);
          break;
        case "end_session_endpoint":
          b.endSessionEndpoint = value.toString();
          break;
        case "grant_types_supported":
          b.grantTypesSupported = stringList(value, name);
          break;
        case "id_token_signing_alg_values_supported":
          b.idTokenSigningAlgValuesSupported = stringList(value, name);
          break;
        case "introspection_endpoint":
          b.introspectionEndpoint = value.toString();
          break;
        case "issuer":
          b.issuer = value.toString();
          break;
        case "jwks_uri":
          b.jwksURI = value.toString();
          break;
        case "registration_endpoint":
          b.registrationEndpoint = value.toString();
          break;
        case "request_parameter_supported":
          b.requestParameterSupported = bool(value, name);
          break;
        case "request_uri_parameter_supported":
          b.requestURIParameterSupported = bool(value, name);
          break;
        case "require_request_uri_registration":
          b.requireRequestURIRegistration = bool(value, name);
          break;
        case "response_modes_supported":
          b.responseModesSupported = stringList(value, name);
          break;
        case "response_types_supported":
          b.responseTypesSupported = stringList(value, name);
          break;
        case "revocation_endpoint":
          b.revocationEndpoint = value.toString();
          break;
        case "scopes_supported":
          b.scopesSupported = stringList(value, name);
          break;
        case "subject_types_supported":
          b.subjectTypesSupported = stringList(value, name);
          break;
        case "token_endpoint":
          b.tokenEndpoint = value.toString();
          break;
        case "token_endpoint_auth_methods_supported":
          b.tokenEndpointAuthMethodsSupported = stringList(value, name);
          break;
        case "token_endpoint_auth_signing_alg_values_supported":
          b.tokenEndpointAuthSigningAlgValuesSupported = stringList(value, name);
          break;
        case "userinfo_endpoint":
          b.userinfoEndpoint = value.toString();
          break;
        default:
          b.otherClaims.put(name, value);
          break;
      }
    }
    return b.build();
  }

  private static Boolean bool(Object value, String name) {
    if (value instanceof Boolean bv) return bv;
    throw new IllegalArgumentException("Discovery field [" + name + "] must be a boolean");
  }

  private static List<String> immutableCopy(List<String> list) {
    return list == null ? null : List.copyOf(list);
  }

  private static void putIfPresent(Map<String, Object> out, String key, Object value) {
    if (value != null) out.put(key, value);
  }

  private static List<String> stringList(Object value, String name) {
    if (!(value instanceof List<?> list)) {
      throw new IllegalArgumentException("Discovery field [" + name + "] must be an array of strings");
    }
    List<String> result = new ArrayList<>();
    for (Object element : list) {
      if (!(element instanceof String s)) {
        throw new IllegalArgumentException("Discovery field [" + name + "] must be an array of strings");
      }
      result.add(s);
    }
    return result;
  }

  public List<String> acrValuesSupported() {
    return acrValuesSupported;
  }

  public String authorizationEndpoint() {
    return authorizationEndpoint;
  }

  public List<String> claimsSupported() {
    return claimsSupported;
  }

  public List<String> codeChallengeMethodsSupported() {
    return codeChallengeMethodsSupported;
  }

  public String endSessionEndpoint() {
    return endSessionEndpoint;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof OpenIDConnectConfiguration that)) return false;
    return Objects.equals(acrValuesSupported, that.acrValuesSupported)
        && Objects.equals(authorizationEndpoint, that.authorizationEndpoint)
        && Objects.equals(claimsSupported, that.claimsSupported)
        && Objects.equals(codeChallengeMethodsSupported, that.codeChallengeMethodsSupported)
        && Objects.equals(endSessionEndpoint, that.endSessionEndpoint)
        && Objects.equals(grantTypesSupported, that.grantTypesSupported)
        && Objects.equals(idTokenSigningAlgValuesSupported, that.idTokenSigningAlgValuesSupported)
        && Objects.equals(introspectionEndpoint, that.introspectionEndpoint)
        && Objects.equals(issuer, that.issuer)
        && Objects.equals(jwksURI, that.jwksURI)
        && Objects.equals(otherClaims, that.otherClaims)
        && Objects.equals(registrationEndpoint, that.registrationEndpoint)
        && Objects.equals(requestParameterSupported, that.requestParameterSupported)
        && Objects.equals(requestURIParameterSupported, that.requestURIParameterSupported)
        && Objects.equals(requireRequestURIRegistration, that.requireRequestURIRegistration)
        && Objects.equals(responseModesSupported, that.responseModesSupported)
        && Objects.equals(responseTypesSupported, that.responseTypesSupported)
        && Objects.equals(revocationEndpoint, that.revocationEndpoint)
        && Objects.equals(scopesSupported, that.scopesSupported)
        && Objects.equals(subjectTypesSupported, that.subjectTypesSupported)
        && Objects.equals(tokenEndpoint, that.tokenEndpoint)
        && Objects.equals(tokenEndpointAuthMethodsSupported, that.tokenEndpointAuthMethodsSupported)
        && Objects.equals(tokenEndpointAuthSigningAlgValuesSupported, that.tokenEndpointAuthSigningAlgValuesSupported)
        && Objects.equals(userinfoEndpoint, that.userinfoEndpoint);
  }

  public List<String> grantTypesSupported() {
    return grantTypesSupported;
  }

  @Override
  public int hashCode() {
    return Objects.hash(acrValuesSupported, authorizationEndpoint, claimsSupported,
        codeChallengeMethodsSupported, endSessionEndpoint, grantTypesSupported,
        idTokenSigningAlgValuesSupported, introspectionEndpoint, issuer, jwksURI,
        otherClaims, registrationEndpoint, requestParameterSupported,
        requestURIParameterSupported, requireRequestURIRegistration,
        responseModesSupported, responseTypesSupported, revocationEndpoint,
        scopesSupported, subjectTypesSupported, tokenEndpoint,
        tokenEndpointAuthMethodsSupported, tokenEndpointAuthSigningAlgValuesSupported,
        userinfoEndpoint);
  }

  public List<String> idTokenSigningAlgValuesSupported() {
    return idTokenSigningAlgValuesSupported;
  }

  public String introspectionEndpoint() {
    return introspectionEndpoint;
  }

  public String issuer() {
    return issuer;
  }

  public String jwksURI() {
    return jwksURI;
  }

  public Map<String, Object> otherClaims() {
    return otherClaims;
  }

  public String registrationEndpoint() {
    return registrationEndpoint;
  }

  public Boolean requestParameterSupported() {
    return requestParameterSupported;
  }

  public Boolean requestURIParameterSupported() {
    return requestURIParameterSupported;
  }

  public Boolean requireRequestURIRegistration() {
    return requireRequestURIRegistration;
  }

  public List<String> responseModesSupported() {
    return responseModesSupported;
  }

  public List<String> responseTypesSupported() {
    return responseTypesSupported;
  }

  public String revocationEndpoint() {
    return revocationEndpoint;
  }

  public List<String> scopesSupported() {
    return scopesSupported;
  }

  public List<String> subjectTypesSupported() {
    return subjectTypesSupported;
  }

  public String toJSON() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  /**
   * Map suitable for JSON serialization. Typed fields with non-null values appear under their snake_case names; entries
   * from {@link #otherClaims()} are flattened to top-level alongside the typed fields.
   *
   * @apiNote The returned map is mutable and not shared with the {@code OpenIDConnectConfiguration} instance.
   *     Callers MUST NOT retain or mutate it — the contract is that each call returns a fresh map intended for
   *     immediate handoff to a JSON serializer. List values reference the configuration's internal unmodifiable lists
   *     directly; the JSON serializer only iterates them.
   */
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    putIfPresent(out, "acr_values_supported", acrValuesSupported);
    putIfPresent(out, "authorization_endpoint", authorizationEndpoint);
    putIfPresent(out, "claims_supported", claimsSupported);
    putIfPresent(out, "code_challenge_methods_supported", codeChallengeMethodsSupported);
    putIfPresent(out, "end_session_endpoint", endSessionEndpoint);
    putIfPresent(out, "grant_types_supported", grantTypesSupported);
    putIfPresent(out, "id_token_signing_alg_values_supported", idTokenSigningAlgValuesSupported);
    putIfPresent(out, "introspection_endpoint", introspectionEndpoint);
    putIfPresent(out, "issuer", issuer);
    putIfPresent(out, "jwks_uri", jwksURI);
    putIfPresent(out, "registration_endpoint", registrationEndpoint);
    putIfPresent(out, "request_parameter_supported", requestParameterSupported);
    putIfPresent(out, "request_uri_parameter_supported", requestURIParameterSupported);
    putIfPresent(out, "require_request_uri_registration", requireRequestURIRegistration);
    putIfPresent(out, "response_modes_supported", responseModesSupported);
    putIfPresent(out, "response_types_supported", responseTypesSupported);
    putIfPresent(out, "revocation_endpoint", revocationEndpoint);
    putIfPresent(out, "scopes_supported", scopesSupported);
    putIfPresent(out, "subject_types_supported", subjectTypesSupported);
    putIfPresent(out, "token_endpoint", tokenEndpoint);
    putIfPresent(out, "token_endpoint_auth_methods_supported", tokenEndpointAuthMethodsSupported);
    putIfPresent(out, "token_endpoint_auth_signing_alg_values_supported", tokenEndpointAuthSigningAlgValuesSupported);
    putIfPresent(out, "userinfo_endpoint", userinfoEndpoint);
    for (Map.Entry<String, Object> e : otherClaims.entrySet()) {
      if (e.getValue() != null) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  @Override
  public String toString() {
    return toJSON();
  }

  public String tokenEndpoint() {
    return tokenEndpoint;
  }

  public List<String> tokenEndpointAuthMethodsSupported() {
    return tokenEndpointAuthMethodsSupported;
  }

  public List<String> tokenEndpointAuthSigningAlgValuesSupported() {
    return tokenEndpointAuthSigningAlgValuesSupported;
  }

  public String userinfoEndpoint() {
    return userinfoEndpoint;
  }

  /**
   * Reusable, mutable builder. Each {@link #build()} returns a fresh immutable {@link OpenIDConnectConfiguration} with
   * independent collection copies.
   */
  public static final class Builder {
    final Map<String, Object> otherClaims = new LinkedHashMap<>();
    List<String> acrValuesSupported;
    String authorizationEndpoint;
    List<String> claimsSupported;
    List<String> codeChallengeMethodsSupported;
    String endSessionEndpoint;
    List<String> grantTypesSupported;
    List<String> idTokenSigningAlgValuesSupported;
    String introspectionEndpoint;
    String issuer;
    String jwksURI;
    String registrationEndpoint;
    Boolean requestParameterSupported;
    Boolean requestURIParameterSupported;
    Boolean requireRequestURIRegistration;
    List<String> responseModesSupported;
    List<String> responseTypesSupported;
    String revocationEndpoint;
    List<String> scopesSupported;
    List<String> subjectTypesSupported;
    String tokenEndpoint;
    List<String> tokenEndpointAuthMethodsSupported;
    List<String> tokenEndpointAuthSigningAlgValuesSupported;
    String userinfoEndpoint;

    private Builder() {
    }

    public Builder acrValuesSupported(List<String> v) {
      this.acrValuesSupported = v;
      return this;
    }

    public Builder authorizationEndpoint(String v) {
      this.authorizationEndpoint = v;
      return this;
    }

    public OpenIDConnectConfiguration build() {
      return new OpenIDConnectConfiguration(this);
    }

    public Builder claim(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (REGISTERED.contains(name)) {
        throw new IllegalArgumentException("Cannot add a typed discovery field [" + name + "] via claim(); use the typed setter");
      }
      otherClaims.put(name, value);
      return this;
    }

    public Builder claimsSupported(List<String> v) {
      this.claimsSupported = v;
      return this;
    }

    public Builder codeChallengeMethodsSupported(List<String> v) {
      this.codeChallengeMethodsSupported = v;
      return this;
    }

    public Builder endSessionEndpoint(String v) {
      this.endSessionEndpoint = v;
      return this;
    }

    public Builder grantTypesSupported(List<String> v) {
      this.grantTypesSupported = v;
      return this;
    }

    public Builder idTokenSigningAlgValuesSupported(List<String> v) {
      this.idTokenSigningAlgValuesSupported = v;
      return this;
    }

    public Builder introspectionEndpoint(String v) {
      this.introspectionEndpoint = v;
      return this;
    }

    public Builder issuer(String v) {
      this.issuer = v;
      return this;
    }

    public Builder jwksURI(String v) {
      this.jwksURI = v;
      return this;
    }

    public Builder registrationEndpoint(String v) {
      this.registrationEndpoint = v;
      return this;
    }

    public Builder requestParameterSupported(Boolean v) {
      this.requestParameterSupported = v;
      return this;
    }

    public Builder requestURIParameterSupported(Boolean v) {
      this.requestURIParameterSupported = v;
      return this;
    }

    public Builder requireRequestURIRegistration(Boolean v) {
      this.requireRequestURIRegistration = v;
      return this;
    }

    public Builder responseModesSupported(List<String> v) {
      this.responseModesSupported = v;
      return this;
    }

    public Builder responseTypesSupported(List<String> v) {
      this.responseTypesSupported = v;
      return this;
    }

    public Builder revocationEndpoint(String v) {
      this.revocationEndpoint = v;
      return this;
    }

    public Builder scopesSupported(List<String> v) {
      this.scopesSupported = v;
      return this;
    }

    public Builder subjectTypesSupported(List<String> v) {
      this.subjectTypesSupported = v;
      return this;
    }

    public Builder tokenEndpoint(String v) {
      this.tokenEndpoint = v;
      return this;
    }

    public Builder tokenEndpointAuthMethodsSupported(List<String> v) {
      this.tokenEndpointAuthMethodsSupported = v;
      return this;
    }

    public Builder tokenEndpointAuthSigningAlgValuesSupported(List<String> v) {
      this.tokenEndpointAuthSigningAlgValuesSupported = v;
      return this;
    }

    public Builder userinfoEndpoint(String v) {
      this.userinfoEndpoint = v;
      return this;
    }
  }
}
