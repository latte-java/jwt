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

package org.lattejava.jwt.oauth2;

import org.lattejava.jwt.LatteJSONProcessor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Server Metadata as defined by <a href="https://tools.ietf.org/html/rfc8414">RFC 8414</a>.
 *
 * <p>Immutable. Construct via {@link #builder()} or {@link #fromMap(Map)} and
 * serialize via {@link #toSerializableMap()} through a
 * {@link org.lattejava.jwt.JSONProcessor}.</p>
 *
 * @author Daniel DeGroff
 */
public class AuthorizationServerMetaData {
  private static final Set<String> REGISTERED = new HashSet<>(Arrays.asList(
      "authorization_endpoint",
      "code_challenge_methods_supported",
      "grant_types_supported",
      "introspection_endpoint",
      "introspection_endpoint_auth_methods_supported",
      "introspection_endpoint_auth_signing_alg_values_supported",
      "issuer",
      "jwks_uri",
      "op_policy_uri",
      "op_tos_uri",
      "registration_endpoint",
      "response_modes_supported",
      "response_types_supported",
      "revocation_endpoint",
      "revocation_endpoint_auth_methods_supported",
      "revocation_endpoint_auth_signing_alg_values_supported",
      "scopes_supported",
      "service_documentation",
      "token_endpoint",
      "token_endpoint_auth_methods_supported",
      "token_endpoint_auth_signing_alg_values_supported",
      "ui_locales_supported"
  ));

  private final String authorizationEndpoint;

  private final List<String> codeChallengeMethodsSupported;

  private final List<String> grantTypesSupported;

  private final String introspectionEndpoint;

  private final List<String> introspectionEndpointAuthMethodsSupported;

  private final List<String> introspectionEndpointAuthSigningAlgValuesSupported;

  private final String issuer;

  private final String jwksUri;

  private final String opPolicyUri;

  private final String opTosUri;

  private final Map<String, Object> otherClaims;

  private final String registrationEndpoint;

  private final List<String> responseModesSupported;

  private final List<String> responseTypesSupported;

  private final String revocationEndpoint;

  private final List<String> revocationEndpointAuthMethodsSupported;

  private final List<String> revocationEndpointAuthSigningAlgValuesSupported;

  private final List<String> scopesSupported;

  private final String serviceDocumentation;

  private final String tokenEndpoint;

  private final List<String> tokenEndpointAuthMethodsSupported;

  private final List<String> tokenEndpointAuthSigningAlgValuesSupported;

  private final List<String> uiLocalesSupported;

  private AuthorizationServerMetaData(Builder b) {
    this.authorizationEndpoint = b.authorizationEndpoint;
    this.codeChallengeMethodsSupported = immutableCopy(b.codeChallengeMethodsSupported);
    this.grantTypesSupported = immutableCopy(b.grantTypesSupported);
    this.introspectionEndpoint = b.introspectionEndpoint;
    this.introspectionEndpointAuthMethodsSupported = immutableCopy(b.introspectionEndpointAuthMethodsSupported);
    this.introspectionEndpointAuthSigningAlgValuesSupported = immutableCopy(b.introspectionEndpointAuthSigningAlgValuesSupported);
    this.issuer = b.issuer;
    this.jwksUri = b.jwksUri;
    this.opPolicyUri = b.opPolicyUri;
    this.opTosUri = b.opTosUri;
    this.registrationEndpoint = b.registrationEndpoint;
    this.responseModesSupported = immutableCopy(b.responseModesSupported);
    this.responseTypesSupported = immutableCopy(b.responseTypesSupported);
    this.revocationEndpoint = b.revocationEndpoint;
    this.revocationEndpointAuthMethodsSupported = immutableCopy(b.revocationEndpointAuthMethodsSupported);
    this.revocationEndpointAuthSigningAlgValuesSupported = immutableCopy(b.revocationEndpointAuthSigningAlgValuesSupported);
    this.scopesSupported = immutableCopy(b.scopesSupported);
    this.serviceDocumentation = b.serviceDocumentation;
    this.tokenEndpoint = b.tokenEndpoint;
    this.tokenEndpointAuthMethodsSupported = immutableCopy(b.tokenEndpointAuthMethodsSupported);
    this.tokenEndpointAuthSigningAlgValuesSupported = immutableCopy(b.tokenEndpointAuthSigningAlgValuesSupported);
    this.uiLocalesSupported = immutableCopy(b.uiLocalesSupported);
    this.otherClaims = Collections.unmodifiableMap(new LinkedHashMap<>(b.otherClaims));
  }

  private static List<String> immutableCopy(List<String> list) {
    return list == null ? null : List.copyOf(list);
  }

  public String authorizationEndpoint() {
    return authorizationEndpoint;
  }

  public List<String> codeChallengeMethodsSupported() {
    return codeChallengeMethodsSupported;
  }

  public List<String> grantTypesSupported() {
    return grantTypesSupported;
  }

  public String introspectionEndpoint() {
    return introspectionEndpoint;
  }

  public List<String> introspectionEndpointAuthMethodsSupported() {
    return introspectionEndpointAuthMethodsSupported;
  }

  public List<String> introspectionEndpointAuthSigningAlgValuesSupported() {
    return introspectionEndpointAuthSigningAlgValuesSupported;
  }

  public String issuer() {
    return issuer;
  }

  public String jwksUri() {
    return jwksUri;
  }

  public String opPolicyUri() {
    return opPolicyUri;
  }

  public String opTosUri() {
    return opTosUri;
  }

  public Map<String, Object> otherClaims() {
    return otherClaims;
  }

  public String registrationEndpoint() {
    return registrationEndpoint;
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

  public List<String> revocationEndpointAuthMethodsSupported() {
    return revocationEndpointAuthMethodsSupported;
  }

  public List<String> revocationEndpointAuthSigningAlgValuesSupported() {
    return revocationEndpointAuthSigningAlgValuesSupported;
  }

  public List<String> scopesSupported() {
    return scopesSupported;
  }

  public String serviceDocumentation() {
    return serviceDocumentation;
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

  public List<String> uiLocalesSupported() {
    return uiLocalesSupported;
  }

  /**
   * Map suitable for JSON serialization. Registered RFC 8414 fields appear
   * under their specified names; non-registered claims are emitted from
   * {@link #otherClaims()}.
   */
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    putIfPresent(out, "authorization_endpoint", authorizationEndpoint);
    putIfPresent(out, "code_challenge_methods_supported", codeChallengeMethodsSupported);
    putIfPresent(out, "grant_types_supported", grantTypesSupported);
    putIfPresent(out, "introspection_endpoint", introspectionEndpoint);
    putIfPresent(out, "introspection_endpoint_auth_methods_supported", introspectionEndpointAuthMethodsSupported);
    putIfPresent(out, "introspection_endpoint_auth_signing_alg_values_supported", introspectionEndpointAuthSigningAlgValuesSupported);
    putIfPresent(out, "issuer", issuer);
    putIfPresent(out, "jwks_uri", jwksUri);
    putIfPresent(out, "op_policy_uri", opPolicyUri);
    putIfPresent(out, "op_tos_uri", opTosUri);
    putIfPresent(out, "registration_endpoint", registrationEndpoint);
    putIfPresent(out, "response_modes_supported", responseModesSupported);
    putIfPresent(out, "response_types_supported", responseTypesSupported);
    putIfPresent(out, "revocation_endpoint", revocationEndpoint);
    putIfPresent(out, "revocation_endpoint_auth_methods_supported", revocationEndpointAuthMethodsSupported);
    putIfPresent(out, "revocation_endpoint_auth_signing_alg_values_supported", revocationEndpointAuthSigningAlgValuesSupported);
    putIfPresent(out, "scopes_supported", scopesSupported);
    putIfPresent(out, "service_documentation", serviceDocumentation);
    putIfPresent(out, "token_endpoint", tokenEndpoint);
    putIfPresent(out, "token_endpoint_auth_methods_supported", tokenEndpointAuthMethodsSupported);
    putIfPresent(out, "token_endpoint_auth_signing_alg_values_supported", tokenEndpointAuthSigningAlgValuesSupported);
    putIfPresent(out, "ui_locales_supported", uiLocalesSupported);
    for (Map.Entry<String, Object> e : otherClaims.entrySet()) {
      if (e.getValue() != null && !REGISTERED.contains(e.getKey())) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  private static void putIfPresent(Map<String, Object> out, String key, Object value) {
    if (value != null) {
      out.put(key, value);
    }
  }

  public static AuthorizationServerMetaData fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    Builder b = new Builder();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) continue;
      switch (name) {
        case "authorization_endpoint": b.authorizationEndpoint = value.toString(); break;
        case "code_challenge_methods_supported": b.codeChallengeMethodsSupported = stringList(value, name); break;
        case "grant_types_supported": b.grantTypesSupported = stringList(value, name); break;
        case "introspection_endpoint": b.introspectionEndpoint = value.toString(); break;
        case "introspection_endpoint_auth_methods_supported": b.introspectionEndpointAuthMethodsSupported = stringList(value, name); break;
        case "introspection_endpoint_auth_signing_alg_values_supported": b.introspectionEndpointAuthSigningAlgValuesSupported = stringList(value, name); break;
        case "issuer": b.issuer = value.toString(); break;
        case "jwks_uri": b.jwksUri = value.toString(); break;
        case "op_policy_uri": b.opPolicyUri = value.toString(); break;
        case "op_tos_uri": b.opTosUri = value.toString(); break;
        case "registration_endpoint": b.registrationEndpoint = value.toString(); break;
        case "response_modes_supported": b.responseModesSupported = stringList(value, name); break;
        case "response_types_supported": b.responseTypesSupported = stringList(value, name); break;
        case "revocation_endpoint": b.revocationEndpoint = value.toString(); break;
        case "revocation_endpoint_auth_methods_supported": b.revocationEndpointAuthMethodsSupported = stringList(value, name); break;
        case "revocation_endpoint_auth_signing_alg_values_supported": b.revocationEndpointAuthSigningAlgValuesSupported = stringList(value, name); break;
        case "scopes_supported": b.scopesSupported = stringList(value, name); break;
        case "service_documentation": b.serviceDocumentation = value.toString(); break;
        case "token_endpoint": b.tokenEndpoint = value.toString(); break;
        case "token_endpoint_auth_methods_supported": b.tokenEndpointAuthMethodsSupported = stringList(value, name); break;
        case "token_endpoint_auth_signing_alg_values_supported": b.tokenEndpointAuthSigningAlgValuesSupported = stringList(value, name); break;
        case "ui_locales_supported": b.uiLocalesSupported = stringList(value, name); break;
        default: b.otherClaims.put(name, value); break;
      }
    }
    return b.build();
  }

  @SuppressWarnings("unchecked")
  private static List<String> stringList(Object value, String name) {
    if (!(value instanceof List)) {
      throw new IllegalArgumentException("Server metadata field [" + name + "] must be an array of strings.");
    }
    List<String> result = new ArrayList<>();
    for (Object element : (List<Object>) value) {
      if (!(element instanceof String)) {
        throw new IllegalArgumentException("Server metadata field [" + name + "] must be an array of strings.");
      }
      result.add((String) element);
    }
    return result;
  }

  public String toJSON() {
    return new String(new LatteJSONProcessor().serialize(toSerializableMap()));
  }

  @Override
  public String toString() {
    return toJSON();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AuthorizationServerMetaData that = (AuthorizationServerMetaData) o;
    return Objects.equals(authorizationEndpoint, that.authorizationEndpoint)
        && Objects.equals(codeChallengeMethodsSupported, that.codeChallengeMethodsSupported)
        && Objects.equals(grantTypesSupported, that.grantTypesSupported)
        && Objects.equals(introspectionEndpoint, that.introspectionEndpoint)
        && Objects.equals(introspectionEndpointAuthMethodsSupported, that.introspectionEndpointAuthMethodsSupported)
        && Objects.equals(introspectionEndpointAuthSigningAlgValuesSupported, that.introspectionEndpointAuthSigningAlgValuesSupported)
        && Objects.equals(issuer, that.issuer)
        && Objects.equals(jwksUri, that.jwksUri)
        && Objects.equals(opPolicyUri, that.opPolicyUri)
        && Objects.equals(opTosUri, that.opTosUri)
        && Objects.equals(otherClaims, that.otherClaims)
        && Objects.equals(registrationEndpoint, that.registrationEndpoint)
        && Objects.equals(responseModesSupported, that.responseModesSupported)
        && Objects.equals(responseTypesSupported, that.responseTypesSupported)
        && Objects.equals(revocationEndpoint, that.revocationEndpoint)
        && Objects.equals(revocationEndpointAuthMethodsSupported, that.revocationEndpointAuthMethodsSupported)
        && Objects.equals(revocationEndpointAuthSigningAlgValuesSupported, that.revocationEndpointAuthSigningAlgValuesSupported)
        && Objects.equals(scopesSupported, that.scopesSupported)
        && Objects.equals(serviceDocumentation, that.serviceDocumentation)
        && Objects.equals(tokenEndpoint, that.tokenEndpoint)
        && Objects.equals(tokenEndpointAuthMethodsSupported, that.tokenEndpointAuthMethodsSupported)
        && Objects.equals(tokenEndpointAuthSigningAlgValuesSupported, that.tokenEndpointAuthSigningAlgValuesSupported)
        && Objects.equals(uiLocalesSupported, that.uiLocalesSupported);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorizationEndpoint, codeChallengeMethodsSupported, grantTypesSupported,
        introspectionEndpoint, introspectionEndpointAuthMethodsSupported,
        introspectionEndpointAuthSigningAlgValuesSupported, issuer, jwksUri, opPolicyUri, opTosUri,
        otherClaims, registrationEndpoint, responseModesSupported, responseTypesSupported,
        revocationEndpoint, revocationEndpointAuthMethodsSupported,
        revocationEndpointAuthSigningAlgValuesSupported, scopesSupported, serviceDocumentation,
        tokenEndpoint, tokenEndpointAuthMethodsSupported,
        tokenEndpointAuthSigningAlgValuesSupported, uiLocalesSupported);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private String authorizationEndpoint;
    private List<String> codeChallengeMethodsSupported;
    private List<String> grantTypesSupported;
    private String introspectionEndpoint;
    private List<String> introspectionEndpointAuthMethodsSupported;
    private List<String> introspectionEndpointAuthSigningAlgValuesSupported;
    private String issuer;
    private String jwksUri;
    private String opPolicyUri;
    private String opTosUri;
    private final Map<String, Object> otherClaims = new LinkedHashMap<>();
    private String registrationEndpoint;
    private List<String> responseModesSupported;
    private List<String> responseTypesSupported;
    private String revocationEndpoint;
    private List<String> revocationEndpointAuthMethodsSupported;
    private List<String> revocationEndpointAuthSigningAlgValuesSupported;
    private List<String> scopesSupported;
    private String serviceDocumentation;
    private String tokenEndpoint;
    private List<String> tokenEndpointAuthMethodsSupported;
    private List<String> tokenEndpointAuthSigningAlgValuesSupported;
    private List<String> uiLocalesSupported;

    private Builder() {}

    public Builder authorizationEndpoint(String v)                                       { this.authorizationEndpoint = v; return this; }
    public Builder codeChallengeMethodsSupported(List<String> v)                         { this.codeChallengeMethodsSupported = v; return this; }
    public Builder grantTypesSupported(List<String> v)                                   { this.grantTypesSupported = v; return this; }
    public Builder introspectionEndpoint(String v)                                       { this.introspectionEndpoint = v; return this; }
    public Builder introspectionEndpointAuthMethodsSupported(List<String> v)             { this.introspectionEndpointAuthMethodsSupported = v; return this; }
    public Builder introspectionEndpointAuthSigningAlgValuesSupported(List<String> v)    { this.introspectionEndpointAuthSigningAlgValuesSupported = v; return this; }
    public Builder issuer(String v)                                                      { this.issuer = v; return this; }
    public Builder jwksUri(String v)                                                     { this.jwksUri = v; return this; }
    public Builder opPolicyUri(String v)                                                 { this.opPolicyUri = v; return this; }
    public Builder opTosUri(String v)                                                    { this.opTosUri = v; return this; }
    public Builder registrationEndpoint(String v)                                        { this.registrationEndpoint = v; return this; }
    public Builder responseModesSupported(List<String> v)                                { this.responseModesSupported = v; return this; }
    public Builder responseTypesSupported(List<String> v)                                { this.responseTypesSupported = v; return this; }
    public Builder revocationEndpoint(String v)                                          { this.revocationEndpoint = v; return this; }
    public Builder revocationEndpointAuthMethodsSupported(List<String> v)                { this.revocationEndpointAuthMethodsSupported = v; return this; }
    public Builder revocationEndpointAuthSigningAlgValuesSupported(List<String> v)       { this.revocationEndpointAuthSigningAlgValuesSupported = v; return this; }
    public Builder scopesSupported(List<String> v)                                       { this.scopesSupported = v; return this; }
    public Builder serviceDocumentation(String v)                                        { this.serviceDocumentation = v; return this; }
    public Builder tokenEndpoint(String v)                                               { this.tokenEndpoint = v; return this; }
    public Builder tokenEndpointAuthMethodsSupported(List<String> v)                     { this.tokenEndpointAuthMethodsSupported = v; return this; }
    public Builder tokenEndpointAuthSigningAlgValuesSupported(List<String> v)            { this.tokenEndpointAuthSigningAlgValuesSupported = v; return this; }
    public Builder uiLocalesSupported(List<String> v)                                    { this.uiLocalesSupported = v; return this; }

    public Builder claim(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (REGISTERED.contains(name)) {
        throw new IllegalArgumentException("Cannot add a registered server-metadata claim [" + name + "]; use the typed setter.");
      }
      otherClaims.put(name, value);
      return this;
    }

    public AuthorizationServerMetaData build() {
      return new AuthorizationServerMetaData(this);
    }
  }
}
