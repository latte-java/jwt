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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Server Metadata as defined by <a href="https://tools.ietf.org/html/rfc8414">RFC 8414</a>.
 *
 * <p>Mutable POJO with a fluent {@link Builder}. Use {@link #fromMap(Map)} for
 * JSON-driven construction and {@link #toSerializableMap()} for serialization
 * via a {@link org.lattejava.jwt.JSONProcessor}.</p>
 *
 * @author Daniel DeGroff
 */
public class AuthorizationServerMetaData {
  private static final java.util.Set<String> REGISTERED = new java.util.HashSet<>(java.util.Arrays.asList(
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

  public String authorization_endpoint;

  public List<String> code_challenge_methods_supported;

  public List<String> grant_types_supported;

  public String introspection_endpoint;

  public List<String> introspection_endpoint_auth_methods_supported;

  public List<String> introspection_endpoint_auth_signing_alg_values_supported;

  public String issuer;

  public String jwks_uri;

  public String op_policy_uri;

  public String op_tos_uri;

  public Map<String, Object> otherClaims = new LinkedHashMap<>();

  public String registration_endpoint;

  public List<String> response_modes_supported;

  public List<String> response_types_supported;

  public String revocation_endpoint;

  public List<String> revocation_endpoint_auth_methods_supported;

  public List<String> revocation_endpoint_auth_signing_alg_values_supported;

  public List<String> scopes_supported;

  public String service_documentation;

  public String token_endpoint;

  public List<String> token_endpoint_auth_methods_supported;

  public List<String> token_endpoint_auth_signing_alg_values_supported;

  public List<String> ui_locales_supported;

  public Map<String, Object> getOtherClaims() {
    return otherClaims;
  }

  /**
   * Map suitable for JSON serialization. Registered RFC 8414 fields appear
   * under their specified names; non-registered claims are emitted from
   * {@link #otherClaims}.
   */
  public Map<String, Object> toSerializableMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    putIfPresent(out, "authorization_endpoint", authorization_endpoint);
    putIfPresent(out, "code_challenge_methods_supported", code_challenge_methods_supported);
    putIfPresent(out, "grant_types_supported", grant_types_supported);
    putIfPresent(out, "introspection_endpoint", introspection_endpoint);
    putIfPresent(out, "introspection_endpoint_auth_methods_supported", introspection_endpoint_auth_methods_supported);
    putIfPresent(out, "introspection_endpoint_auth_signing_alg_values_supported", introspection_endpoint_auth_signing_alg_values_supported);
    putIfPresent(out, "issuer", issuer);
    putIfPresent(out, "jwks_uri", jwks_uri);
    putIfPresent(out, "op_policy_uri", op_policy_uri);
    putIfPresent(out, "op_tos_uri", op_tos_uri);
    putIfPresent(out, "registration_endpoint", registration_endpoint);
    putIfPresent(out, "response_modes_supported", response_modes_supported);
    putIfPresent(out, "response_types_supported", response_types_supported);
    putIfPresent(out, "revocation_endpoint", revocation_endpoint);
    putIfPresent(out, "revocation_endpoint_auth_methods_supported", revocation_endpoint_auth_methods_supported);
    putIfPresent(out, "revocation_endpoint_auth_signing_alg_values_supported", revocation_endpoint_auth_signing_alg_values_supported);
    putIfPresent(out, "scopes_supported", scopes_supported);
    putIfPresent(out, "service_documentation", service_documentation);
    putIfPresent(out, "token_endpoint", token_endpoint);
    putIfPresent(out, "token_endpoint_auth_methods_supported", token_endpoint_auth_methods_supported);
    putIfPresent(out, "token_endpoint_auth_signing_alg_values_supported", token_endpoint_auth_signing_alg_values_supported);
    putIfPresent(out, "ui_locales_supported", ui_locales_supported);
    if (otherClaims != null) {
      for (Map.Entry<String, Object> e : otherClaims.entrySet()) {
        if (e.getValue() != null && !REGISTERED.contains(e.getKey())) {
          out.put(e.getKey(), e.getValue());
        }
      }
    }
    return out;
  }

  private static void putIfPresent(Map<String, Object> out, String key, Object value) {
    if (value != null) {
      out.put(key, value);
    }
  }

  @SuppressWarnings("unchecked")
  public static AuthorizationServerMetaData fromMap(Map<String, Object> map) {
    Objects.requireNonNull(map, "map");
    AuthorizationServerMetaData m = new AuthorizationServerMetaData();
    for (Map.Entry<String, Object> entry : map.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      if (value == null) continue;
      switch (name) {
        case "authorization_endpoint": m.authorization_endpoint = value.toString(); break;
        case "code_challenge_methods_supported": m.code_challenge_methods_supported = stringList(value, name); break;
        case "grant_types_supported": m.grant_types_supported = stringList(value, name); break;
        case "introspection_endpoint": m.introspection_endpoint = value.toString(); break;
        case "introspection_endpoint_auth_methods_supported": m.introspection_endpoint_auth_methods_supported = stringList(value, name); break;
        case "introspection_endpoint_auth_signing_alg_values_supported": m.introspection_endpoint_auth_signing_alg_values_supported = stringList(value, name); break;
        case "issuer": m.issuer = value.toString(); break;
        case "jwks_uri": m.jwks_uri = value.toString(); break;
        case "op_policy_uri": m.op_policy_uri = value.toString(); break;
        case "op_tos_uri": m.op_tos_uri = value.toString(); break;
        case "registration_endpoint": m.registration_endpoint = value.toString(); break;
        case "response_modes_supported": m.response_modes_supported = stringList(value, name); break;
        case "response_types_supported": m.response_types_supported = stringList(value, name); break;
        case "revocation_endpoint": m.revocation_endpoint = value.toString(); break;
        case "revocation_endpoint_auth_methods_supported": m.revocation_endpoint_auth_methods_supported = stringList(value, name); break;
        case "revocation_endpoint_auth_signing_alg_values_supported": m.revocation_endpoint_auth_signing_alg_values_supported = stringList(value, name); break;
        case "scopes_supported": m.scopes_supported = stringList(value, name); break;
        case "service_documentation": m.service_documentation = value.toString(); break;
        case "token_endpoint": m.token_endpoint = value.toString(); break;
        case "token_endpoint_auth_methods_supported": m.token_endpoint_auth_methods_supported = stringList(value, name); break;
        case "token_endpoint_auth_signing_alg_values_supported": m.token_endpoint_auth_signing_alg_values_supported = stringList(value, name); break;
        case "ui_locales_supported": m.ui_locales_supported = stringList(value, name); break;
        default: m.otherClaims.put(name, value); break;
      }
    }
    return m;
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
    AuthorizationServerMetaData metaData = (AuthorizationServerMetaData) o;
    return Objects.equals(authorization_endpoint, metaData.authorization_endpoint) && Objects.equals(code_challenge_methods_supported, metaData.code_challenge_methods_supported) && Objects.equals(grant_types_supported, metaData.grant_types_supported) && Objects.equals(introspection_endpoint, metaData.introspection_endpoint) && Objects.equals(introspection_endpoint_auth_methods_supported, metaData.introspection_endpoint_auth_methods_supported) && Objects.equals(introspection_endpoint_auth_signing_alg_values_supported, metaData.introspection_endpoint_auth_signing_alg_values_supported) && Objects.equals(issuer, metaData.issuer) && Objects.equals(jwks_uri, metaData.jwks_uri) && Objects.equals(op_policy_uri, metaData.op_policy_uri) && Objects.equals(op_tos_uri, metaData.op_tos_uri) && Objects.equals(otherClaims, metaData.otherClaims) && Objects.equals(registration_endpoint, metaData.registration_endpoint) && Objects.equals(response_modes_supported, metaData.response_modes_supported) && Objects.equals(response_types_supported, metaData.response_types_supported) && Objects.equals(revocation_endpoint, metaData.revocation_endpoint) && Objects.equals(revocation_endpoint_auth_methods_supported, metaData.revocation_endpoint_auth_methods_supported) && Objects.equals(revocation_endpoint_auth_signing_alg_values_supported, metaData.revocation_endpoint_auth_signing_alg_values_supported) && Objects.equals(scopes_supported, metaData.scopes_supported) && Objects.equals(service_documentation, metaData.service_documentation) && Objects.equals(token_endpoint, metaData.token_endpoint) && Objects.equals(token_endpoint_auth_methods_supported, metaData.token_endpoint_auth_methods_supported) && Objects.equals(token_endpoint_auth_signing_alg_values_supported, metaData.token_endpoint_auth_signing_alg_values_supported) && Objects.equals(ui_locales_supported, metaData.ui_locales_supported);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorization_endpoint, code_challenge_methods_supported, grant_types_supported, introspection_endpoint, introspection_endpoint_auth_methods_supported, introspection_endpoint_auth_signing_alg_values_supported, issuer, jwks_uri, op_policy_uri, op_tos_uri, otherClaims, registration_endpoint, response_modes_supported, response_types_supported, revocation_endpoint, revocation_endpoint_auth_methods_supported, revocation_endpoint_auth_signing_alg_values_supported, scopes_supported, service_documentation, token_endpoint, token_endpoint_auth_methods_supported, token_endpoint_auth_signing_alg_values_supported, ui_locales_supported);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private final AuthorizationServerMetaData m = new AuthorizationServerMetaData();

    public Builder authorizationEndpoint(String v)                                       { m.authorization_endpoint = v; return this; }
    public Builder codeChallengeMethodsSupported(List<String> v)                         { m.code_challenge_methods_supported = v; return this; }
    public Builder grantTypesSupported(List<String> v)                                   { m.grant_types_supported = v; return this; }
    public Builder introspectionEndpoint(String v)                                       { m.introspection_endpoint = v; return this; }
    public Builder introspectionEndpointAuthMethodsSupported(List<String> v)             { m.introspection_endpoint_auth_methods_supported = v; return this; }
    public Builder introspectionEndpointAuthSigningAlgValuesSupported(List<String> v)    { m.introspection_endpoint_auth_signing_alg_values_supported = v; return this; }
    public Builder issuer(String v)                                                      { m.issuer = v; return this; }
    public Builder jwksUri(String v)                                                     { m.jwks_uri = v; return this; }
    public Builder opPolicyUri(String v)                                                 { m.op_policy_uri = v; return this; }
    public Builder opTosUri(String v)                                                    { m.op_tos_uri = v; return this; }
    public Builder registrationEndpoint(String v)                                        { m.registration_endpoint = v; return this; }
    public Builder responseModesSupported(List<String> v)                                { m.response_modes_supported = v; return this; }
    public Builder responseTypesSupported(List<String> v)                                { m.response_types_supported = v; return this; }
    public Builder revocationEndpoint(String v)                                          { m.revocation_endpoint = v; return this; }
    public Builder revocationEndpointAuthMethodsSupported(List<String> v)                { m.revocation_endpoint_auth_methods_supported = v; return this; }
    public Builder revocationEndpointAuthSigningAlgValuesSupported(List<String> v)       { m.revocation_endpoint_auth_signing_alg_values_supported = v; return this; }
    public Builder scopesSupported(List<String> v)                                       { m.scopes_supported = v; return this; }
    public Builder serviceDocumentation(String v)                                        { m.service_documentation = v; return this; }
    public Builder tokenEndpoint(String v)                                               { m.token_endpoint = v; return this; }
    public Builder tokenEndpointAuthMethodsSupported(List<String> v)                     { m.token_endpoint_auth_methods_supported = v; return this; }
    public Builder tokenEndpointAuthSigningAlgValuesSupported(List<String> v)            { m.token_endpoint_auth_signing_alg_values_supported = v; return this; }
    public Builder uiLocalesSupported(List<String> v)                                    { m.ui_locales_supported = v; return this; }

    public Builder claim(String name, Object value) {
      Objects.requireNonNull(name, "name");
      if (REGISTERED.contains(name)) {
        throw new IllegalArgumentException("Cannot add a registered server-metadata claim [" + name + "]; use the typed setter.");
      }
      m.otherClaims.put(name, value);
      return this;
    }

    public AuthorizationServerMetaData build() {
      AuthorizationServerMetaData out = new AuthorizationServerMetaData();
      out.authorization_endpoint = m.authorization_endpoint;
      out.code_challenge_methods_supported = m.code_challenge_methods_supported;
      out.grant_types_supported = m.grant_types_supported;
      out.introspection_endpoint = m.introspection_endpoint;
      out.introspection_endpoint_auth_methods_supported = m.introspection_endpoint_auth_methods_supported;
      out.introspection_endpoint_auth_signing_alg_values_supported = m.introspection_endpoint_auth_signing_alg_values_supported;
      out.issuer = m.issuer;
      out.jwks_uri = m.jwks_uri;
      out.op_policy_uri = m.op_policy_uri;
      out.op_tos_uri = m.op_tos_uri;
      out.registration_endpoint = m.registration_endpoint;
      out.response_modes_supported = m.response_modes_supported;
      out.response_types_supported = m.response_types_supported;
      out.revocation_endpoint = m.revocation_endpoint;
      out.revocation_endpoint_auth_methods_supported = m.revocation_endpoint_auth_methods_supported;
      out.revocation_endpoint_auth_signing_alg_values_supported = m.revocation_endpoint_auth_signing_alg_values_supported;
      out.scopes_supported = m.scopes_supported;
      out.service_documentation = m.service_documentation;
      out.token_endpoint = m.token_endpoint;
      out.token_endpoint_auth_methods_supported = m.token_endpoint_auth_methods_supported;
      out.token_endpoint_auth_signing_alg_values_supported = m.token_endpoint_auth_signing_alg_values_supported;
      out.ui_locales_supported = m.ui_locales_supported;
      out.otherClaims.putAll(m.otherClaims);
      return out;
    }
  }
}
