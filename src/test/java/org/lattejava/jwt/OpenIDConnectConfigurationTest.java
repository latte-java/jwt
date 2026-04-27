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

import org.testng.annotations.*;

import static org.testng.Assert.*;

public class OpenIDConnectConfigurationTest extends BaseTest {
  @Test
  public void builder_is_reusable_independent_collections() {
    // Use case: mutating a list passed to a setter after build() must not affect the built instance.
    java.util.List<String> scopes = new java.util.ArrayList<>(List.of("openid"));
    OpenIDConnectConfiguration.Builder b = OpenIDConnectConfiguration.builder()
                                                                     .issuer("a")
                                                                     .scopesSupported(scopes);
    OpenIDConnectConfiguration first = b.build();
    scopes.add("profile");  // mutate the original list AFTER build()
    OpenIDConnectConfiguration second = b.issuer("b").build();
    assertEquals(first.issuer(), "a");
    assertEquals(second.issuer(), "b");
    assertEquals(first.scopesSupported(), List.of("openid"));  // unaffected by post-build mutation
    assertEquals(second.scopesSupported(), List.of("openid", "profile"));  // sees current builder state
  }

  @Test
  public void claim_rejects_typed_field_keys() {
    // Use case: claim() must reject snake_case keys that are typed fields to prevent misuse
    OpenIDConnectConfiguration.Builder b = OpenIDConnectConfiguration.builder();
    assertThrows(IllegalArgumentException.class, () -> b.claim("issuer", "x"));
    assertThrows(IllegalArgumentException.class, () -> b.claim("jwks_uri", "x"));
    assertThrows(IllegalArgumentException.class, () -> b.claim("token_endpoint", "x"));
  }

  @Test
  public void equals_and_hashCode() {
    // Use case: two configurations with the same typed fields are equal and share the same hash code
    OpenIDConnectConfiguration a = OpenIDConnectConfiguration.builder().issuer("x").build();
    OpenIDConnectConfiguration b = OpenIDConnectConfiguration.builder().issuer("x").build();
    OpenIDConnectConfiguration c = OpenIDConnectConfiguration.builder().issuer("y").build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertNotEquals(c, a);
  }

  @Test
  public void fromMap_rejects_non_boolean_for_boolean_field() {
    // Use case: a string "true" where a boolean is expected must be rejected with a clear error.
    Map<String, Object> raw = Map.of("request_parameter_supported", "true");  // String, not Boolean
    assertThrows(IllegalArgumentException.class, () -> OpenIDConnectConfiguration.fromMap(raw));
  }

  @Test
  public void fromMap_rejects_non_list_for_string_array_field() {
    // Use case: a bare string where a list is expected must be rejected with a clear error.
    Map<String, Object> raw = Map.of("response_types_supported", "code");  // String, not List
    assertThrows(IllegalArgumentException.class, () -> OpenIDConnectConfiguration.fromMap(raw));
  }

  @Test
  public void fromMap_rejects_non_string_element_in_string_array_field() {
    // Use case: a numeric element inside a string-array field must be rejected.
    Map<String, Object> raw = Map.of("response_types_supported", List.of("code", 42));
    assertThrows(IllegalArgumentException.class, () -> OpenIDConnectConfiguration.fromMap(raw));
  }

  @Test
  public void fromMap_routes_typed_keys_and_otherClaims() {
    // Use case: discovery JSON parsed by LatteJSONProcessor → typed accessors + otherClaims for unknown keys.
    Map<String, Object> raw = new java.util.LinkedHashMap<>();
    raw.put("issuer", "https://example.com");
    raw.put("jwks_uri", "https://example.com/jwks");
    raw.put("response_types_supported", List.of("code"));
    raw.put("require_request_uri_registration", true);
    raw.put("mfa_challenge_endpoint", "https://example.com/mfa");
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.fromMap(raw);
    assertEquals(cfg.issuer(), "https://example.com");
    assertEquals(cfg.jwksURI(), "https://example.com/jwks");
    assertEquals(cfg.responseTypesSupported(), List.of("code"));
    assertEquals(cfg.requireRequestURIRegistration(), Boolean.TRUE);
    assertEquals(cfg.otherClaims().get("mfa_challenge_endpoint"), "https://example.com/mfa");
  }

  @Test
  public void fromMap_silently_skips_null_values() {
    // Use case: null values in the raw map are ignored rather than written as null into typed fields.
    Map<String, Object> raw = new java.util.LinkedHashMap<>();
    raw.put("issuer", "https://example.com");
    raw.put("jwks_uri", null);
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.fromMap(raw);
    assertEquals(cfg.issuer(), "https://example.com");
    assertNull(cfg.jwksURI());
  }

  @Test
  public void list_accessors_return_unmodifiable_views() {
    // Use case: callers cannot mutate list-typed fields through the accessor
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
                                                               .scopesSupported(List.of("openid", "profile"))
                                                               .build();
    assertThrows(UnsupportedOperationException.class, () -> cfg.scopesSupported().add("email"));
  }

  @Test
  public void otherClaims_returns_unmodifiable_view() {
    // Use case: callers cannot mutate the otherClaims map through the accessor
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
                                                               .claim("mfa_challenge_endpoint", "https://example.com/mfa")
                                                               .build();
    assertThrows(UnsupportedOperationException.class, () -> cfg.otherClaims().put("x", "y"));
  }

  @Test
  public void toJSON_round_trip_via_LatteJSONProcessor() throws Exception {
    // Use case: toJSON produces valid JSON that round-trips through LatteJSONProcessor with correct wire names
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
                                                               .issuer("https://example.com")
                                                               .jwksURI("https://example.com/.well-known/jwks.json")
                                                               .responseTypesSupported(List.of("code", "id_token"))
                                                               .requireRequestURIRegistration(true)
                                                               .claim("mfa_challenge_endpoint", "https://example.com/mfa")
                                                               .build();
    String json = cfg.toJSON();
    Map<String, Object> reparsed = new LatteJSONProcessor().deserialize(json.getBytes());
    assertEquals(reparsed.get("issuer"), "https://example.com");
    assertEquals(reparsed.get("jwks_uri"), "https://example.com/.well-known/jwks.json");
    assertEquals(reparsed.get("require_request_uri_registration"), true);
    assertEquals(reparsed.get("mfa_challenge_endpoint"), "https://example.com/mfa");
    assertFalse(reparsed.containsKey("token_endpoint"));
  }

  @Test
  public void toSerializableMap_flattens_otherClaims_to_top_level() {
    // Use case: otherClaims entries appear at the top level of the serializable map alongside typed fields
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
                                                               .issuer("x")
                                                               .claim("vendor_extension", 42)
                                                               .build();
    Map<String, Object> map = cfg.toSerializableMap();
    assertEquals(map.get("issuer"), "x");
    assertEquals(map.get("vendor_extension"), 42);
  }

  @Test
  public void toSerializableMap_omits_null_typed_fields() {
    // Use case: null-valued typed fields are omitted from the serializable map
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").build();
    Map<String, Object> map = cfg.toSerializableMap();
    assertTrue(map.containsKey("issuer"));
    assertFalse(map.containsKey("token_endpoint"));
    assertFalse(map.containsKey("jwks_uri"));
  }

  @Test
  public void toString_equals_toJSON() {
    // Use case: toString() is a stable alias for toJSON()
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().issuer("x").build();
    assertEquals(cfg.toString(), cfg.toJSON());
  }

  @Test
  public void typed_accessors_round_trip_through_builder() {
    // Use case: every typed accessor returns the value set on the builder
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder()
                                                               .acrValuesSupported(List.of("0"))
                                                               .authorizationEndpoint("https://example.com/auth")
                                                               .claimsSupported(List.of("sub"))
                                                               .codeChallengeMethodsSupported(List.of("S256"))
                                                               .endSessionEndpoint("https://example.com/logout")
                                                               .grantTypesSupported(List.of("authorization_code"))
                                                               .idTokenSigningAlgValuesSupported(List.of("RS256"))
                                                               .introspectionEndpoint("https://example.com/introspect")
                                                               .issuer("https://example.com")
                                                               .jwksURI("https://example.com/jwks")
                                                               .registrationEndpoint("https://example.com/register")
                                                               .requestParameterSupported(false)
                                                               .requestURIParameterSupported(true)
                                                               .requireRequestURIRegistration(false)
                                                               .responseModesSupported(List.of("query"))
                                                               .responseTypesSupported(List.of("code"))
                                                               .revocationEndpoint("https://example.com/revoke")
                                                               .scopesSupported(List.of("openid"))
                                                               .subjectTypesSupported(List.of("public"))
                                                               .tokenEndpoint("https://example.com/token")
                                                               .tokenEndpointAuthMethodsSupported(List.of("client_secret_basic"))
                                                               .tokenEndpointAuthSigningAlgValuesSupported(List.of("RS256"))
                                                               .userinfoEndpoint("https://example.com/userinfo")
                                                               .build();
    assertEquals(cfg.acrValuesSupported(), List.of("0"));
    assertEquals(cfg.authorizationEndpoint(), "https://example.com/auth");
    assertEquals(cfg.claimsSupported(), List.of("sub"));
    assertEquals(cfg.codeChallengeMethodsSupported(), List.of("S256"));
    assertEquals(cfg.endSessionEndpoint(), "https://example.com/logout");
    assertEquals(cfg.grantTypesSupported(), List.of("authorization_code"));
    assertEquals(cfg.idTokenSigningAlgValuesSupported(), List.of("RS256"));
    assertEquals(cfg.introspectionEndpoint(), "https://example.com/introspect");
    assertEquals(cfg.issuer(), "https://example.com");
    assertEquals(cfg.jwksURI(), "https://example.com/jwks");
    assertEquals(cfg.registrationEndpoint(), "https://example.com/register");
    assertEquals(cfg.requestParameterSupported(), Boolean.FALSE);
    assertEquals(cfg.requestURIParameterSupported(), Boolean.TRUE);
    assertEquals(cfg.requireRequestURIRegistration(), Boolean.FALSE);
    assertEquals(cfg.responseModesSupported(), List.of("query"));
    assertEquals(cfg.responseTypesSupported(), List.of("code"));
    assertEquals(cfg.revocationEndpoint(), "https://example.com/revoke");
    assertEquals(cfg.scopesSupported(), List.of("openid"));
    assertEquals(cfg.subjectTypesSupported(), List.of("public"));
    assertEquals(cfg.tokenEndpoint(), "https://example.com/token");
    assertEquals(cfg.tokenEndpointAuthMethodsSupported(), List.of("client_secret_basic"));
    assertEquals(cfg.tokenEndpointAuthSigningAlgValuesSupported(), List.of("RS256"));
    assertEquals(cfg.userinfoEndpoint(), "https://example.com/userinfo");
  }

  @Test
  public void unset_typed_accessors_return_null() {
    // Use case: unset typed fields return null, and otherClaims() returns an empty non-null map
    OpenIDConnectConfiguration cfg = OpenIDConnectConfiguration.builder().build();
    assertNull(cfg.issuer());
    assertNull(cfg.jwksURI());
    assertNull(cfg.scopesSupported());
    assertNull(cfg.requestParameterSupported());
    assertNotNull(cfg.otherClaims());
    assertTrue(cfg.otherClaims().isEmpty());
  }
}
