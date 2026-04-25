/*
 * Copyright (c) 2016-2025, FusionAuth, All Rights Reserved
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

import org.lattejava.jwt.jwks.JSONWebKey;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.internal.pem.PEM;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.lattejava.jwt.internal.pem.PEM.PKCS_8_PRIVATE_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_8_PRIVATE_KEY_SUFFIX;
import static org.lattejava.jwt.internal.pem.PEM.X509_PUBLIC_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.X509_PUBLIC_KEY_SUFFIX;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class JWTUtilsTest extends BaseTest {
  // decodeHeader/decodePayload moved to JWTDecoder.decodeUnsecured().
  @Test
  public void decodePayload() {
    JWT jwt = JWT.builder().subject("123456789").build();

    // HMAC signed
    String encodedJWT = new org.lattejava.jwt.JWTEncoder().encode(jwt, HMACSigner.newSHA512Signer("super-secret-key-1-that-is-at-least-64-bytes-long-for-sha512-algorithm-compat-req!!"));
    JWT decoded = new JWTDecoder().decodeUnsecured(encodedJWT);
    assertEquals(decoded.subject(), "123456789");
    Assert.assertEquals(decoded.header().alg(), Algorithm.HS512);
  }

  @Test
  public void generateECKey() {
    // 256-bit key
    KeyPair keyPair256 = JWTUtils.generate256_ECKeyPair();
    ECPrivateKey privateKey256 = PEM.decode(keyPair256.privateKey).getPrivateKey();
    ECPublicKey publicKey256 = PEM.decode(keyPair256.publicKey).getPublicKey();

    assertEquals(privateKey256.getAlgorithm(), "EC");
    assertEquals(privateKey256.getFormat(), "PKCS#8");
    assertEquals(privateKey256.getParams().getCurve().getField().getFieldSize(), 256);

    assertEquals(publicKey256.getAlgorithm(), "EC");
    assertEquals(publicKey256.getFormat(), "X.509");
    assertEquals(publicKey256.getParams().getCurve().getField().getFieldSize(), 256);

    assertPrefix(keyPair256.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair256.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair256.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair256.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    //   NOTE: some JCE providers don't include the public key from calling privateKey.getEncoded(), which is why we are
    //   passing both in here. This is the only way to consistently ensure that the PEM encoding is the same as the original
    String actualPrivateKey256 = PEM.encode(privateKey256, publicKey256);
    String actualPublicKey256 = PEM.encode(publicKey256);
    assertEquals(actualPrivateKey256, keyPair256.privateKey);
    assertEquals(actualPublicKey256, keyPair256.publicKey);

    // 384-bit key
    KeyPair keyPair384 = JWTUtils.generate384_ECKeyPair();
    ECPrivateKey privateKey384 = PEM.decode(keyPair384.privateKey).getPrivateKey();
    ECPublicKey publicKey384 = PEM.decode(keyPair384.publicKey).getPublicKey();

    assertEquals(privateKey384.getAlgorithm(), "EC");
    assertEquals(privateKey384.getFormat(), "PKCS#8");
    assertEquals(privateKey384.getParams().getCurve().getField().getFieldSize(), 384);

    assertEquals(publicKey384.getAlgorithm(), "EC");
    assertEquals(publicKey384.getFormat(), "X.509");
    assertEquals(publicKey384.getParams().getCurve().getField().getFieldSize(), 384);

    assertPrefix(keyPair384.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair384.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair384.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair384.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    //   NOTE: some JCE providers don't include the public key from calling privateKey.getEncoded(), which is why we are
    //   passing both in here. This is the only way to consistently ensure that the PEM encoding is the same as the original
    String actualPrivateKey384 = PEM.encode(privateKey384, publicKey384);
    String actualPublicKey384 = PEM.encode(publicKey384);
    assertEquals(actualPrivateKey384, keyPair384.privateKey);
    assertEquals(actualPublicKey384, keyPair384.publicKey);

    // 521-bit key
    KeyPair keyPair521 = JWTUtils.generate521_ECKeyPair();
    ECPrivateKey privateKey521 = PEM.decode(keyPair521.privateKey).getPrivateKey();
    ECPublicKey publicKey521 = PEM.decode(keyPair521.publicKey).getPublicKey();

    assertEquals(privateKey521.getAlgorithm(), "EC");
    assertEquals(privateKey521.getFormat(), "PKCS#8");
    assertEquals(privateKey521.getParams().getCurve().getField().getFieldSize(), 521);

    assertEquals(publicKey521.getAlgorithm(), "EC");
    assertEquals(publicKey521.getFormat(), "X.509");
    assertEquals(publicKey521.getParams().getCurve().getField().getFieldSize(), 521);

    assertPrefix(keyPair521.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair521.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair521.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair521.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    //   NOTE: some JCE providers don't include the public key from calling privateKey.getEncoded(), which is why we are
    //   passing both in here. This is the only way to consistently ensure that the PEM encoding is the same as the original
    String actualPrivateKey521 = PEM.encode(privateKey521, publicKey521);
    String actualPublicKey521 = PEM.encode(publicKey521);
    assertEquals(actualPrivateKey521, keyPair521.privateKey);
    assertEquals(actualPublicKey521, keyPair521.publicKey);
  }

  @Test
  public void generate_ed25519_EdDSAKeyPair() {
    KeyPair keyPair = JWTUtils.generate_ed25519_EdDSAKeyPair();
    EdECPrivateKey privateKey = PEM.decode(keyPair.privateKey).getPrivateKey();
    EdECPublicKey publicKey = PEM.decode(keyPair.publicKey).getPublicKey();

    assertEquals(privateKey.getAlgorithm(), FipsEnabled ? "Ed25519" : "EdDSA");
    assertEquals(privateKey.getFormat(), "PKCS#8");
    assertEquals(privateKey.getParams().getName(), "Ed25519");
    assertEquals(privateKey.getBytes().orElseThrow().length, 32);

    assertEquals(publicKey.getAlgorithm(), FipsEnabled ? "Ed25519" : "EdDSA");
    assertEquals(publicKey.getFormat(), "X.509");
  }

  @Test
  public void generate_ed448_EdDSAKeyPair() {
    KeyPair keyPair = JWTUtils.generate_ed448_EdDSAKeyPair();
    EdECPrivateKey privateKey = PEM.decode(keyPair.privateKey).getPrivateKey();
    EdECPublicKey publicKey = PEM.decode(keyPair.publicKey).getPublicKey();

    assertEquals(privateKey.getAlgorithm(), FipsEnabled ? "Ed448" : "EdDSA");
    assertEquals(privateKey.getFormat(), "PKCS#8");
    assertEquals(privateKey.getParams().getName(), "Ed448");
    assertEquals(privateKey.getBytes().orElseThrow().length, 57);

    assertEquals(publicKey.getAlgorithm(), FipsEnabled ? "Ed448" : "EdDSA");
    assertEquals(publicKey.getFormat(), "X.509");
  }

  @Test
  public void generateRSAPSS_key() {
    // 2048-bit key
    KeyPair keyPair2048 = JWTUtils.generate2048_RSAPSSKeyPair();
    RSAPrivateKey privateKey2048 = PEM.decode(keyPair2048.privateKey).getPrivateKey();
    RSAPublicKey publicKey2048 = PEM.decode(keyPair2048.publicKey).getPublicKey();

    assertEquals(privateKey2048.getModulus().bitLength(), 2048);
    assertEquals(privateKey2048.getAlgorithm(), "RSASSA-PSS");
    assertEquals(privateKey2048.getFormat(), "PKCS#8");

    assertEquals(publicKey2048.getModulus().bitLength(), 2048);
    assertEquals(publicKey2048.getAlgorithm(), "RSASSA-PSS");
    assertEquals(publicKey2048.getFormat(), "X.509");

    assertPrefix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair2048.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair2048.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey2048 = PEM.encode(privateKey2048);
    String actualPublicKey2048 = PEM.encode(publicKey2048);
    assertEquals(actualPrivateKey2048, keyPair2048.privateKey);
    assertEquals(actualPublicKey2048, keyPair2048.publicKey);

    // 3072-bit key
    KeyPair keyPair3072 = JWTUtils.generate3072_RSAPSSKeyPair();
    RSAPrivateKey privateKey3072 = PEM.decode(keyPair3072.privateKey).getPrivateKey();
    RSAPublicKey publicKey3072 = PEM.decode(keyPair3072.publicKey).getPublicKey();

    assertEquals(privateKey3072.getModulus().bitLength(), 3072);
    assertEquals(privateKey3072.getAlgorithm(), "RSASSA-PSS");
    assertEquals(privateKey3072.getFormat(), "PKCS#8");

    assertEquals(publicKey3072.getModulus().bitLength(), 3072);
    assertEquals(publicKey3072.getAlgorithm(), "RSASSA-PSS");
    assertEquals(publicKey3072.getFormat(), "X.509");

    assertPrefix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair3072.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair3072.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey3072 = PEM.encode(privateKey3072);
    String actualPublicKey3072 = PEM.encode(publicKey3072);
    assertEquals(actualPrivateKey3072, keyPair3072.privateKey);
    assertEquals(actualPublicKey3072, keyPair3072.publicKey);

    // 4096-bit key
    KeyPair keyPair4096 = JWTUtils.generate4096_RSAPSSKeyPair();
    RSAPrivateKey privateKey4096 = PEM.decode(keyPair4096.privateKey).getPrivateKey();
    RSAPublicKey publicKey4096 = PEM.decode(keyPair4096.publicKey).getPublicKey();

    assertEquals(privateKey4096.getModulus().bitLength(), 4096);
    assertEquals(privateKey4096.getAlgorithm(), "RSASSA-PSS");
    assertEquals(privateKey4096.getFormat(), "PKCS#8");

    assertEquals(publicKey4096.getModulus().bitLength(), 4096);
    assertEquals(publicKey4096.getAlgorithm(), "RSASSA-PSS");
    assertEquals(publicKey4096.getFormat(), "X.509");

    assertPrefix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair4096.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair4096.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey4096 = PEM.encode(privateKey4096);
    String actualPublicKey4096 = PEM.encode(publicKey4096);
    assertEquals(actualPrivateKey4096, keyPair4096.privateKey);
    assertEquals(actualPublicKey4096, keyPair4096.publicKey);
  }

  @Test
  public void generateRSAKey() {
    // 2048-bit key
    KeyPair keyPair2048 = JWTUtils.generate2048_RSAKeyPair();
    RSAPrivateKey privateKey2048 = PEM.decode(keyPair2048.privateKey).getPrivateKey();
    RSAPublicKey publicKey2048 = PEM.decode(keyPair2048.publicKey).getPublicKey();

    assertEquals(privateKey2048.getModulus().bitLength(), 2048);
    assertEquals(privateKey2048.getAlgorithm(), "RSA");
    assertEquals(privateKey2048.getFormat(), "PKCS#8");

    assertEquals(publicKey2048.getModulus().bitLength(), 2048);
    assertEquals(publicKey2048.getAlgorithm(), "RSA");
    assertEquals(publicKey2048.getFormat(), "X.509");

    assertPrefix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair2048.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair2048.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair2048.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey2048 = PEM.encode(privateKey2048);
    String actualPublicKey2048 = PEM.encode(publicKey2048);
    assertEquals(actualPrivateKey2048, keyPair2048.privateKey);
    assertEquals(actualPublicKey2048, keyPair2048.publicKey);

    // 3072-bit key
    KeyPair keyPair3072 = JWTUtils.generate3072_RSAKeyPair();
    RSAPrivateKey privateKey3072 = PEM.decode(keyPair3072.privateKey).getPrivateKey();
    RSAPublicKey publicKey3072 = PEM.decode(keyPair3072.publicKey).getPublicKey();

    assertEquals(privateKey3072.getModulus().bitLength(), 3072);
    assertEquals(privateKey3072.getAlgorithm(), "RSA");
    assertEquals(privateKey3072.getFormat(), "PKCS#8");

    assertEquals(publicKey3072.getModulus().bitLength(), 3072);
    assertEquals(publicKey3072.getAlgorithm(), "RSA");
    assertEquals(publicKey3072.getFormat(), "X.509");

    assertPrefix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair3072.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair3072.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair3072.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey3072 = PEM.encode(privateKey3072);
    String actualPublicKey3072 = PEM.encode(publicKey3072);
    assertEquals(actualPrivateKey3072, keyPair3072.privateKey);
    assertEquals(actualPublicKey3072, keyPair3072.publicKey);

    // 4096-bit key
    KeyPair keyPair4096 = JWTUtils.generate4096_RSAKeyPair();
    RSAPrivateKey privateKey4096 = PEM.decode(keyPair4096.privateKey).getPrivateKey();
    RSAPublicKey publicKey4096 = PEM.decode(keyPair4096.publicKey).getPublicKey();

    assertEquals(privateKey4096.getModulus().bitLength(), 4096);
    assertEquals(privateKey4096.getAlgorithm(), "RSA");
    assertEquals(privateKey4096.getFormat(), "PKCS#8");

    assertEquals(publicKey4096.getModulus().bitLength(), 4096);
    assertEquals(publicKey4096.getAlgorithm(), "RSA");
    assertEquals(publicKey4096.getFormat(), "X.509");

    assertPrefix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_PREFIX);
    assertSuffix(keyPair4096.privateKey, PKCS_8_PRIVATE_KEY_SUFFIX);
    assertPrefix(keyPair4096.publicKey, X509_PUBLIC_KEY_PREFIX);
    assertSuffix(keyPair4096.publicKey, X509_PUBLIC_KEY_SUFFIX);

    // Now go backwards from the key to a PEM and assert they come out the same.
    String actualPrivateKey4096 = PEM.encode(privateKey4096);
    String actualPublicKey4096 = PEM.encode(publicKey4096);
    assertEquals(actualPrivateKey4096, keyPair4096.privateKey);
    assertEquals(actualPublicKey4096, keyPair4096.publicKey);
  }

  @Test
  public void hmacSecretLengths() {
    String hmac256 = JWTUtils.generateSHA256_HMACSecret();
    assertEquals(hmac256.length(), 44);
    assertEquals(Base64.getDecoder().decode(hmac256.getBytes(StandardCharsets.UTF_8)).length, 32);

    String hmac384 = JWTUtils.generateSHA384_HMACSecret();
    assertEquals(hmac384.length(), 64);
    assertEquals(Base64.getDecoder().decode(hmac384.getBytes(StandardCharsets.UTF_8)).length, 48);

    String hmac512 = JWTUtils.generateSHA512_HMACSecret();
    assertEquals(hmac512.length(), 88);
    assertEquals(Base64.getDecoder().decode(hmac512.getBytes(StandardCharsets.UTF_8)).length, 64);
  }

  @Test
  public void jws_kid_rsaControl() {
    // Control example from RFC 7638
    // https://tools.ietf.org/html/rfc7638#section-3.1
    JSONWebKey rsaKey = JSONWebKey.builder()
        .kty(KeyType.RSA)
        .n("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
        .e("AQAB")
        .build();

    // SHA-1
    assertEquals(rsaKey.thumbprintSHA1(), "nMGlFRw9Y5POaSOaIaRBc9P2nfA");

    // SHA-256
    assertEquals(rsaKey.thumbprintSHA256(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
  }

  @Test
  public void jws_kid_ec() {
    JSONWebKey ecKey = JSONWebKey.builder()
        .kty(KeyType.EC)
        .crv("P-256")
        .x("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
        .y("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
        .build();

    // SHA-1
    assertEquals(ecKey.thumbprintSHA1(), "VHriznG7vJAFpXMXRmGgAkA5sEE");

    // SHA-256
    assertEquals(ecKey.thumbprintSHA256(), "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");
  }

  @Test
  public void jws_kid_eddsa() {
    // Control example from RFC 8037 (the SHA-256 thumbprint)
    // https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.3
    JSONWebKey eddsaKey = JSONWebKey.builder()
        .kty(KeyType.OKP)
        .crv("Ed25519")
        .x("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
        .build();

    // SHA-1
    assertEquals(eddsaKey.thumbprintSHA1(), "VmxEWEmFxGLRPOX30HXyts0yJOE");

    // SHA-256
    assertEquals(eddsaKey.thumbprintSHA256(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  }

  private void assertPrefix(String key, String prefix) {
    assertTrue(key.startsWith(prefix));
  }

  private void assertSuffix(String key, String suffix) {
    String trimmed = key.trim();
    assertTrue(trimmed.endsWith(suffix));
  }
}
