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

package org.lattejava.jwt.x509;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.BaseJWTTest;
import org.lattejava.jwt.pem.PEM;
import org.lattejava.jwt.pem.PEMDecoder;
import org.lattejava.jwt.pem.PEMEncoder;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Tests for {@link X509}, the sun.*-free X.509 self-signed certificate builder.
 *
 * @author The Latte Project
 */
public class X509BuilderTest extends BaseJWTTest {

  @DataProvider(name = "signatureAlgorithms")
  public Object[][] signatureAlgorithms() {
    return new Object[][]{
        {Algorithm.RS256}, {Algorithm.RS384}, {Algorithm.RS512},
        {Algorithm.PS256}, {Algorithm.PS384}, {Algorithm.PS512},
        {Algorithm.ES256}, {Algorithm.ES384}, {Algorithm.ES512},
        {Algorithm.Ed25519}, {Algorithm.Ed448}
    };
  }

  @Test(dataProvider = "signatureAlgorithms")
  public void roundTrip_perAlgorithm(Algorithm algorithm) throws Exception {
    // Use case: For each supported signature algorithm, X509.builder() produces a
    // certificate that round-trips through CertificateFactory and preserves subject,
    // issuer, validity, serial, and public key.
    KeyPair kp = generateKeyPair(algorithm);
    Instant notBefore = Instant.parse("2024-01-01T00:00:00Z");
    Instant notAfter = notBefore.plus(365, ChronoUnit.DAYS);
    BigInteger serial = new BigInteger("1234567890");

    X509Certificate cert = X509.builder()
        .serialNumber(serial)
        .issuer("CN=Latte Test CA")
        .subject("CN=Latte Test Subject")
        .validity(notBefore, notAfter)
        .publicKey(kp.getPublic())
        .build(kp.getPrivate(), algorithm);

    assertNotNull(cert);

    // Round-trip via CertificateFactory using the encoded form.
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate parsed = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

    assertEquals(parsed.getSerialNumber(), serial);
    assertEquals(parsed.getSubjectX500Principal().getName(), "CN=Latte Test Subject");
    assertEquals(parsed.getIssuerX500Principal().getName(), "CN=Latte Test CA");
    assertEquals(parsed.getNotBefore().toInstant(), notBefore);
    assertEquals(parsed.getNotAfter().toInstant(), notAfter);
    assertEquals(parsed.getPublicKey(), kp.getPublic());

    // Self-signed: verify the cert against its own public key.
    parsed.verify(kp.getPublic());
  }

  @Test
  public void invalidValidity_rejected() throws Exception {
    // Use case: validity with notBefore > notAfter is rejected at build time.
    KeyPair kp = generateKeyPair(Algorithm.RS256);
    Instant t = Instant.parse("2024-01-01T00:00:00Z");
    X509.Builder b = X509.builder()
        .serialNumber(BigInteger.ONE)
        .issuer("CN=A")
        .subject("CN=A")
        .validity(t.plus(1, ChronoUnit.DAYS), t)
        .publicKey(kp.getPublic());
    assertThrows(IllegalStateException.class, () -> b.build(kp.getPrivate(), Algorithm.RS256));
  }

  @Test
  public void missingSubject_rejected() throws Exception {
    // Use case: missing subject is rejected.
    KeyPair kp = generateKeyPair(Algorithm.RS256);
    Instant now = Instant.parse("2024-01-01T00:00:00Z");
    X509.Builder b = X509.builder()
        .serialNumber(BigInteger.ONE)
        .issuer("CN=A")
        .validity(now, now.plus(30, ChronoUnit.DAYS))
        .publicKey(kp.getPublic());
    assertThrows(IllegalStateException.class, () -> b.build(kp.getPrivate(), Algorithm.RS256));
  }

  @Test
  public void missingPublicKey_rejected() throws Exception {
    // Use case: missing public key is rejected.
    KeyPair kp = generateKeyPair(Algorithm.RS256);
    Instant now = Instant.parse("2024-01-01T00:00:00Z");
    X509.Builder b = X509.builder()
        .serialNumber(BigInteger.ONE)
        .issuer("CN=A")
        .subject("CN=B")
        .validity(now, now.plus(30, ChronoUnit.DAYS));
    assertThrows(IllegalStateException.class, () -> b.build(kp.getPrivate(), Algorithm.RS256));
  }

  @Test
  public void missingSerial_rejected() throws Exception {
    // Use case: missing serial number is rejected.
    KeyPair kp = generateKeyPair(Algorithm.RS256);
    Instant now = Instant.parse("2024-01-01T00:00:00Z");
    X509.Builder b = X509.builder()
        .issuer("CN=A")
        .subject("CN=B")
        .validity(now, now.plus(30, ChronoUnit.DAYS))
        .publicKey(kp.getPublic());
    assertThrows(IllegalStateException.class, () -> b.build(kp.getPrivate(), Algorithm.RS256));
  }

  @Test
  public void pem_roundTrip() throws Exception {
    // Use case: a built certificate round-trips through PEM encoding and decoding.
    KeyPair kp = generateKeyPair(Algorithm.ES256);
    Instant now = Instant.parse("2024-01-01T00:00:00Z");
    X509Certificate cert = X509.builder()
        .serialNumber(BigInteger.valueOf(99))
        .issuer("CN=PEM Issuer")
        .subject("CN=PEM Subject")
        .validity(now, now.plus(30, ChronoUnit.DAYS))
        .publicKey(kp.getPublic())
        .build(kp.getPrivate(), Algorithm.ES256);
    String pem = new PEMEncoder().encode(cert);

    assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
    assertTrue(pem.contains("-----END CERTIFICATE-----"));

    PEM decoded = new PEMDecoder().decode(pem);
    assertNotNull(decoded.certificate);
    assertEquals(((X509Certificate) decoded.certificate).getSerialNumber(), BigInteger.valueOf(99));
  }

  @Test
  public void validity_acrossBoundary() throws Exception {
    // Use case: validity beyond the 2050 boundary uses GeneralizedTime for notAfter (RFC 5280 §4.1.2.5).
    KeyPair kp = generateKeyPair(Algorithm.ES256);
    Instant notBefore = Instant.parse("2049-12-31T00:00:00Z"); // UTCTime
    Instant notAfter = Instant.parse("2050-06-01T00:00:00Z"); // GeneralizedTime

    X509Certificate cert = X509.builder()
        .serialNumber(BigInteger.ONE)
        .issuer("CN=Boundary")
        .subject("CN=Boundary")
        .validity(notBefore, notAfter)
        .publicKey(kp.getPublic())
        .build(kp.getPrivate(), Algorithm.ES256);

    assertEquals(cert.getNotBefore().toInstant(), notBefore);
    assertEquals(cert.getNotAfter().toInstant(), notAfter);
  }

  // ---- Helpers ----

  static KeyPair generateKeyPair(Algorithm algorithm) throws Exception {
    String name = algorithm.name();
    if (name.startsWith("RS")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
      g.initialize(2048);
      return g.generateKeyPair();
    } else if (name.startsWith("PS")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("RSASSA-PSS");
      g.initialize(2048);
      return g.generateKeyPair();
    } else if (name.equals("ES256")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp256r1"));
      return g.generateKeyPair();
    } else if (name.equals("ES384")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp384r1"));
      return g.generateKeyPair();
    } else if (name.equals("ES512")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp521r1"));
      return g.generateKeyPair();
    } else if (name.equals("Ed25519")) {
      return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    } else if (name.equals("Ed448")) {
      return KeyPairGenerator.getInstance("Ed448").generateKeyPair();
    }
    throw new IllegalArgumentException("Unsupported algorithm: " + name);
  }
}
