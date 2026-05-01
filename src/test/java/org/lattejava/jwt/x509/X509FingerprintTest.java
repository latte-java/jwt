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

import java.io.*;
import java.nio.charset.*;
import java.security.cert.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Tests for the X.509 certificate fingerprint and thumbprint helpers on {@link X509}.
 *
 * @author Daniel DeGroff
 */
public class X509FingerprintTest extends BaseJWTTest {

  private static final String BASE64_DER = "MIIC5jCCAc6gAwIBAgIQNCdDZLmeeL5H6O2BE+aQCjANBgkqhkiG9w0BAQsFADAvMS0wKwYDVQQDEyRBREZTIFNpZ25pbmcgLSB1bWdjb25uZWN0LnVtdXNpYy5jb20wHhcNMTcxMDE4MTUyOTAzWhcNMTgxMDE4MTUyOTAzWjAvMS0wKwYDVQQDEyRBREZTIFNpZ25pbmcgLSB1bWdjb25uZWN0LnVtdXNpYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnUl7AwWO1fjpijswRY40bs8jegA4Kz4ycM12h8PqD0CbydWyCnPmY/mzI8EPWsaT3uJ4QaYEEq+taNTu/GB8eFDs1flDb1JNjkZ2ECDZpdwgAS/z+RvI7D+tRARNUU7QvkMAOfFTb3zS4Cx52RoXlp3Bdrtzk9KaO/DJc7IoxLCAWuXL8kxuBRwfPzeQXX/i+wIRtkJAFotOq7j/XxgYO0/UzCenZDAr+Xbl8JfmrkFaegEQFwAC2/jlAP9OYjF39qD+9kI/HP9CcnXxoAIbq8lJkIKvuoURV9mErlel2Oj+tgvveq28NEV36RwqnfAqAIsAT4BTs739JUsnoHnKbAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGesHLA8V2/4ljxwbjeBsBBk8fJ4DGVufKJJXBit7jb37/9/XVtkVg1Y2IuVoYnzpnOxAZ/Zizp8/HKH2bApqEOcAU3oZ471FZlzXAv1G51S0i1UUD/OWgc3z84pk9AMtWSka26GOWA4pb/Mw/nrBrG3R8NY6ZgLZQqbYR2GQBj5JXbDsJtzYkVXY6N5KmsBekVJ92ddjKMy5SfcGY0j3BFFsBOUpaONWgBFAD2rOH9FnwoY7tcTKa5u4MfwSXMYLal/Vk9kFAtBV2Uqe/MgitB8OgAGYYqGU8VRPVH4K/n8sx5EarZPXcOJkHbI/C70Puc0jxra4e4/2c4HqifMAYQ=";

  private static X509Certificate parseCert(@SuppressWarnings("SameParameterValue") String base64Der) throws Exception {
    byte[] der = Base64.getDecoder().decode(base64Der.getBytes(StandardCharsets.UTF_8));
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
  }

  @Test
  public void encodingConversion() {
    // Use case: a configuration file or log line carries a hex SHA-1
    // fingerprint and you need the JOSE x5t form to put in a header.
    assertEquals(X509.fingerprintToThumbprint("BC34F6D776BF005E5E45D12529995AF7EF5DA5CF"),
        "vDT213a_AF5eRdElKZla9-9dpc8");
    assertEquals(X509.fingerprintToThumbprint("B4814D2DF3D8635E2C3340CB4E9E93F81677C8F68F50F29CF079E1E9EBD74DE3"),
        "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM");

    // Use case: reverse direction -- received an x5t value, want to display
    // it as a hex fingerprint to a human.
    assertEquals(X509.thumbprintToFingerprint("vDT213a_AF5eRdElKZla9-9dpc8"),
        "BC34F6D776BF005E5E45D12529995AF7EF5DA5CF");
    assertEquals(X509.thumbprintToFingerprint("tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM"),
        "B4814D2DF3D8635E2C3340CB4E9E93F81677C8F68F50F29CF079E1E9EBD74DE3");
  }

  @Test
  public void fingerprint_byteInput() {
    byte[] der = Base64.getDecoder().decode(BASE64_DER.getBytes(StandardCharsets.UTF_8));

    // Use case: caller has raw DER bytes (e.g., already decoded from a JWKS
    // x5c element) and wants the fingerprint without re-parsing the cert.
    assertEquals(X509.fingerprintSHA256(der),
        "B4814D2DF3D8635E2C3340CB4E9E93F81677C8F68F50F29CF079E1E9EBD74DE3");
    assertEquals(X509.fingerprintSHA1(der),
        "BC34F6D776BF005E5E45D12529995AF7EF5DA5CF");
  }

  @Test
  public void fingerprint_certInput() throws Exception {
    X509Certificate cert = parseCert(BASE64_DER);

    // Use case: get the modern (SHA-256) hex fingerprint of a cert, like
    // what `openssl x509 -fingerprint -sha256` shows.
    assertEquals(X509.fingerprintSHA256(cert),
        "B4814D2DF3D8635E2C3340CB4E9E93F81677C8F68F50F29CF079E1E9EBD74DE3");

    // Use case: get the legacy (SHA-1) hex fingerprint, equivalent to what
    // older Windows cert dialogs and `openssl x509 -fingerprint -sha1` show.
    assertEquals(X509.fingerprintSHA1(cert),
        "BC34F6D776BF005E5E45D12529995AF7EF5DA5CF");
  }

  @Test
  public void thumbprint_certAndByteInput() throws Exception {
    X509Certificate cert = parseCert(BASE64_DER);
    byte[] der = Base64.getDecoder().decode(BASE64_DER.getBytes(StandardCharsets.UTF_8));

    // Use case: produce the JWS-header `x5t#S256` (SHA-256, base64URL-no-pad).
    String expectedS256 = "tIFNLfPYY14sM0DLTp6T-BZ3yPaPUPKc8Hnh6evXTeM";
    assertEquals(X509.thumbprintSHA256(cert), expectedS256);
    assertEquals(X509.thumbprintSHA256(der), expectedS256);

    // Use case: produce the legacy JWS-header `x5t` (SHA-1, base64URL-no-pad).
    String expectedS1 = "vDT213a_AF5eRdElKZla9-9dpc8";
    assertEquals(X509.thumbprintSHA1(cert), expectedS1);
    assertEquals(X509.thumbprintSHA1(der), expectedS1);
  }
}
