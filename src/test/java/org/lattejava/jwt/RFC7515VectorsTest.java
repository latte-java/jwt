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

import org.lattejava.jwt.algorithm.ec.ECVerifier;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Spec §14 "Wire-format Compatibility Tests" -- RFC 7515 Appendix A test
 * vectors verify correctly. Each vector is the canonical published example
 * from RFC 7515.
 *
 * <p>For ES256 and ES512 only verification is exercised (per RFC 7515
 * Appendix A.3 / A.4 the signing operation is randomized, so the
 * library cannot reproduce the published signature byte-for-byte; but
 * verifying the published signature with the published key is the
 * spec-anchoring contract).</p>
 *
 * @author The Latte Project
 */
public class RFC7515VectorsTest extends BaseJWTTest {
  private static byte[] b64u(String in) {
    return Base64.getUrlDecoder().decode(in);
  }

  private static BigInteger b64uPositive(String in) {
    return new BigInteger(1, b64u(in));
  }

  // RFC 7515 Appendix A.1 -- HS256 -- published shared key (256 bits) is the
  // JWK octet sequence given in §A.1.1.
  private static final byte[] HS256_KEY = b64u(
      "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

  // RFC 7515 §A.1 published JWS Compact Serialization (the entire token).
  private static final String HS256_JWS =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
          + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
          + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  // RFC 7515 §A.2 published RSA public key (n, e). 2048-bit.
  private static final BigInteger RS256_N = b64uPositive(
      "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw"
          + "-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL"
          + "-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4"
          + "LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ");

  private static final BigInteger RS256_E = b64uPositive("AQAB");

  // RFC 7515 §A.2 published JWS for HS-style claims; signature is deterministic for RSASSA-PKCS1-v1_5.
  private static final String RS256_JWS =
      "eyJhbGciOiJSUzI1NiJ9"
          + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
          + ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

  // RFC 7515 §A.3 published EC P-256 public key.
  private static final BigInteger ES256_X = b64uPositive("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");

  private static final BigInteger ES256_Y = b64uPositive("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");

  private static final String ES256_JWS =
      "eyJhbGciOiJFUzI1NiJ9"
          + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
          + ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

  // RFC 7515 §A.4 published EC P-521 public key.
  private static final BigInteger ES512_X = b64uPositive("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk");

  private static final BigInteger ES512_Y = b64uPositive("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2");

  private static final String ES512_JWS =
      "eyJhbGciOiJFUzUxMiJ9"
          + ".UGF5bG9hZA"
          + ".AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";

  private static PublicKey rsaPublic(BigInteger n, BigInteger e) {
    try {
      return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  private static PublicKey ecPublic(String curveName, BigInteger x, BigInteger y) {
    try {
      java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
      params.init(new java.security.spec.ECGenParameterSpec(curveName));
      java.security.spec.ECParameterSpec ecSpec = params.getParameterSpec(java.security.spec.ECParameterSpec.class);
      return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecSpec));
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * The published RFC 7515 vectors have {@code exp:1300819380} (March 2011),
   * which is in the past. Decoding with a real clock would raise
   * {@link JWTExpiredException}; we pin the clock to a moment before the
   * vector's {@code exp}.
   */
  private static JWTDecoder vectorClockDecoder() {
    return new JWTDecoder.Builder()
        .fixedTime(java.time.Instant.ofEpochSecond(1300819300L))
        .build();
  }

  // Use case: RFC 7515 Appendix A.1 -- HS256 published vector verifies.
  @Test
  public void rfc7515_appendixA1_hs256_verifies() {
    Verifier v = HMACVerifier.newVerifier(HS256_KEY);
    JWT jwt = vectorClockDecoder().decode(HS256_JWS, VerifierResolver.of(v));
    assertNotNull(jwt);
    assertEquals(jwt.issuer(), "joe");
    assertEquals(jwt.expiresAt().getEpochSecond(), 1300819380L);
    assertEquals(jwt.getBoolean("http://example.com/is_root"), Boolean.TRUE);
  }

  // Use case: RFC 7515 Appendix A.2 -- RS256 published vector verifies with the
  // published RSA public key.
  @Test
  public void rfc7515_appendixA2_rs256_verifies() {
    Verifier v = RSAVerifier.newVerifier(rsaPublic(RS256_N, RS256_E));
    JWT jwt = vectorClockDecoder().decode(RS256_JWS, VerifierResolver.of(v));
    assertNotNull(jwt);
    assertEquals(jwt.issuer(), "joe");
  }

  // Use case: RFC 7515 Appendix A.3 -- ES256 published vector verifies.
  // Signing is randomized so we only verify; this is the spec contract.
  @Test
  public void rfc7515_appendixA3_es256_verifies() {
    Verifier v = ECVerifier.newVerifier(ecPublic("secp256r1", ES256_X, ES256_Y));
    JWT jwt = vectorClockDecoder().decode(ES256_JWS, VerifierResolver.of(v));
    assertNotNull(jwt);
    assertEquals(jwt.issuer(), "joe");
  }

  // Use case: RFC 7515 Appendix A.4 -- ES512 published vector verifies.
  // Note A.4 uses a non-JSON payload "Payload"; we decodeUnsecured-with-verify
  // is not applicable. Decode would fail because the payload is not a JSON
  // object. We exercise the verifier directly using the signing input bytes.
  @Test
  public void rfc7515_appendixA4_es512_verifies() {
    Verifier v = ECVerifier.newVerifier(ecPublic("secp521r1", ES512_X, ES512_Y));
    String[] parts = ES512_JWS.split("\\.");
    assertEquals(parts.length, 3);
    String signingInput = parts[0] + "." + parts[1];
    byte[] signature = b64u(parts[2]);
    // canVerify must accept ES512.
    assert v.canVerify(Algorithm.ES512);
    v.verify(Algorithm.ES512, signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8), signature);
  }
}
