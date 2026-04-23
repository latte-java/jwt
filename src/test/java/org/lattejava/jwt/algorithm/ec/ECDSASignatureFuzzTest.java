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

package org.lattejava.jwt.algorithm.ec;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.BaseJWTTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * Sign-then-verify fuzz for each supported ECDSA curve. These rapidly
 * exercise r/s integers with random high-bit patterns and small values so
 * that the DER↔JOSE conversion is repeatedly round-tripped against the JCE
 * implementation. Catches regressions in
 * {@link org.lattejava.jwt.internal.JOSEConverter} that unit tests would
 * miss (e.g., off-by-one padding).
 *
 * @author Daniel DeGroff
 */
public class ECDSASignatureFuzzTest extends BaseJWTTest {
  private static final SecureRandom RNG = new SecureRandom();

  private KeyPair p256;

  private KeyPair p384;

  private KeyPair p521;

  private String openssl521Pem;

  @BeforeClass
  public void setupKeys() throws Exception {
    p256 = generate("secp256r1");
    p384 = generate("secp384r1");
    p521 = generate("secp521r1");
    // OpenSSL-generated P-521 PEM that carries both the private key and an
    // encoded public key (see PEMDecoder behavior). Using one file for both
    // signer and verifier guarantees the public/private match and stresses
    // the 66-byte curve-int path with a non-JCE-generated key.
    openssl521Pem = readFile("ec_private_secp521r1_p_512_openssl_pkcs8.pem");
  }

  @Test(invocationCount = 2_000)
  public void fuzz_ES256_P256() throws Exception {
    ECSigner signer = ECSigner.newSHA256Signer(p256.getPrivate());
    ECVerifier verifier = ECVerifier.newVerifier(p256.getPublic());
    signThenVerify(signer, verifier, Algorithm.ES256);
  }

  @Test(invocationCount = 2_000)
  public void fuzz_ES384_P384() throws Exception {
    ECSigner signer = ECSigner.newSHA384Signer(p384.getPrivate());
    ECVerifier verifier = ECVerifier.newVerifier(p384.getPublic());
    signThenVerify(signer, verifier, Algorithm.ES384);
  }

  @Test(invocationCount = 2_000)
  public void fuzz_ES512_P521() throws Exception {
    ECSigner signer = ECSigner.newSHA512Signer(p521.getPrivate());
    ECVerifier verifier = ECVerifier.newVerifier(p521.getPublic());
    signThenVerify(signer, verifier, Algorithm.ES512);
  }

  @Test(invocationCount = 2_000)
  public void fuzz_ES512_OpensslKey() throws Exception {
    ECSigner signer = ECSigner.newSHA512Signer(openssl521Pem);
    ECVerifier verifier = ECVerifier.newVerifier(openssl521Pem);
    signThenVerify(signer, verifier, Algorithm.ES512);
  }

  private void signThenVerify(ECSigner signer, ECVerifier verifier, Algorithm algorithm) {
    byte[] message = new byte[64];
    RNG.nextBytes(message);
    byte[] signature = signer.sign(message);
    verifier.verify(algorithm, message, signature);
  }

  private static KeyPair generate(String curve) throws Exception {
    java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
    kpg.initialize(new java.security.spec.ECGenParameterSpec(curve));
    return kpg.generateKeyPair();
  }
}
