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

import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import org.lattejava.jwt.algorithm.ec.*;
import org.lattejava.jwt.algorithm.ed.*;
import org.lattejava.jwt.algorithm.hmac.*;
import org.lattejava.jwt.algorithm.rsa.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

/**
 * Verifies that every {@link Signer}/{@link Verifier} pair is safe to share across threads. Each call to {@code sign()}
 * / {@code verify()} must obtain a fresh JCA primitive ({@code Mac}/{@code Signature}) -- reusing one across threads
 * produces corrupted state and/or intermittent {@code SignatureException}s.
 *
 * @author Daniel DeGroff
 */
public class SignerVerifierThreadSafetyTest extends BaseJWTTest {
  private static final int ITERATIONS_PER_THREAD = 100;
  private static final int THREAD_COUNT = 32;

  @Test(dataProvider = "signerVerifierPairs")
  public void sharedAcrossThreads(String label, Signer signer, Verifier verifier) throws Exception {
    byte[] message = ("thread-safety test for " + label).getBytes();
    ExecutorService pool = Executors.newFixedThreadPool(THREAD_COUNT);
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(THREAD_COUNT);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    try {
      for (int t = 0; t < THREAD_COUNT; t++) {
        pool.submit(() -> {
          try {
            start.await();
            for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
              byte[] signature = signer.sign(message);
              verifier.verify(message, signature);
            }
          } catch (Throwable th) {
            failure.compareAndSet(null, th);
          } finally {
            done.countDown();
          }
        });
      }
      start.countDown();
      assertTrue(done.await(60, TimeUnit.SECONDS), "Threads did not complete in time for [" + label + "]");
      assertNull(failure.get(), "Concurrent sign/verify failed for [" + label + "]: " + failure.get());
    } finally {
      pool.shutdownNow();
    }
  }

  @DataProvider(name = "signerVerifierPairs")
  public Object[][] signerVerifierPairs() {
    String hmacSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    String rsaPriv = readFile("rsa_private_key_2048.pem");
    String rsaPub = readFile("rsa_public_key_2048.pem");
    String ecPriv256 = readFile("ec_private_key_p_256.pem");
    String ecPub256 = readFile("ec_public_key_p_256.pem");
    String ecPriv384 = readFile("ec_private_key_p_384.pem");
    String ecPub384 = readFile("ec_public_key_p_384.pem");
    String ecPriv521 = readFile("ec_private_key_p_521.pem");
    String ecPub521 = readFile("ec_public_key_p_521.pem");
    String ed25519Priv = readFile("ed_dsa_ed25519_private_key.pem");
    String ed25519Pub = readFile("ed_dsa_ed25519_public_key.pem");
    String ed448Priv = readFile("ed_dsa_ed448_private_key.pem");
    String ed448Pub = readFile("ed_dsa_ed448_public_key.pem");
    return new Object[][]{
        {"HS256", HMACSigner.newSHA256Signer(hmacSecret), HMACVerifier.newVerifier(Algorithm.HS256, hmacSecret)},
        {"HS384", HMACSigner.newSHA384Signer(hmacSecret), HMACVerifier.newVerifier(Algorithm.HS384, hmacSecret)},
        {"HS512", HMACSigner.newSHA512Signer(hmacSecret), HMACVerifier.newVerifier(Algorithm.HS512, hmacSecret)},
        {"RS256", RSASigner.newSHA256Signer(rsaPriv), RSAVerifier.newVerifier(Algorithm.RS256, rsaPub)},
        {"RS384", RSASigner.newSHA384Signer(rsaPriv), RSAVerifier.newVerifier(Algorithm.RS384, rsaPub)},
        {"RS512", RSASigner.newSHA512Signer(rsaPriv), RSAVerifier.newVerifier(Algorithm.RS512, rsaPub)},
        {"PS256", RSAPSSSigner.newSHA256Signer(rsaPriv), RSAPSSVerifier.newVerifier(Algorithm.PS256, rsaPub)},
        {"PS384", RSAPSSSigner.newSHA384Signer(rsaPriv), RSAPSSVerifier.newVerifier(Algorithm.PS384, rsaPub)},
        {"PS512", RSAPSSSigner.newSHA512Signer(rsaPriv), RSAPSSVerifier.newVerifier(Algorithm.PS512, rsaPub)},
        {"ES256", ECSigner.newSHA256Signer(ecPriv256), ECVerifier.newVerifier(ecPub256)},
        {"ES384", ECSigner.newSHA384Signer(ecPriv384), ECVerifier.newVerifier(ecPub384)},
        {"ES512", ECSigner.newSHA512Signer(ecPriv521), ECVerifier.newVerifier(ecPub521)},
        {"Ed25519", EdDSASigner.newSigner(ed25519Priv), EdDSAVerifier.newVerifier(ed25519Pub)},
        {"Ed448", EdDSASigner.newSigner(ed448Priv), EdDSAVerifier.newVerifier(ed448Pub)},
    };
  }
}
