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

import org.lattejava.jwt.algorithm.ec.ECSigner;
import org.lattejava.jwt.algorithm.ec.ECVerifier;
import org.lattejava.jwt.algorithm.ed.EdDSASigner;
import org.lattejava.jwt.algorithm.ed.EdDSAVerifier;
import org.lattejava.jwt.algorithm.hmac.HMACSigner;
import org.lattejava.jwt.algorithm.hmac.HMACVerifier;
import org.lattejava.jwt.algorithm.rsa.RSAPSSSigner;
import org.lattejava.jwt.algorithm.rsa.RSAPSSVerifier;
import org.lattejava.jwt.algorithm.rsa.RSASigner;
import org.lattejava.jwt.algorithm.rsa.RSAVerifier;
import org.lattejava.jwt.pem.PEM;
import org.testng.SkipException;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.function.Supplier;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Coverage of the {@code Signers} factory contract:
 * <ul>
 *   <li>{@code forHMAC} accepts only HS* algorithms; rejects asymmetric algorithms with
 *       {@link IllegalArgumentException} so a misplaced PEM cannot become an HMAC secret.</li>
 *   <li>{@code forAsymmetric} accepts only RS{@literal *}/PS{@literal *}/ES{@literal *}/Ed{@literal *}
 *       algorithms; rejects HS{@literal *}.</li>
 *   <li>The {@code kid} parameter is propagated to the produced {@code Signer}.</li>
 *   <li>Signers produced by these factories round-trip with the matching family verifier.</li>
 * </ul>
 *
 * @author The Latte Project
 */
public class SignersTest extends BaseTest {
  private static final String HMAC_SECRET_32 = "super-secret-key-that-is-at-least-32-bytes-long!!";
  private static final String HMAC_SECRET_64 =
      "super-secret-key-that-is-at-least-64-bytes-long-for-sha512-algorithm-compat-requirement!!";

  private static String readFile(String name) {
    try {
      return new String(Files.readAllBytes(Paths.get("src/test/resources/" + name)));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // ---------------------------------------------------------------------
  // DataProviders
  // ---------------------------------------------------------------------

  @DataProvider(name = "hmacAlgorithms")
  public Object[][] hmacAlgorithms() {
    return new Object[][] {
        {Algorithm.HS256, HMAC_SECRET_32},
        {Algorithm.HS384, HMAC_SECRET_64},
        {Algorithm.HS512, HMAC_SECRET_64},
    };
  }

  // (algorithm, signer-from-factory supplier, verifier supplier)
  @DataProvider(name = "asymmetricAlgorithms")
  public Object[][] asymmetricAlgorithms() {
    return new Object[][] {
        {Algorithm.RS256,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.RS256, readFile("rsa_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"))},
        {Algorithm.RS384,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.RS384, readFile("rsa_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"))},
        {Algorithm.RS512,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.RS512, readFile("rsa_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAVerifier.newVerifier(readFile("rsa_public_key_2048.pem"))},
        {Algorithm.PS256,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.PS256, readFile("rsa_pss_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAPSSVerifier.newVerifier(readFile("rsa_pss_public_key_2048.pem"))},
        {Algorithm.PS384,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.PS384, readFile("rsa_pss_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAPSSVerifier.newVerifier(readFile("rsa_pss_public_key_2048.pem"))},
        {Algorithm.PS512,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.PS512, readFile("rsa_pss_private_key_2048.pem")),
            (Supplier<Verifier>) () -> RSAPSSVerifier.newVerifier(readFile("rsa_pss_public_key_2048.pem"))},
        {Algorithm.ES256,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.ES256, readFile("ec_private_key_p_256.pem")),
            (Supplier<Verifier>) () -> ECVerifier.newVerifier(readFile("ec_public_key_p_256.pem"))},
        {Algorithm.ES384,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.ES384, readFile("ec_private_key_p_384.pem")),
            (Supplier<Verifier>) () -> ECVerifier.newVerifier(readFile("ec_public_key_p_384.pem"))},
        {Algorithm.ES512,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.ES512, readFile("ec_private_key_p_521.pem")),
            (Supplier<Verifier>) () -> ECVerifier.newVerifier(readFile("ec_public_key_p_521.pem"))},
        {Algorithm.Ed25519,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.Ed25519, readFile("ed_dsa_ed25519_private_key.pem")),
            (Supplier<Verifier>) () -> EdDSAVerifier.newVerifier(readFile("ed_dsa_ed25519_public_key.pem"))},
        {Algorithm.Ed448,
            (Supplier<Signer>) () -> Signers.forAsymmetric(Algorithm.Ed448, readFile("ed_dsa_ed448_private_key.pem")),
            (Supplier<Verifier>) () -> EdDSAVerifier.newVerifier(readFile("ed_dsa_ed448_public_key.pem"))},
    };
  }

  // (HMAC algorithm crossed with asymmetric API call) -- IllegalArgumentException
  @DataProvider(name = "asymmetricAPIRejectsHMAC")
  public Object[][] asymmetricAPIRejectsHMAC() {
    return new Object[][] {
        {Algorithm.HS256},
        {Algorithm.HS384},
        {Algorithm.HS512},
    };
  }

  // (asymmetric algorithm crossed with HMAC API call) -- IllegalArgumentException
  @DataProvider(name = "hmacAPIRejectsAsymmetric")
  public Object[][] hmacAPIRejectsAsymmetric() {
    return new Object[][] {
        {Algorithm.RS256}, {Algorithm.RS384}, {Algorithm.RS512},
        {Algorithm.PS256}, {Algorithm.PS384}, {Algorithm.PS512},
        {Algorithm.ES256}, {Algorithm.ES384}, {Algorithm.ES512},
        {Algorithm.Ed25519}, {Algorithm.Ed448},
        {Algorithm.ES256K},
    };
  }

  // ---------------------------------------------------------------------
  // forHMAC -- happy paths
  // ---------------------------------------------------------------------

  @Test(dataProvider = "hmacAlgorithms")
  public void forHMAC_string_returnsWorkingSigner(Algorithm algorithm, String secret) {
    // Use case: Signers.forHMAC(HS256, secret) creates an HMACSigner.
    Signer signer = Signers.forHMAC(algorithm, secret);
    assertNotNull(signer);
    assertSame(signer.algorithm(), algorithm);

    byte[] signature = signer.sign("message".getBytes(StandardCharsets.UTF_8));
    assertNotNull(signature);
    assertTrue(signature.length > 0);

    // round-trip verify with the matching family verifier
    Verifier verifier = HMACVerifier.newVerifier(secret);
    verifier.verify(algorithm, "message".getBytes(StandardCharsets.UTF_8), signature);
  }

  @Test(dataProvider = "hmacAlgorithms")
  public void forHMAC_bytes_returnsWorkingSigner(Algorithm algorithm, String secret) {
    byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
    Signer signer = Signers.forHMAC(algorithm, secretBytes);
    assertSame(signer.algorithm(), algorithm);

    byte[] signature = signer.sign("message".getBytes(StandardCharsets.UTF_8));
    Verifier verifier = HMACVerifier.newVerifier(secretBytes);
    verifier.verify(algorithm, "message".getBytes(StandardCharsets.UTF_8), signature);
  }

  @Test
  public void forHMAC_stringAndBytesEquivalent() {
    // Use case: Signers.forHMAC(HS256, byte[]) and forHMAC(HS256, String) produce signers
    // that verify each other's signatures when the underlying bytes match.
    Signer fromString = Signers.forHMAC(Algorithm.HS256, HMAC_SECRET_32);
    Signer fromBytes = Signers.forHMAC(Algorithm.HS256, HMAC_SECRET_32.getBytes(StandardCharsets.UTF_8));
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sigA = fromString.sign(msg);
    byte[] sigB = fromBytes.sign(msg);
    assertEquals(sigA, sigB);
  }

  @Test
  public void forHMAC_kidIsPropagated_string() {
    Signer signer = Signers.forHMAC(Algorithm.HS256, HMAC_SECRET_32, "kid-1");
    assertEquals(signer.kid(), "kid-1");
  }

  @Test
  public void forHMAC_kidIsPropagated_bytes() {
    Signer signer = Signers.forHMAC(Algorithm.HS256, HMAC_SECRET_32.getBytes(StandardCharsets.UTF_8), "kid-2");
    assertEquals(signer.kid(), "kid-2");
  }

  @Test
  public void forHMAC_nullKidYieldsNullKid() {
    Signer signer = Signers.forHMAC(Algorithm.HS256, HMAC_SECRET_32);
    // default Signer.kid() returns null when not provided
    assertEquals(signer.kid(), null);
  }

  // ---------------------------------------------------------------------
  // forHMAC -- mismatch rejection
  // ---------------------------------------------------------------------

  @Test(dataProvider = "hmacAPIRejectsAsymmetric")
  public void forHMAC_rejectsAsymmetricAlgorithm_string(Algorithm algorithm) {
    // Use case: Signers.forHMAC(RS256, secret) throws IllegalArgumentException -- algorithm
    // class mismatch caught at call time so that misplaced key material is fail-fast.
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forHMAC(algorithm, HMAC_SECRET_32));
  }

  @Test(dataProvider = "hmacAPIRejectsAsymmetric")
  public void forHMAC_rejectsAsymmetricAlgorithm_bytes(Algorithm algorithm) {
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forHMAC(algorithm, HMAC_SECRET_32.getBytes(StandardCharsets.UTF_8)));
  }

  @Test(dataProvider = "hmacAPIRejectsAsymmetric")
  public void forHMAC_rejectsAsymmetricAlgorithm_stringWithKid(Algorithm algorithm) {
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forHMAC(algorithm, HMAC_SECRET_32, "kid"));
  }

  @Test(dataProvider = "hmacAPIRejectsAsymmetric")
  public void forHMAC_rejectsAsymmetricAlgorithm_bytesWithKid(Algorithm algorithm) {
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forHMAC(algorithm, HMAC_SECRET_32.getBytes(StandardCharsets.UTF_8), "kid"));
  }

  // ---------------------------------------------------------------------
  // forAsymmetric -- happy paths
  // ---------------------------------------------------------------------

  @Test(dataProvider = "asymmetricAlgorithms")
  public void forAsymmetric_pem_returnsWorkingSigner(Algorithm algorithm,
                                                     Supplier<Signer> signerFactory,
                                                     Supplier<Verifier> verifierFactory) {
    // Use case: Signers.forAsymmetric(RS256, pemString) -- creates an RSASigner from PEM
    // (and analogous for every other asymmetric family).
    Signer signer = signerFactory.get();
    assertNotNull(signer);
    assertSame(signer.algorithm(), algorithm);

    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] signature = signer.sign(msg);
    assertNotNull(signature);
    assertTrue(signature.length > 0);

    Verifier verifier = verifierFactory.get();
    verifier.verify(algorithm, msg, signature);
  }

  @Test
  public void forAsymmetric_privateKey_es256() {
    // Use case: Signers.forAsymmetric(ES256, privateKey) -- accepts a pre-built PrivateKey.
    PrivateKey key = PEM.decode(readFile("ec_private_key_p_256.pem")).privateKey;
    Signer signer = Signers.forAsymmetric(Algorithm.ES256, key);
    assertSame(signer.algorithm(), Algorithm.ES256);
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sig = signer.sign(msg);

    PublicKey pub = PEM.decode(readFile("ec_public_key_p_256.pem")).publicKey;
    ECVerifier.newVerifier(pub).verify(Algorithm.ES256, msg, sig);
  }

  @Test
  public void forAsymmetric_privateKey_rs256() {
    PrivateKey key = PEM.decode(readFile("rsa_private_key_2048.pem")).privateKey;
    Signer signer = Signers.forAsymmetric(Algorithm.RS256, key);
    assertSame(signer.algorithm(), Algorithm.RS256);
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sig = signer.sign(msg);
    PublicKey pub = PEM.decode(readFile("rsa_public_key_2048.pem")).publicKey;
    RSAVerifier.newVerifier(pub).verify(Algorithm.RS256, msg, sig);
  }

  @Test
  public void forAsymmetric_privateKey_ed25519() {
    PrivateKey key = PEM.decode(readFile("ed_dsa_ed25519_private_key.pem")).privateKey;
    Signer signer = Signers.forAsymmetric(Algorithm.Ed25519, key);
    assertSame(signer.algorithm(), Algorithm.Ed25519);
  }

  @Test
  public void forAsymmetric_privateKey_ps256() {
    PrivateKey key = PEM.decode(readFile("rsa_pss_private_key_2048.pem")).privateKey;
    Signer signer = Signers.forAsymmetric(Algorithm.PS256, key);
    assertSame(signer.algorithm(), Algorithm.PS256);
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sig = signer.sign(msg);
    PublicKey pub = PEM.decode(readFile("rsa_pss_public_key_2048.pem")).publicKey;
    RSAPSSVerifier.newVerifier(pub).verify(Algorithm.PS256, msg, sig);
  }

  @Test
  public void forAsymmetric_privateKey_es256k() throws Exception {
    // Use case: Signers.forAsymmetric(ES256K, secp256k1PrivateKey) must produce a signer
    // whose algorithm() == ES256K and that round-trips with ECVerifier. Previously the
    // dispatch routed ES256K to ECSigner.newSHA256Signer (which constructs with
    // Algorithm.ES256) causing ECFamily.assertCurveMatchesAlgorithm to reject the
    // secp256k1 curve against ES256 -- rendering the factory unusable for ES256K.
    java.security.KeyPair kp;
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp256k1"));
      kp = g.generateKeyPair();
    } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
      throw new SkipException("secp256k1 KeyPairGenerator unavailable in this JCA profile");
    }

    Signer signer = Signers.forAsymmetric(Algorithm.ES256K, kp.getPrivate());
    assertSame(signer.algorithm(), Algorithm.ES256K);

    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sig;
    try {
      sig = signer.sign(msg);
    } catch (org.lattejava.jwt.JWTSigningException e) {
      // Some JCA profiles can generate secp256k1 keys but lack a SHA256withECDSA
      // provider that accepts them. This matches ES256KRuntimeBehaviorTest's documented
      // fallback. The factory contract (algorithm() tag) is still verified above.
      Throwable root = e.getCause();
      if (root instanceof NoSuchAlgorithmException || root instanceof java.security.NoSuchProviderException) {
        return;
      }
      throw e;
    }

    Verifier verifier = ECVerifier.newVerifier(kp.getPublic());
    verifier.verify(Algorithm.ES256K, msg, sig);
  }

  @Test
  public void forAsymmetric_privateKey_es256k_kidPropagated() throws Exception {
    java.security.KeyPair kp;
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp256k1"));
      kp = g.generateKeyPair();
    } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
      throw new SkipException("secp256k1 KeyPairGenerator unavailable in this JCA profile");
    }
    Signer signer = Signers.forAsymmetric(Algorithm.ES256K, kp.getPrivate(), "btc-kid");
    assertSame(signer.algorithm(), Algorithm.ES256K);
    assertEquals(signer.kid(), "btc-kid");
  }

  @Test
  public void forAsymmetric_kidPropagated_pem() {
    Signer signer = Signers.forAsymmetric(Algorithm.RS256,
        readFile("rsa_private_key_2048.pem"), "rsa-kid");
    assertEquals(signer.kid(), "rsa-kid");
  }

  @Test
  public void forAsymmetric_kidPropagated_privateKey() {
    PrivateKey key = PEM.decode(readFile("rsa_private_key_2048.pem")).privateKey;
    Signer signer = Signers.forAsymmetric(Algorithm.RS256, key, "rsa-kid-pk");
    assertEquals(signer.kid(), "rsa-kid-pk");
  }

  // ---------------------------------------------------------------------
  // forAsymmetric -- mismatch rejection
  // ---------------------------------------------------------------------

  @Test(dataProvider = "asymmetricAPIRejectsHMAC")
  public void forAsymmetric_rejectsHMACAlgorithm_pem(Algorithm hmacAlgorithm) {
    // Use case: Signers.forAsymmetric(HS256, pem) throws IllegalArgumentException --
    // asymmetric API refuses an HMAC algorithm regardless of payload.
    String anyPem = readFile("rsa_private_key_2048.pem");
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forAsymmetric(hmacAlgorithm, anyPem));
  }

  @Test(dataProvider = "asymmetricAPIRejectsHMAC")
  public void forAsymmetric_rejectsHMACAlgorithm_pemWithKid(Algorithm hmacAlgorithm) {
    String anyPem = readFile("rsa_private_key_2048.pem");
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forAsymmetric(hmacAlgorithm, anyPem, "kid"));
  }

  @Test(dataProvider = "asymmetricAPIRejectsHMAC")
  public void forAsymmetric_rejectsHMACAlgorithm_privateKey(Algorithm hmacAlgorithm) {
    PrivateKey rsa = PEM.decode(readFile("rsa_private_key_2048.pem")).privateKey;
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forAsymmetric(hmacAlgorithm, rsa));
  }

  @Test(dataProvider = "asymmetricAPIRejectsHMAC")
  public void forAsymmetric_rejectsHMACAlgorithm_privateKeyWithKid(Algorithm hmacAlgorithm) {
    PrivateKey rsa = PEM.decode(readFile("rsa_private_key_2048.pem")).privateKey;
    assertThrows(IllegalArgumentException.class,
        () -> Signers.forAsymmetric(hmacAlgorithm, rsa, "kid"));
  }

  // ---------------------------------------------------------------------
  // Verifiers.forHMAC / forAsymmetric -- happy paths and mismatch rejection
  // ---------------------------------------------------------------------

  @Test(dataProvider = "hmacAlgorithms")
  public void verifiers_forHMAC_string_roundTrip(Algorithm algorithm, String secret) {
    // Use case: Verifiers.forHMAC(HS256, byte[]) and forHMAC(HS256, String) produce verifiers
    // that accept signatures from a matching HMACSigner.
    Verifier verifier = Verifiers.forHMAC(algorithm, secret);
    assertNotNull(verifier);
    assertTrue(verifier.canVerify(algorithm));

    Signer signer = HMACSigner.class == HMACSigner.class
        ? signerForHMAC(algorithm, secret)
        : null;
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sig = signer.sign(msg);
    verifier.verify(algorithm, msg, sig);
  }

  @Test(dataProvider = "hmacAlgorithms")
  public void verifiers_forHMAC_bytes_roundTrip(Algorithm algorithm, String secret) {
    byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
    Verifier verifier = Verifiers.forHMAC(algorithm, secretBytes);
    assertTrue(verifier.canVerify(algorithm));
    Signer signer = signerForHMAC(algorithm, secret);
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    byte[] sig = signer.sign(msg);
    verifier.verify(algorithm, msg, sig);
  }

  @Test(dataProvider = "hmacAPIRejectsAsymmetric")
  public void verifiers_forHMAC_rejectsAsymmetric_string(Algorithm algorithm) {
    assertThrows(IllegalArgumentException.class,
        () -> Verifiers.forHMAC(algorithm, HMAC_SECRET_32));
  }

  @Test(dataProvider = "hmacAPIRejectsAsymmetric")
  public void verifiers_forHMAC_rejectsAsymmetric_bytes(Algorithm algorithm) {
    assertThrows(IllegalArgumentException.class,
        () -> Verifiers.forHMAC(algorithm, HMAC_SECRET_32.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void verifiers_forAsymmetric_pem_rsa() {
    // Use case: Verifiers.forAsymmetric(RS256, publicKey) creates RSAVerifier.
    Verifier verifier = Verifiers.forAsymmetric(Algorithm.RS256, readFile("rsa_public_key_2048.pem"));
    assertTrue(verifier.canVerify(Algorithm.RS256));
    Signer signer = RSASigner.newSHA256Signer(readFile("rsa_private_key_2048.pem"));
    byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
    verifier.verify(Algorithm.RS256, msg, signer.sign(msg));
  }

  @Test
  public void verifiers_forAsymmetric_publicKey_rsa() {
    PublicKey pub = PEM.decode(readFile("rsa_public_key_2048.pem")).publicKey;
    Verifier verifier = Verifiers.forAsymmetric(Algorithm.RS256, pub);
    assertTrue(verifier.canVerify(Algorithm.RS256));
  }

  @Test
  public void verifiers_forAsymmetric_pem_pss() {
    Verifier verifier = Verifiers.forAsymmetric(Algorithm.PS256, readFile("rsa_pss_public_key_2048.pem"));
    assertTrue(verifier.canVerify(Algorithm.PS256));
    Signer signer = RSAPSSSigner.newSHA256Signer(readFile("rsa_pss_private_key_2048.pem"));
    byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
    verifier.verify(Algorithm.PS256, msg, signer.sign(msg));
  }

  @Test
  public void verifiers_forAsymmetric_pem_ec() {
    Verifier verifier = Verifiers.forAsymmetric(Algorithm.ES256, readFile("ec_public_key_p_256.pem"));
    assertTrue(verifier.canVerify(Algorithm.ES256));
    Signer signer = ECSigner.newSHA256Signer(readFile("ec_private_key_p_256.pem"));
    byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
    verifier.verify(Algorithm.ES256, msg, signer.sign(msg));
  }

  @Test
  public void verifiers_forAsymmetric_pem_ed25519() {
    Verifier verifier = Verifiers.forAsymmetric(Algorithm.Ed25519, readFile("ed_dsa_ed25519_public_key.pem"));
    assertTrue(verifier.canVerify(Algorithm.Ed25519));
    Signer signer = EdDSASigner.newSigner(readFile("ed_dsa_ed25519_private_key.pem"));
    byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
    verifier.verify(Algorithm.Ed25519, msg, signer.sign(msg));
  }

  @Test(dataProvider = "asymmetricAPIRejectsHMAC")
  public void verifiers_forAsymmetric_rejectsHMACAlgorithm_pem(Algorithm hmacAlgorithm) {
    String anyPem = readFile("rsa_public_key_2048.pem");
    assertThrows(IllegalArgumentException.class,
        () -> Verifiers.forAsymmetric(hmacAlgorithm, anyPem));
  }

  @Test(dataProvider = "asymmetricAPIRejectsHMAC")
  public void verifiers_forAsymmetric_rejectsHMACAlgorithm_publicKey(Algorithm hmacAlgorithm) {
    PublicKey pub = PEM.decode(readFile("rsa_public_key_2048.pem")).publicKey;
    assertThrows(IllegalArgumentException.class,
        () -> Verifiers.forAsymmetric(hmacAlgorithm, pub));
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  private static Signer signerForHMAC(Algorithm algorithm, String secret) {
    return switch (algorithm.name()) {
      case "HS256" -> HMACSigner.newSHA256Signer(secret);
      case "HS384" -> HMACSigner.newSHA384Signer(secret);
      case "HS512" -> HMACSigner.newSHA512Signer(secret);
      default -> throw new AssertionError(algorithm.name());
    };
  }
}
