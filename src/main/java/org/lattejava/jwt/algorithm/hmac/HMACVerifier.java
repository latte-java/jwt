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

package org.lattejava.jwt.algorithm.hmac;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.InvalidJWTSignatureException;
import org.lattejava.jwt.JWTVerifierException;
import org.lattejava.jwt.Verifier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * HMAC-based {@link Verifier} for the {@code HS256} / {@code HS384} /
 * {@code HS512} JWA algorithms (RFC 7518 §3.2).
 *
 * <p>Signature comparison uses
 * {@link MessageDigest#isEqual(byte[], byte[])} -- documented as
 * constant-time since JDK 7u40 (JDK-8006276) -- per the spec §6
 * HMAC constant-time contract.</p>
 *
 * <p>Each call to {@link #verify(Algorithm, byte[], byte[])} obtains a
 * fresh {@link Mac} instance per the spec §6 thread-safety contract.</p>
 *
 * @author The Latte Project
 */
public class HMACVerifier implements Verifier {
  private final byte[] secret;

  private HMACVerifier(byte[] secret) {
    Objects.requireNonNull(secret);
    this.secret = secret;
  }

  private HMACVerifier(String secret) {
    this(secret == null ? null : secret.getBytes(StandardCharsets.UTF_8));
  }

  public static HMACVerifier newVerifier(String secret) {
    return new HMACVerifier(secret);
  }

  public static HMACVerifier newVerifier(byte[] bytes) {
    return new HMACVerifier(bytes);
  }

  public static HMACVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);
    try {
      return new HMACVerifier(Files.readAllBytes(path));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return switch (algorithm.name()) {
      case "HS256", "HS384", "HS512" -> true;
      default -> false;
    };
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);
    HMACFamily.assertMinimumSecretLength(algorithm, secret);

    String jcaName = HMACFamily.toJCA(algorithm);
    try {
      Mac mac = Mac.getInstance(jcaName);
      mac.init(new SecretKeySpec(secret, jcaName));
      byte[] expected = mac.doFinal(message);
      if (!MessageDigest.isEqual(signature, expected)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
