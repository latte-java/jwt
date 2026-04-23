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

package org.lattejava.jwt.jwks;

import org.lattejava.jwt.Algorithm;
import org.lattejava.jwt.JWTUtils;
import org.lattejava.jwt.KeyType;
import org.lattejava.jwt.der.DerDecodingException;
import org.lattejava.jwt.der.DerInputStream;
import org.lattejava.jwt.der.ObjectIdentifier;
import org.lattejava.jwt.internal.KeyUtils;
import org.lattejava.jwt.pem.PEM;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Objects;

import static org.lattejava.jwt.jwks.JWKUtils.base64EncodeUint;

/**
 * Internal helper that converts Java key material (PEM, PrivateKey,
 * PublicKey, Certificate) into {@link JSONWebKey} instances. Package-private
 * by design — external callers should use the {@code JSONWebKey.from(...)}
 * overloads instead.
 *
 * @author Daniel DeGroff
 */
class JSONWebKeyConverter {
  /**
   * Build a JSON Web Key from the provided encoded PEM.
   */
  JSONWebKey build(String encodedPEM) {
    Objects.requireNonNull(encodedPEM);
    PEM pem = PEM.decode(encodedPEM);
    if (pem.privateKey != null) {
      return build(pem.privateKey);
    } else if (pem.certificate != null) {
      return build(pem.certificate);
    } else if (pem.publicKey != null) {
      return build(pem.publicKey);
    }

    throw new JSONWebKeyException("PEM did not contain a public or private key");
  }

  /**
   * Build a JSON Web Key from the provided PrivateKey.
   */
  JSONWebKey build(PrivateKey privateKey) {
    Objects.requireNonNull(privateKey);
    JSONWebKey.Builder b = JSONWebKey.builder()
        .kty(getKeyType(privateKey))
        .use("sig");

    if (privateKey instanceof RSAPrivateKey rsaPrivateKey) {
      b.n(base64EncodeUint(rsaPrivateKey.getModulus()));
      b.d(base64EncodeUint(rsaPrivateKey.getPrivateExponent()));
    }

    // CRT (Chinese Remainder Theorem) private key
    if (privateKey instanceof RSAPrivateCrtKey rsaPrivateKey) {
      b.e(base64EncodeUint(rsaPrivateKey.getPublicExponent()));
      b.p(base64EncodeUint(rsaPrivateKey.getPrimeP()));
      b.q(base64EncodeUint(rsaPrivateKey.getPrimeQ()));
      b.qi(base64EncodeUint(rsaPrivateKey.getCrtCoefficient()));

      BigInteger dp = rsaPrivateKey.getPrivateExponent().mod(rsaPrivateKey.getPrimeP().subtract(BigInteger.valueOf(1)));
      BigInteger dq = rsaPrivateKey.getPrivateExponent().mod(rsaPrivateKey.getPrimeQ().subtract(BigInteger.valueOf(1)));

      b.dp(base64EncodeUint(dp));
      b.dq(base64EncodeUint(dq));
    }

    if (privateKey instanceof ECPrivateKey ecPrivateKey) {
      String crv = getCurveOID(privateKey);
      b.crv(crv);
      if (crv != null) {
        switch (crv) {
          case "P-256": b.alg(Algorithm.ES256); break;
          case "P-384": b.alg(Algorithm.ES384); break;
          case "P-521": b.alg(Algorithm.ES512); break;
        }
      }

      int byteLength = getCoordinateLength(ecPrivateKey);
      b.d(base64EncodeUint(ecPrivateKey.getS(), byteLength));
      b.x(base64EncodeUint(ecPrivateKey.getParams().getGenerator().getAffineX(), byteLength));
      b.y(base64EncodeUint(ecPrivateKey.getParams().getGenerator().getAffineY(), byteLength));
    } else if (privateKey instanceof EdECPrivateKey edPrivateKey) {
      String crv = getCurveOID(edPrivateKey);
      b.crv(crv);
      b.alg(Algorithm.fromName(crv));

      var privateKeyBytes = edPrivateKey.getBytes().orElseThrow(
          () -> new JSONWebKeyException("Failed to obtain private key bytes"));
      b.d(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));
      try {
        byte[] publicKeyBytes = KeyUtils.deriveEdDSAPublicKeyFromPrivate(privateKeyBytes, crv);
        b.x(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
      } catch (Exception e) {
        throw new JSONWebKeyException("Failed to derive EdDSA public key for curve [" + crv + "]", e);
      }
    }

    return b.build();
  }

  private String getCurveOID(Key key) {
    try {
      return KeyUtils.getCurveName(key);
    } catch (Exception e) {
      throw new JSONWebKeyException("Failed to read OID from the public key", e);
    }
  }

  /**
   * Build a JSON Web Key from the provided PublicKey.
   */
  JSONWebKey build(PublicKey publicKey) {
    Objects.requireNonNull(publicKey);
    KeyType kty = getKeyType(publicKey);
    JSONWebKey.Builder b = JSONWebKey.builder()
        .kty(kty)
        .use("sig");

    if (publicKey instanceof RSAPublicKey rsaPublicKey) {
      b.e(base64EncodeUint(rsaPublicKey.getPublicExponent()));
      b.n(base64EncodeUint(rsaPublicKey.getModulus()));
    } else if (kty == KeyType.EC) {
      ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
      b.crv(getCurveOID(ecPublicKey));

      int length = KeyUtils.getKeyLength(publicKey);
      if (length == 256) {
        b.alg(Algorithm.ES256);
      } else if (length == 384) {
        b.alg(Algorithm.ES384);
      } else if (length == 521) {
        b.alg(Algorithm.ES512);
      }

      int byteLength = getCoordinateLength(ecPublicKey);
      b.x(base64EncodeUint(ecPublicKey.getW().getAffineX(), byteLength));
      b.y(base64EncodeUint(ecPublicKey.getW().getAffineY(), byteLength));
    } else if (kty == KeyType.OKP) {
      String crv = getCurveOID(publicKey);
      b.crv(crv);
      b.alg(Algorithm.fromName(crv));

      int keyLength = KeyUtils.getKeyLength(publicKey);
      byte[] publicKeyBytes;
      try {
        var sequence = new DerInputStream(publicKey.getEncoded()).getSequence();
        publicKeyBytes = sequence[1].toByteArray();
      } catch (DerDecodingException e) {
        throw new JSONWebKeyException("Failed to read public key from DER encoding", e);
      }

      b.x(base64EncodeUint(new BigInteger(publicKeyBytes), keyLength));
    }

    return b.build();
  }

  /**
   * Build a JSON Web Key from the provided X.509 Certificate.
   */
  JSONWebKey build(Certificate certificate) {
    Objects.requireNonNull(certificate);
    JSONWebKey base = build(certificate.getPublicKey());
    if (!(certificate instanceof X509Certificate x509Certificate)) {
      return base;
    }

    Algorithm alg = base.alg() != null ? base.alg() : determineKeyAlgorithm(x509Certificate);

    try {
      String encodedCertificate = new String(Base64.getEncoder().encode(certificate.getEncoded()));
      // Rebuild using the existing fields plus alg + x5c chain.
      return JSONWebKey.builder()
          .alg(alg)
          .crv(base.crv())
          .kid(base.kid())
          .kty(base.kty())
          .use(base.use())
          .keyOps(base.key_ops())
          .x5u(base.x5u())
          .d(base.d()).dp(base.dp()).dq(base.dq()).e(base.e()).n(base.n())
          .p(base.p()).q(base.q()).qi(base.qi())
          .x(base.x()).y(base.y())
          .x5c(Collections.singletonList(encodedCertificate))
          .x5t(JWTUtils.generateJWS_x5t(encodedCertificate))
          .x5tS256(JWTUtils.generateJWS_x5t("SHA-256", encodedCertificate))
          .build();
    } catch (CertificateEncodingException e) {
      throw new JSONWebKeyException("Failed to encode X.509 certificate", e);
    }
  }

  private int getCoordinateLength(ECKey key) {
    return (int) Math.ceil(key.getParams().getCurve().getField().getFieldSize() / 8d);
  }

  private Algorithm determineKeyAlgorithm(X509Certificate x509Certificate) {
    String sigAlgName = x509Certificate.getSigAlgName();
    Algorithm result = Algorithm.fromName(sigAlgName);
    if (result != null) {
      return result;
    }

    if ("RSASSA-PSS".equals(sigAlgName)) {
      byte[] encodedBytes = x509Certificate.getSigAlgParams();
      try {
        String oid = new DerInputStream(new DerInputStream(encodedBytes)
            .getSequence()[1].toByteArray())
            .getSequence()[1]
            .getOID().toString();

        result = switch (oid) {
          case ObjectIdentifier.SHA256 -> Algorithm.PS256;
          case ObjectIdentifier.SHA384 -> Algorithm.PS384;
          case ObjectIdentifier.SHA512 -> Algorithm.PS512;
          default -> null;
        };
      } catch (IOException e) {
        throw new JSONWebKeyException("Failed to decode X.509 signature algorithm parameters", e);
      }
    }

    return result;
  }

  private KeyType getKeyType(Key key) {
    return switch (key.getAlgorithm()) {
      case "RSA", "RSASSA-PSS" -> KeyType.RSA;
      case "EC" -> KeyType.EC;
      case "EdDSA", "Ed25519", "Ed448" -> KeyType.OKP;
      default -> null;
    };
  }
}
