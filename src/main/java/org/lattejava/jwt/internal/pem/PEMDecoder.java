/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

package org.lattejava.jwt.internal.pem;

import org.lattejava.jwt.PEMDecoderException;
import org.lattejava.jwt.internal.der.DerInputStream;
import org.lattejava.jwt.internal.der.DerOutputStream;
import org.lattejava.jwt.internal.der.DerValue;
import org.lattejava.jwt.internal.der.ObjectIdentifier;
import org.lattejava.jwt.internal.der.Tag;
import org.lattejava.jwt.KeyType;
import org.lattejava.jwt.internal.KeyUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Objects;

import static org.lattejava.jwt.internal.pem.PEM.EC_PRIVATE_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.EC_PRIVATE_KEY_SUFFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_1_PRIVATE_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_1_PRIVATE_KEY_SUFFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_1_PUBLIC_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_1_PUBLIC_KEY_SUFFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_8_PRIVATE_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.PKCS_8_PRIVATE_KEY_SUFFIX;
import static org.lattejava.jwt.internal.pem.PEM.X509_CERTIFICATE_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.X509_CERTIFICATE_SUFFIX;
import static org.lattejava.jwt.internal.pem.PEM.X509_PUBLIC_KEY_PREFIX;
import static org.lattejava.jwt.internal.pem.PEM.X509_PUBLIC_KEY_SUFFIX;

/**
 * @author Daniel DeGroff
 */
public class PEMDecoder {
  private static final byte[] EC_ENCRYPTION_OID = new byte[]{(byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x02, (byte) 0x01};

  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param path the path to the encoded PEM file
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(Path path) {
    Objects.requireNonNull(path);

    try {
      return decode(Files.readAllBytes(path));
    } catch (IOException e) {
      // Echo the path as the caller supplied it rather than resolving
      // to an absolute path. Callers recognize their own input, and
      // this avoids leaking filesystem layout into consumer logs.
      throw new PEMDecoderException("Unable to read file from path [" + path + "]", e);
    }
  }

  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param bytes the byte array of the encoded PEM file
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return decode(new String(bytes));
  }

  /**
   * Decode a PEM and extract the public or private keys. If the encoded private key contains the public key, the returned
   * PEM object will contain both keys.
   *
   * @param encodedKey the string representation the encoded PEM
   * @return a PEM object containing a public or private key, or both
   */
  public PEM decode(String encodedKey) {
    Objects.requireNonNull(encodedKey);

    try {
      if (encodedKey.contains(PKCS_1_PUBLIC_KEY_PREFIX)) {
        return decode_PKCS_1_Public(encodedKey);
      } else if (encodedKey.contains(X509_PUBLIC_KEY_PREFIX)) {
        return decode_X_509(encodedKey);
      } else if (encodedKey.contains(X509_CERTIFICATE_PREFIX)) {
        return new PEM(CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(getKeyBytes(encodedKey, X509_CERTIFICATE_PREFIX, X509_CERTIFICATE_SUFFIX))));
      } else if (encodedKey.contains(PKCS_1_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_1_Private(encodedKey);
      } else if (encodedKey.contains(PKCS_8_PRIVATE_KEY_PREFIX)) {
        return decode_PKCS_8(encodedKey);
      } else if (encodedKey.contains(EC_PRIVATE_KEY_SUFFIX)) {
        return decode_EC_privateKey(encodedKey);
      } else {
        throw new PEMDecoderException(new InvalidParameterException("Unexpected PEM format"));
      }
    } catch (CertificateException | InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException |
             IOException | NoSuchAlgorithmException e) {
      throw new PEMDecoderException(e);
    }
  }

  private PEM decode_EC_privateKey(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = getKeyBytes(encodedKey, EC_PRIVATE_KEY_PREFIX, EC_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();
    BigInteger version = sequence[0].getBigInteger();

    // Expecting this EC private key to be version 1, it is not encapsulated in a PKCS#8 container
    if (!version.equals(BigInteger.valueOf(1))) {
      throw new PEMDecoderException("Expected version [1] but found [" + version + "]");
    }

    // This is an EC private key, encapsulate it in a PKCS#8 format to be compatible with the Java Key Factory
    //
    // EC Private key
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   PrivateKey      OCTET STRING
    //   [0] parameters  Context Specific
    //     curve           OBJECT IDENTIFIER
    //   [1] publicKey   Context Specific
    //                     BIT STRING
    // }
    //

    // Convert it to:
    //
    // DER Encoded PKCS#8  - version 0
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   algorithm       AlgorithmIdentifier,
    //   PrivateKey      OCTET STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length == 2) {
      // This is an EC encoded key w/out the context specific values [0] or [1] - this means we don't
      // have enough information to build a PKCS#8 key.
      throw new PEMDecoderException("EC private key does not contain the curve identifier required to convert to PKCS#8 format");
    }

    ObjectIdentifier curveOID = sequence[2].getOID();
    DerOutputStream pkcs_8 = new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(BigInteger.valueOf(0))) // Always version 0
            .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                .writeValue(new DerValue(Tag.ObjectIdentifier, EC_ENCRYPTION_OID))
                .writeValue(new DerValue(Tag.ObjectIdentifier, curveOID.value))))
            .writeValue(new DerValue(Tag.OctetString, bytes))));

    ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs_8.toByteArray()));

    // Extract the public key from the PEM
    DerValue bitString = new DerInputStream(sequence[3]).readDerValue();
    PublicKey publicKey = getPublicKeyFromPrivateEC(bitString, privateKey);

    // The publicKey may be null if it was not found in the private key
    return new PEM(privateKey, publicKey);
  }

  private PEM decode_PKCS_1_Private(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_1_PRIVATE_KEY_PREFIX, PKCS_1_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#1 structure
    // https://tools.ietf.org/html/rfc3447#appendix-A.1
    // ------------------------------------------------------
    // RSAPrivateKey ::= SEQUENCE {
    //   version           Version,
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER,  -- e
    //   privateExponent   INTEGER,  -- d
    //   prime1            INTEGER,  -- p
    //   prime2            INTEGER,  -- q
    //   exponent1         INTEGER,  -- d mod (p-1)
    //   exponent2         INTEGER,  -- d mod (q-1)
    //   coefficient       INTEGER,  -- (inverse of q) mod p
    //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    // }

    if (sequence.length < 9) {
      throw new PEMDecoderException(
          new InvalidKeyException("Expected at least [9] values in PKCS#1 private key DER sequence but found [" + sequence.length + "]"));
    }

    // Ignoring the version value in the sequence
    BigInteger n = sequence[1].getBigInteger();
    BigInteger e = sequence[2].getBigInteger();
    BigInteger d = sequence[3].getBigInteger();
    BigInteger p = sequence[4].getBigInteger();
    BigInteger q = sequence[5].getBigInteger();
    BigInteger d_mod_p1 = sequence[6].getBigInteger();
    BigInteger d_mod_q1 = sequence[7].getBigInteger();
    BigInteger mod_p = sequence[8].getBigInteger();

    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, d_mod_p1, d_mod_q1, mod_p));
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));

    return new PEM(privateKey, publicKey);
  }

  private PEM decode_PKCS_1_Public(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_1_PUBLIC_KEY_PREFIX, PKCS_1_PUBLIC_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#1 structure
    // ------------------------------------------------------
    // RSAPublicKey ::= SEQUENCE {
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER   -- e
    // }

    if (sequence.length != 2 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Integer)) {
      // Expect the following format : [ Integer | Integer ]
      throw new InvalidKeyException("Expected PKCS#1 public key DER sequence format [Integer | Integer]");
    }

    BigInteger modulus = sequence[0].getBigInteger();
    BigInteger publicExponent = sequence[1].getBigInteger();
    return new PEM(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent)));
  }

  private PEM decode_PKCS_8(String encodedKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
    byte[] bytes = getKeyBytes(encodedKey, PKCS_8_PRIVATE_KEY_PREFIX, PKCS_8_PRIVATE_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded PKCS#8
    // ------------------------------------------------------
    // PrivateKeyInfo ::= SEQUENCE {
    //   version         Version,
    //   algorithm       AlgorithmIdentifier,
    //   PrivateKey      OCTET STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    // EC and RSA will be length 3, EdDSA will be 4 or 5
    if (sequence.length < 3 || !sequence[0].tag.is(Tag.Integer) || !sequence[1].tag.is(Tag.Sequence) || !sequence[2].tag.is(Tag.OctetString)) {
      // Expect the following format : [ Integer | Sequence | OctetString ]
      throw new InvalidKeyException("Expected private key DER sequence format [Integer | Sequence | OctetString] or [Integer | Sequence | OctetString | Attributes]");
    }

    ObjectIdentifier algorithmOID = new DerInputStream(sequence[1].toByteArray()).getOID();
    KeyType type = KeyType.forOid(algorithmOID.decode());
    if (type == null) {
      throw new InvalidKeyException("Expected EC, Ed or RSA key type but found OID [" + algorithmOID.decode() + "]");
    }

    PrivateKey privateKey = KeyFactory.getInstance(jcaKeyFactoryName(algorithmOID.decode(), type)).generatePrivate(new PKCS8EncodedKeySpec(bytes));

    // Attempt to extract the public key if available
    if (privateKey instanceof ECPrivateKey ecPrivateKey) {
      DerValue[] privateKeySequence = new DerInputStream(sequence[2]).getSequence();
      if (privateKeySequence.length == 3 && privateKeySequence[2].tag.rawByte == (byte) 0xA1) {
        DerValue bitString = new DerInputStream(privateKeySequence[2]).readDerValue();
        PublicKey publicKey = getPublicKeyFromPrivateEC(bitString, ecPrivateKey);
        return new PEM(privateKey, publicKey);
      } else {
        // The private key did not contain the public key
        return new PEM(privateKey);
      }
    } else if (privateKey instanceof RSAPrivateCrtKey rsaPrivateCrtKey) {
      BigInteger modulus = rsaPrivateCrtKey.getModulus();
      BigInteger publicExponent = rsaPrivateCrtKey.getPublicExponent();
      PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      return new PEM(privateKey, publicKey);
    } else if (privateKey instanceof EdECPrivateKey edECPrivateKey) {

      byte[] algorithmIdentifier = sequence[1].toByteArray();
      byte[] publicKeyBytes;
      byte[] derEncodedPublicKey;
      if (sequence.length >= 4) {
        int index = sequence.length - 1;
        publicKeyBytes = sequence[index].toByteArray();
        derEncodedPublicKey = derEncodePublicKey(algorithmIdentifier, publicKeyBytes);
      } else {
        // The private key did not contain the public key. The public key can be derived from the privat key.
        String curve = KeyUtils.getCurveName(privateKey);
        publicKeyBytes = KeyUtils.deriveEdDSAPublicKeyFromPrivate(edECPrivateKey.getBytes().orElseThrow(), curve);

        byte[] bitStringKeyBytes = new byte[publicKeyBytes.length + 1];
        bitStringKeyBytes[0] = 0x0;
        System.arraycopy(publicKeyBytes, 0, bitStringKeyBytes, 1, publicKeyBytes.length);
        derEncodedPublicKey = new DerOutputStream()
            .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                .writeValue(new DerValue(Tag.Sequence, algorithmIdentifier))
                .writeValue(new DerValue(Tag.BitString, bitStringKeyBytes))))
            .toByteArray();
      }

      PublicKey publicKey = KeyFactory.getInstance(edECPrivateKey.getAlgorithm())
          .generatePublic(new X509EncodedKeySpec(derEncodedPublicKey, edECPrivateKey.getAlgorithm()));
      return new PEM(privateKey, publicKey);
    }

    return new PEM(privateKey);
  }

  private PEM decode_X_509(String encodedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    byte[] bytes = getKeyBytes(encodedKey, X509_PUBLIC_KEY_PREFIX, X509_PUBLIC_KEY_SUFFIX);
    DerValue[] sequence = new DerInputStream(bytes).getSequence();

    // DER Encoded Public Key Format SubjectPublicKeyInfo
    // ------------------------------------------------------
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm       OBJECT IDENTIFIER,
    //   parameters      ANY DEFINED BY algorithm OPTIONAL
    // }

    if (sequence.length != 2 || !sequence[0].tag.is(Tag.Sequence) || !sequence[1].tag.is(Tag.BitString)) {
      // Expect the following format : [ Sequence | BitString ]
      throw new InvalidKeyException("Expected X.509 public key DER sequence format [Sequence | BitString]");
    }

    DerInputStream der = new DerInputStream(sequence[0].toByteArray());
    ObjectIdentifier algorithmOID = der.getOID();

    KeyType type = KeyType.forOid(algorithmOID.decode());
    if (type == null) {
      throw new InvalidKeyException("Expected [2] values in X.509 public key DER sequence but found [" + sequence.length + "]");
    }

    return new PEM(KeyFactory.getInstance(jcaKeyFactoryName(algorithmOID.decode(), type)).generatePublic(new X509EncodedKeySpec(bytes)));
  }

  /**
   * Parse the TBSCertificate fields out of a DER-encoded X.509 certificate without
   * relying on {@link CertificateFactory}. Supports v1 (no version field) and v3
   * (explicit [0] EXPLICIT version) layouts.
   *
   * <p>Returned fields: {@code serialNumber}, {@code issuer} (raw DN bytes from the DER
   * encoding), {@code subject} (raw DN bytes), {@code notBefore} and {@code notAfter}
   * (decoded UTCTime / GeneralizedTime). Use this when you need certificate
   * metadata without materialising an {@link java.security.cert.X509Certificate}.</p>
   *
   * @param derCertificate the full DER-encoded X.509 certificate bytes
   * @return the parsed TBS field record
   */
  public TBSFields decodeTBSCertificateFields(byte[] derCertificate) {
    Objects.requireNonNull(derCertificate, "derCertificate");
    try {
      // Parse outer Certificate SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
      DerValue[] outer = new DerInputStream(derCertificate).getSequence();
      if (outer.length < 1) {
        throw new PEMDecoderException("Expected at least [1] element in certificate outer sequence but found [" + outer.length + "]");
      }
      // outer[0] is TBSCertificate (a SEQUENCE). Its toByteArray() returns the SEQUENCE's
      // body (children), which we walk as a list of DerValues.
      java.util.List<DerValue> tbs = parseValues(outer[0].toByteArray());

      int idx = 0;
      // Optional [0] EXPLICIT version
      if (!tbs.isEmpty() && tbs.get(0).tag.rawByte == (byte) 0xA0) {
        idx++;
      }
      BigInteger serial = tbs.get(idx++).getBigInteger();
      // signature AlgorithmIdentifier (SEQUENCE) -- skip
      idx++;
      byte[] issuer = encodeSequenceOf(tbs.get(idx++));
      // validity SEQUENCE { notBefore, notAfter }
      java.util.List<DerValue> validity = parseValues(tbs.get(idx++).toByteArray());
      Instant notBefore = decodeTime(validity.get(0));
      Instant notAfter = decodeTime(validity.get(1));
      byte[] subject = encodeSequenceOf(tbs.get(idx));

      return new TBSFields(serial, issuer, subject, notBefore, notAfter);
    } catch (Exception e) {
      throw new PEMDecoderException(e);
    }
  }

  /**
   * Walk a sequence-of-DerValues blob (no outer SEQUENCE tag/length): keep reading
   * tag/length/value triples until exhausted.
   */
  private static java.util.List<DerValue> parseValues(byte[] body) throws Exception {
    java.util.List<DerValue> out = new java.util.ArrayList<>();
    DerInputStream s = new DerInputStream(body);
    while (s.data.available() > 0) {
      out.add(s.readDerValue());
    }
    return out;
  }

  private static byte[] encodeSequenceOf(DerValue dv) throws Exception {
    // Re-emit the value as full DER (preserve original tag + length + content) so
    // callers can pass it to e.g. javax.security.auth.x500.X500Principal if they wish.
    return new DerOutputStream()
        .writeValue(dv)
        .toByteArray();
  }

  private static Instant decodeTime(DerValue v) {
    String s = new String(v.toByteArray(), StandardCharsets.US_ASCII);
    if (v.tag.value == Tag.UTCTime) {
      DateTimeFormatter f = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'");
      LocalDateTime ldt = LocalDateTime.parse(s, f);
      // 2-digit year: 50-99 -> 1950-1999, 00-49 -> 2000-2049 (X.690 §11.8)
      int year = ldt.getYear();
      if (year >= 2000 + 50) {
        ldt = ldt.withYear(year - 100);
      }
      return ldt.toInstant(ZoneOffset.UTC);
    } else if (v.tag.value == Tag.GeneralizedTime) {
      DateTimeFormatter f = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");
      return LocalDateTime.parse(s, f).toInstant(ZoneOffset.UTC);
    }
    throw new IllegalArgumentException("Unexpected time tag [" + v.tag + "]");
  }

  /**
   * Field record for a parsed TBSCertificate. Distinguished names are returned in
   * raw DER form (the encoded {@code Name} SEQUENCE) so callers can hand them to
   * higher-level X.500 APIs without re-parsing.
   */
  public record TBSFields(BigInteger serialNumber,
                          byte[] issuerDer,
                          byte[] subjectDer,
                          Instant notBefore,
                          Instant notAfter) {
  }

  private byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
    int startIndex = key.indexOf(keyPrefix);
    int endIndex = key.indexOf(keySuffix);

    String base64 = key.substring(startIndex + keyPrefix.length(), endIndex).replaceAll("\\s+", "");
    return Base64.getDecoder().decode(base64);
  }

  private byte[] getEncodedPublicKeyFromPrivate(byte[] bitString, byte[] encodedKey) throws IOException {
    DerValue[] sequence = new DerInputStream(encodedKey).getSequence();
    return derEncodePublicKey(sequence[1].toByteArray(), bitString);
  }

  private byte[] derEncodePublicKey(byte[] algorithmIdentifier, byte[] publicKeyBytes) throws IOException {
    // Build an X.509 DER encoded byte array from the provided byte[]
    //
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    return new DerOutputStream()
        .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
            .writeValue(new DerValue(Tag.Sequence, algorithmIdentifier))
            .writeValue(new DerValue(Tag.BitString, publicKeyBytes))))
        .toByteArray();
  }

  /**
   * Map a DER algorithm OID + resolved {@link KeyType} to the JCA algorithm
   * string consumed by {@link KeyFactory#getInstance(String)}.
   *
   * @param oid the algorithm OID extracted from the DER stream
   * @param type the resolved {@code KeyType} (RSA, EC, OKP)
   * @return the JCA name (e.g. {@code "RSA"}, {@code "RSASSA-PSS"}, {@code "EC"}, {@code "EdDSA"})
   */
  private String jcaKeyFactoryName(String oid, KeyType type) {
    // PSS-specific OID maps to JCA "RSASSA-PSS" KeyFactory (provider-dependent).
    // All other RSA OIDs use the generic "RSA" KeyFactory.
    if (org.lattejava.jwt.internal.der.ObjectIdentifier.RSASSA_PSS_ENCRYPTION.equals(oid)) {
      return "RSASSA-PSS";
    }
    if (type == KeyType.OKP) {
      return "EdDSA";
    }
    return type.name();
  }

  private PublicKey getPublicKeyFromPrivateEC(DerValue bitString, ECPrivateKey privateKey) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    // Build an X.509 DER encoded byte array from the provided bitString
    //
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    byte[] encodedPublicKey = getEncodedPublicKeyFromPrivate(bitString.toByteArray(), privateKey.getEncoded());
    return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encodedPublicKey));
  }
}
