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

import org.lattejava.jwt.internal.HexUtils;
import org.lattejava.jwt.internal.der.DerOutputStream;
import org.lattejava.jwt.internal.der.DerValue;
import org.lattejava.jwt.internal.der.ObjectIdentifier;
import org.lattejava.jwt.internal.der.Tag;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Facade for X.509 certificate construction.
 *
 * <p>Use {@link #builder()} to construct a self-signed or CA-signed X.509
 * (v3) certificate without depending on private JDK classes. The builder
 * encodes the TBSCertificate as DER (per RFC 5280 &sect;4.1), signs it with
 * a {@link java.security.Signature} configured to match the requested
 * {@link Algorithm}, and wraps the result in the outer Certificate
 * SEQUENCE. The encoded bytes are re-parsed via the JDK
 * {@link java.security.cert.CertificateFactory} to materialise an
 * {@link X509Certificate} for the caller.</p>
 *
 * <p>Supported signature algorithms: RS256, RS384, RS512, PS256, PS384,
 * PS512, ES256, ES384, ES512, Ed25519, Ed448.</p>
 *
 * <p>Distinguished names are accepted as a comma-separated list of
 * {@code "ATTR=value"} pairs (CN, C, L, ST, O, OU). Full RFC 4514 parsing
 * is not supported.</p>
 *
 * @author Daniel DeGroff
 */
public final class X509 {
  private X509() {}

  /**
   * Returns a new {@link Builder} for constructing an X.509 certificate.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the SHA-256 fingerprint of {@code cert} as an uppercase hex
   * string with no separators.
   *
   * <p>The fingerprint is the SHA-256 digest over the certificate's DER
   * encoding -- the same value shown by {@code openssl x509 -fingerprint
   * -sha256} (with the colons removed). For the JOSE-spec encoding of the
   * same digest, see {@link #thumbprintSHA256(X509Certificate)}.</p>
   *
   * @param cert the X.509 certificate; non-null
   * @return uppercase hex of the SHA-256 digest of {@code cert.getEncoded()}
   * @throws IllegalArgumentException if the certificate cannot be encoded
   */
  public static String fingerprintSHA256(X509Certificate cert) {
    return HexUtils.fromBytes(digest("SHA-256", encoded(cert)));
  }

  /**
   * Returns the SHA-1 fingerprint of {@code cert} as an uppercase hex
   * string with no separators.
   *
   * <p>SHA-1 is retained for compatibility with older display formats
   * (Windows cert dialog, legacy {@code openssl x509 -fingerprint}). For
   * new use, prefer {@link #fingerprintSHA256(X509Certificate)}.</p>
   *
   * @param cert the X.509 certificate; non-null
   * @return uppercase hex of the SHA-1 digest of {@code cert.getEncoded()}
   * @throws IllegalArgumentException if the certificate cannot be encoded
   */
  public static String fingerprintSHA1(X509Certificate cert) {
    return HexUtils.fromBytes(digest("SHA-1", encoded(cert)));
  }

  /**
   * Returns the SHA-256 fingerprint of the supplied DER-encoded certificate
   * bytes as an uppercase hex string with no separators.
   *
   * <p>Use this overload when you already have raw DER bytes (for example,
   * the contents of a JWKS {@code x5c} element after base64 decoding) and
   * do not want to materialise an {@link X509Certificate}.</p>
   *
   * @param der the DER-encoded certificate bytes; non-null
   * @return uppercase hex of the SHA-256 digest of {@code der}
   */
  public static String fingerprintSHA256(byte[] der) {
    return HexUtils.fromBytes(digest("SHA-256", der));
  }

  /**
   * Returns the SHA-1 fingerprint of the supplied DER-encoded certificate
   * bytes as an uppercase hex string with no separators.
   *
   * <p>SHA-1 is retained for compatibility with older display formats; for
   * new use, prefer {@link #fingerprintSHA256(byte[])}.</p>
   *
   * @param der the DER-encoded certificate bytes; non-null
   * @return uppercase hex of the SHA-1 digest of {@code der}
   */
  public static String fingerprintSHA1(byte[] der) {
    return HexUtils.fromBytes(digest("SHA-1", der));
  }

  /**
   * Returns the SHA-256 thumbprint of {@code cert} as a base64url-no-pad
   * string. This is the encoding used in the JWS {@code x5t#S256} header
   * (RFC 7515 &sect;4.1.8).
   *
   * <p>For the hex form of the same digest, see
   * {@link #fingerprintSHA256(X509Certificate)}.</p>
   *
   * @param cert the X.509 certificate; non-null
   * @return base64url-no-pad of the SHA-256 digest of {@code cert.getEncoded()}
   * @throws IllegalArgumentException if the certificate cannot be encoded
   */
  public static String thumbprintSHA256(X509Certificate cert) {
    return base64url(digest("SHA-256", encoded(cert)));
  }

  /** SHA-256 thumbprint of {@code der}; see {@link #thumbprintSHA256(X509Certificate)}. */
  public static String thumbprintSHA256(byte[] der) {
    return base64url(digest("SHA-256", der));
  }

  /**
   * Returns the SHA-1 thumbprint of {@code cert} as a base64url-no-pad
   * string. This is the encoding used in the legacy JWS {@code x5t}
   * header (RFC 7515 &sect;4.1.7).
   *
   * @param cert the X.509 certificate; non-null
   * @return base64url-no-pad of the SHA-1 digest of {@code cert.getEncoded()}
   * @throws IllegalArgumentException if the certificate cannot be encoded
   */
  public static String thumbprintSHA1(X509Certificate cert) {
    return base64url(digest("SHA-1", encoded(cert)));
  }

  /** SHA-1 thumbprint of {@code der}; see {@link #thumbprintSHA1(X509Certificate)}. */
  public static String thumbprintSHA1(byte[] der) {
    return base64url(digest("SHA-1", der));
  }

  /**
   * Converts an uppercase hex X.509 fingerprint to its base64url-no-pad
   * thumbprint form. The input length determines the digest algorithm:
   * 40 hex chars (SHA-1) becomes an {@code x5t} value, 64 hex chars
   * (SHA-256) becomes an {@code x5t#S256} value.
   *
   * @param fingerprint the hex-encoded fingerprint; non-null
   * @return the equivalent base64url-no-pad thumbprint
   */
  public static String fingerprintToThumbprint(String fingerprint) {
    return base64url(HexUtils.toBytes(fingerprint));
  }

  /**
   * Converts a base64url-no-pad X.509 thumbprint to its uppercase hex
   * fingerprint form. Reverses {@link #fingerprintToThumbprint(String)}.
   *
   * @param thumbprint the base64url-no-pad thumbprint; non-null
   * @return the equivalent uppercase hex fingerprint
   */
  public static String thumbprintToFingerprint(String thumbprint) {
    return HexUtils.fromBytes(Base64.getUrlDecoder().decode(thumbprint.getBytes(StandardCharsets.UTF_8)));
  }

  // ---- Internal digest helpers ----

  private static byte[] encoded(X509Certificate cert) {
    try {
      return cert.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private static byte[] digest(String algorithm, byte[] bytes) {
    try {
      return MessageDigest.getInstance(algorithm).digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      // Algorithm name is hard-coded by callers ("SHA-1" / "SHA-256");
      // unreachable under any conformant JCA provider.
      throw new IllegalStateException(e);
    }
  }

  private static String base64url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Builder for a single X.509 certificate. Calling {@link #build()} performs
   * live cryptographic signing; each invocation signs fresh bytes and returns
   * a new {@link X509Certificate}. The builder may be reused to produce
   * additional certificates with the same TBS fields, but typical callers
   * should construct a fresh builder per certificate since serial number and
   * timestamps should differ.
   */
  public static final class Builder {
    private BigInteger serialNumber;

    private String issuerDn;

    private String subjectDn;

    private Instant notBefore;

    private Instant notAfter;

    private PublicKey publicKey;

    private PrivateKey signingKey;

    private Algorithm signatureAlgorithm;

    private Builder() {}

    /** Set the certificate serial number (required, must be non-null). */
    public Builder serialNumber(BigInteger serial) {
      this.serialNumber = serial;
      return this;
    }

    /**
     * Set the issuer Distinguished Name as a comma-separated list of
     * {@code "ATTR=value"} pairs (CN, C, L, ST, O, OU). For self-signed
     * certificates, pass the same DN as {@link #subject(String)}.
     */
    public Builder issuer(String dn) {
      this.issuerDn = dn;
      return this;
    }

    /**
     * Set the subject Distinguished Name as a comma-separated list of
     * {@code "ATTR=value"} pairs (CN, C, L, ST, O, OU).
     */
    public Builder subject(String dn) {
      this.subjectDn = dn;
      return this;
    }

    /**
     * Set the certificate validity window. {@code notBefore} must not be
     * after {@code notAfter}; violated at {@link #build()} time.
     */
    public Builder validity(Instant notBefore, Instant notAfter) {
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      return this;
    }

    /** Set the public key embedded in the certificate's SubjectPublicKeyInfo. */
    public Builder publicKey(PublicKey key) {
      this.publicKey = key;
      return this;
    }

    /**
     * Set the private key used to sign the certificate. For a self-signed
     * certificate this must correspond to {@link #publicKey(PublicKey)} so the
     * cert verifies against itself.
     */
    public Builder signingKey(PrivateKey key) {
      this.signingKey = key;
      return this;
    }

    /**
     * Set the JWA algorithm used to sign the certificate. Must be one of the
     * supported set (RS256/384/512, PS256/384/512, ES256/384/512, Ed25519,
     * Ed448). HMAC algorithms cannot sign certificates; ES256K is not supported
     * for X.509.
     *
     * <p>Rejected at setter time with an {@link IllegalArgumentException} so the
     * problem surfaces at the call site rather than during {@link #build()}.</p>
     */
    public Builder signatureAlgorithm(Algorithm algorithm) {
      Objects.requireNonNull(algorithm, "algorithm");
      switch (algorithm.name()) {
        case "RS256": case "RS384": case "RS512":
        case "PS256": case "PS384": case "PS512":
        case "ES256": case "ES384": case "ES512":
        case "Ed25519": case "Ed448":
          break;
        default:
          throw new IllegalArgumentException("Unsupported signature algorithm for X.509 [" + algorithm.name() + "]");
      }
      this.signatureAlgorithm = algorithm;
      return this;
    }

    /**
     * Build the certificate, sign it with the configured signing key under the
     * configured signature algorithm, and return the parsed {@link
     * X509Certificate}.
     */
    public X509Certificate build() {
      require(signingKey != null, "signingKey");
      require(signatureAlgorithm != null, "signatureAlgorithm");
      require(serialNumber != null, "serialNumber");
      require(issuerDn != null, "issuer");
      require(subjectDn != null, "subject");
      require(notBefore != null && notAfter != null, "validity");
      require(publicKey != null, "publicKey");
      if (notBefore.isAfter(notAfter)) {
        throw new IllegalStateException("Expected notBefore [" + notBefore + "] not after notAfter [" + notAfter + "]");
      }

      try {
        byte[] tbs = encodeTBSCertificate(signatureAlgorithm);
        byte[] signature = sign(tbs, signingKey, signatureAlgorithm);

        DerOutputStream cert = new DerOutputStream()
            .writeValue(new DerValue(new Tag(Tag.Sequence), new DerOutputStream()
                .writeValue(tbs)
                .writeValue(new DerValue(new Tag(Tag.Sequence), encodeAlgorithmIdentifier(signatureAlgorithm)))
                .writeValue(DerValue.newBitString(signature))));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.toByteArray()));
      } catch (RuntimeException re) {
        throw re;
      } catch (Exception e) {
        throw new PEMEncoderException(e);
      }
    }

    // ---- Internal: TBSCertificate construction ----

    private byte[] encodeTBSCertificate(Algorithm signatureAlgorithm) throws Exception {
      DerOutputStream tbs = new DerOutputStream()
          // version [0] EXPLICIT INTEGER (v3 = 2)
          .writeValue(new DerValue(0xA0, new DerOutputStream()
              .writeValue(new DerValue(BigInteger.valueOf(2)))))
          // serialNumber INTEGER
          .writeValue(new DerValue(serialNumber))
          // signature AlgorithmIdentifier
          .writeValue(new DerValue(new Tag(Tag.Sequence), encodeAlgorithmIdentifier(signatureAlgorithm)))
          // issuer Name
          .writeValue(new DerValue(new Tag(Tag.Sequence), encodeName(issuerDn)))
          // validity SEQUENCE { notBefore, notAfter }
          .writeValue(new DerValue(new Tag(Tag.Sequence), new DerOutputStream()
              .writeValue(encodeTime(notBefore))
              .writeValue(encodeTime(notAfter))))
          // subject Name
          .writeValue(new DerValue(new Tag(Tag.Sequence), encodeName(subjectDn)))
          // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey } - already DER-encoded by JDK
          .writeValue(publicKey.getEncoded());

      return new DerOutputStream()
          .writeValue(new DerValue(new Tag(Tag.Sequence), tbs))
          .toByteArray();
    }

    private DerValue encodeTime(Instant t) {
      return t.isBefore(DerValue.TIME_ENCODING_BOUNDARY)
          ? DerValue.newUTCTime(t)
          : DerValue.newGeneralizedTime(t);
    }

    /**
     * Encode a Distinguished Name as {@code SEQUENCE OF SET OF SEQUENCE { OID, value }}.
     * Supports a comma-separated list of {@code "ATTR=value"} pairs (CN, C, L, ST, O, OU).
     * The encoding produces one RDN (SET) per attribute, in the order given.
     */
    private DerOutputStream encodeName(String dn) throws Exception {
      Map<String, String> attributeOids = attributeOids();
      DerOutputStream nameBody = new DerOutputStream();
      String[] rdns = dn.split(",");
      for (String rdn : rdns) {
        int eq = rdn.indexOf('=');
        if (eq <= 0) {
          throw new IllegalArgumentException("Malformed RDN segment [" + rdn + "]");
        }
        String type = rdn.substring(0, eq).trim();
        String value = rdn.substring(eq + 1).trim();
        String oid = attributeOids.get(type);
        if (oid == null) {
          throw new IllegalArgumentException("Unsupported DN attribute [" + type + "]");
        }

        // SET OF SEQUENCE { AttributeType OID, AttributeValue UTF8String }
        DerOutputStream attrSeq = new DerOutputStream()
            .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(oid)))
            .writeValue(DerValue.newUTF8String(value));
        DerOutputStream rdnSet = new DerOutputStream()
            .writeValue(new DerValue(new Tag(Tag.Sequence), attrSeq));
        nameBody.writeValue(new DerValue(new Tag(Tag.Set), rdnSet));
      }
      return nameBody;
    }

    private static Map<String, String> attributeOids() {
      Map<String, String> m = new LinkedHashMap<>();
      m.put("CN", ObjectIdentifier.X_520_DN_COMMON_NAME);
      m.put("C", ObjectIdentifier.X_520_DN_COUNTRY);
      m.put("L", ObjectIdentifier.X_520_DN_LOCALITY);
      m.put("ST", ObjectIdentifier.X_520_DN_STATE);
      m.put("O", ObjectIdentifier.X_520_DN_ORGANIZATION);
      m.put("OU", ObjectIdentifier.X_520_DN_ORGANIZATIONAL_UNIT);
      return m;
    }

    // ---- AlgorithmIdentifier encoding (per family) ----

    private DerOutputStream encodeAlgorithmIdentifier(Algorithm a) throws Exception {
      String name = a.name();
      switch (name) {
        case "RS256":
          return rsaAlgId(ObjectIdentifier.RSA_SHA256);
        case "RS384":
          return rsaAlgId(ObjectIdentifier.RSA_SHA384);
        case "RS512":
          return rsaAlgId(ObjectIdentifier.RSA_SHA512);
        case "PS256":
          return pssAlgId(ObjectIdentifier.SHA256, 32);
        case "PS384":
          return pssAlgId(ObjectIdentifier.SHA384, 48);
        case "PS512":
          return pssAlgId(ObjectIdentifier.SHA512, 64);
        case "ES256":
          return ecAlgId("1.2.840.10045.4.3.2");
        case "ES384":
          return ecAlgId("1.2.840.10045.4.3.3");
        case "ES512":
          return ecAlgId("1.2.840.10045.4.3.4");
        case "Ed25519":
          return eddsaAlgId(ObjectIdentifier.EdDSA_25519);
        case "Ed448":
          return eddsaAlgId(ObjectIdentifier.EdDSA_448);
        default:
          throw new IllegalArgumentException("Unsupported signature algorithm for X.509 [" + name + "]");
      }
    }

    /** RSA PKCS#1 v1.5: SEQUENCE { OID, NULL } */
    private DerOutputStream rsaAlgId(String oid) throws Exception {
      return new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(oid)))
          .writeValue(DerValue.newNull());
    }

    /** EC: SEQUENCE { OID } - no parameters per RFC 5758 &sect;3.2 (curve OID lives in SPKI). */
    private DerOutputStream ecAlgId(String oid) throws Exception {
      return new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(oid)));
    }

    /** EdDSA: SEQUENCE { OID } - parameters absent per RFC 8410 &sect;3. */
    private DerOutputStream eddsaAlgId(String oid) throws Exception {
      return new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(oid)));
    }

    /**
     * RSASSA-PSS: SEQUENCE { OID 1.2.840.113549.1.1.10, RSASSA-PSS-params }.
     *
     * <p>The params follow RFC 4055 &sect;3.1: hashAlgorithm[0], maskGenAlgorithm[1] with MGF1 OID
     * 1.2.840.113549.1.1.8 + the same hash, saltLength[2] = digest length, trailerField[3] = 1.</p>
     */
    private DerOutputStream pssAlgId(String hashOid, int saltLen) throws Exception {
      // hashAlgorithm: SEQUENCE { OID, NULL }
      DerOutputStream hashAlg = new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(hashOid)))
          .writeValue(DerValue.newNull());

      // maskGenAlgorithm: SEQUENCE { mgf1OID, hashAlgorithm }
      DerOutputStream maskGen = new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode("1.2.840.113549.1.1.8")))
          .writeValue(new DerValue(new Tag(Tag.Sequence), hashAlg));
      // Re-encode hashAlg for the outer use because it was consumed; rebuild instead of reusing
      DerOutputStream hashAlg2 = new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(hashOid)))
          .writeValue(DerValue.newNull());

      DerOutputStream params = new DerOutputStream()
          // [0] hashAlgorithm
          .writeValue(new DerValue(0xA0, new DerOutputStream()
              .writeValue(new DerValue(new Tag(Tag.Sequence), hashAlg2))))
          // [1] maskGenAlgorithm
          .writeValue(new DerValue(0xA1, new DerOutputStream()
              .writeValue(new DerValue(new Tag(Tag.Sequence), maskGen))))
          // [2] saltLength
          .writeValue(new DerValue(0xA2, new DerOutputStream()
              .writeValue(new DerValue(BigInteger.valueOf(saltLen)))))
          // [3] trailerField
          .writeValue(new DerValue(0xA3, new DerOutputStream()
              .writeValue(new DerValue(BigInteger.valueOf(1)))));

      return new DerOutputStream()
          .writeValue(new DerValue(Tag.ObjectIdentifier, ObjectIdentifier.encode(ObjectIdentifier.RSASSA_PSS_ENCRYPTION)))
          .writeValue(new DerValue(new Tag(Tag.Sequence), params));
    }

    // ---- Signing ----

    private byte[] sign(byte[] tbs, PrivateKey key, Algorithm algorithm) throws Exception {
      String name = algorithm.name();
      Signature signature;
      switch (name) {
        case "RS256": signature = Signature.getInstance("SHA256withRSA"); break;
        case "RS384": signature = Signature.getInstance("SHA384withRSA"); break;
        case "RS512": signature = Signature.getInstance("SHA512withRSA"); break;
        case "PS256":
          signature = Signature.getInstance("RSASSA-PSS");
          signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
          break;
        case "PS384":
          signature = Signature.getInstance("RSASSA-PSS");
          signature.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1));
          break;
        case "PS512":
          signature = Signature.getInstance("RSASSA-PSS");
          signature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
          break;
        case "ES256": signature = Signature.getInstance("SHA256withECDSA"); break;
        case "ES384": signature = Signature.getInstance("SHA384withECDSA"); break;
        case "ES512": signature = Signature.getInstance("SHA512withECDSA"); break;
        case "Ed25519": signature = Signature.getInstance("Ed25519"); break;
        case "Ed448":   signature = Signature.getInstance("Ed448"); break;
        default:
          throw new IllegalArgumentException("Unsupported signature algorithm for X.509 [" + name + "]");
      }
      signature.initSign(key);
      signature.update(tbs);
      return signature.sign();
    }

    private static void require(boolean cond, String field) {
      if (!cond) {
        throw new IllegalStateException("X509.Builder requires [" + field + "]");
      }
    }
  }
}
