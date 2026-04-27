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

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.*;
import java.util.*;

import org.lattejava.jwt.*;
import org.lattejava.jwt.internal.der.*;

import static org.lattejava.jwt.internal.pem.PEM.*;

/**
 * Encode a <code>PrivateKey</code> or <code>PublicKey</code> into a PEM formatted string.
 *
 * @author Daniel DeGroff
 */
public class PEMEncoder {
  private static final Base64.Encoder Base64_MIME_Encoder = Base64.getMimeEncoder(64, new byte[]{'\n'});

  /**
   * Encode the provided keys in a PEM format and return a string. If both private and public keys are provided a
   * private key PEM will be returned with the public key embedded.
   * <p>
   * If <code>null</code> is passed for one of the two parameters, a PEM will be returned that only includes the
   * non-null value.
   * <p>
   * Both values may not be null.
   *
   * @param privateKey the private key
   * @param publicKey  the public key
   * @return a PEM Encoded key
   */
  public String encode(PrivateKey privateKey, PublicKey publicKey) {
    if (privateKey == null && publicKey == null) {
      throw new PEMEncoderException(new InvalidParameterException("At least one key must be provided"));
    }

    Key key = Objects.requireNonNullElse(privateKey, publicKey);
    StringBuilder sb = new StringBuilder();
    addOpeningTag(key, sb);
    try {

      // There may be other cases where we need to rebuild the private key to get the public key embedded,
      // however, there are no tests for any other conditions than this one.
      if (key.getFormat().equals("PKCS#8") && key instanceof ECPrivateKey && publicKey != null) {
        byte[] encodedKey = key.getEncoded();

        DerValue[] sequence = new DerInputStream(encodedKey).getSequence();
        ObjectIdentifier algorithmOID = sequence[1].getOID();
        ObjectIdentifier curveOID = sequence[1].getOID();

        // DER Encoded PKCS#8  - version 0
        // ------------------------------------------------------
        // PrivateKeyInfo ::= SEQUENCE {
        //   version         Version,
        //   algorithm       AlgorithmIdentifier,
        //   PrivateKey      OCTET STRING        <--- un-encapsulated private key
        // }
        //
        // AlgorithmIdentifier ::= SEQUENCE {
        //   algorithm       OBJECT IDENTIFIER,
        //   parameters      ANY DEFINED BY algorithm OPTIONAL
        // }
        //
        //
        // EC Private Key - un-encapsulated
        //
        // ECPrivateKey ::= SEQUENCE {
        //     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //     privateKey     OCTET STRING,
        //     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        //     publicKey  [1] BIT STRING OPTIONAL
        // }

        // Check if the PrivateKey already includes the public key
        DerValue[] nested = new DerInputStream(sequence[2]).getSequence();
        if (nested.length >= 2) {
          // Re-build the PrivateKey and include the PublicKey passed into the method and NOT the PublicKey from the DER
          // (because it's optional)
          DerValue[] publicSequence = new DerInputStream(publicKey.getEncoded()).getSequence();
          byte[] nestedPrivateKeyBytes = new DerOutputStream().writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
              .writeValue(new DerValue(nested[0].getBigInteger()))
              .writeValue(new DerValue(Tag.OctetString, nested[1].toByteArray()))
              .writeValue(new DerValue(0xA1,
                  new DerOutputStream().writeValue(new DerValue(Tag.BitString, publicSequence[1].toByteArray()))))
          )).toByteArray();

          // Now encode the whole thing in an PKCS#8 container
          DerOutputStream pkcs_8 = new DerOutputStream()
              .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                  .writeValue(new DerValue(BigInteger.valueOf(0))) // Always version 0
                  .writeValue(new DerValue(Tag.Sequence, new DerOutputStream()
                      .writeValue(new DerValue(Tag.ObjectIdentifier, algorithmOID.value))
                      .writeValue(new DerValue(Tag.ObjectIdentifier, curveOID.value))))
                  .writeValue(new DerValue(Tag.OctetString, nestedPrivateKeyBytes))));

          sb.append(Base64_MIME_Encoder.encodeToString(pkcs_8.toByteArray()));
        }
      } else {
        sb.append(Base64_MIME_Encoder.encodeToString(key.getEncoded()));
      }

    } catch (IOException e) {
      throw new PEMEncoderException(e);
    }

    addClosingTag(key, sb);
    return sb.toString();
  }

  /**
   * Encode the provided key in a PEM format and return a string.
   * <p>
   * Both values may no be null.
   *
   * @param key the key, this parameter may be of type <code>PrivateKey</code> <code>PublicKey</code>
   * @return a PEM encoded key
   */
  public String encode(Key key) {
    if (key instanceof PrivateKey privateKey) {
      return encode(privateKey, null);
    } else if (key instanceof PublicKey publicKey) {
      return encode(null, publicKey);
    }

    throw new PEMEncoderException(new InvalidParameterException("Expected key type [PrivateKey | PublicKey] but found [" + key.getClass().getCanonicalName() + "]"));
  }

  /**
   * Encode the X.509 certificate in a PEM format and return a string.
   *
   * @param certificate The certificate
   * @return a PEM encoded certificate
   */
  public String encode(Certificate certificate) {
    try {
      return X509_CERTIFICATE_PREFIX + "\n" + Base64_MIME_Encoder.encodeToString(certificate.getEncoded()) + "\n" + X509_CERTIFICATE_SUFFIX;
    } catch (CertificateEncodingException e) {
      throw new PEMEncoderException(e);
    }
  }

  /**
   * Attempt to covert a ASN.1 DER encoded X.509 certificate into a PEM encoded string.
   *
   * @param derEncoded base64 ASN.1 DER encoded bytes of an X.509 certificate
   * @return a PEM encoded certificate
   */
  public String parseEncodedCertificate(String derEncoded) {
    return PEM.X509_CERTIFICATE_PREFIX + "\n" + chopIt(derEncoded) + "\n" + PEM.X509_CERTIFICATE_SUFFIX;
  }

  private void addClosingTag(Key key, StringBuilder sb) {
    sb.append("\n");
    if (key instanceof PrivateKey) {
      if (key.getFormat().equals("PKCS#1")) {
        sb.append(PEM.PKCS_1_PRIVATE_KEY_SUFFIX);
      } else if (key.getFormat().equals("PKCS#8")) {
        sb.append(PEM.PKCS_8_PRIVATE_KEY_SUFFIX);
      }
    } else {
      sb.append(PEM.X509_PUBLIC_KEY_SUFFIX);
    }
  }

  private void addOpeningTag(Key key, StringBuilder sb) {
    String format = key.getFormat();
    if (key instanceof PrivateKey) {
      if (format.equals("PKCS#1")) {
        sb.append(PEM.PKCS_1_PRIVATE_KEY_PREFIX).append("\n");
      } else if (format.equals("PKCS#8")) {
        sb.append(PEM.PKCS_8_PRIVATE_KEY_PREFIX).append("\n");
      } else {
        throw new PEMEncoderException(
            new InvalidParameterException("Expected private key format [PKCS#1] or [PKCS#8] but found [" + format + "]"));
      }
    } else {
      if (format.equals("X.509")) {
        sb.append(PEM.X509_PUBLIC_KEY_PREFIX).append("\n");
      } else {
        throw new PEMEncoderException(
            new InvalidParameterException("Expected public key format [X.509] but found [" + format + "]"));
      }
    }
  }

  private String chopIt(String s) {
    List<String> lines = new ArrayList<>();

    // The incoming string may or may not contain line returns, normalize first and then re-encode to 64 characters wide
    String normalized = removeLineReturns(s);

    for (int i = 0; i < normalized.length(); ) {
      lines.add(normalized.substring(i, Math.min(i + 64, normalized.length())));
      i = i + 64;
    }

    return String.join("\n", lines);
  }

  private String removeLineReturns(String str) {
    if (str == null) {
      return null;
    }

    return str.replaceAll("\\r\\n|\\r|\\n", "");
  }
}
