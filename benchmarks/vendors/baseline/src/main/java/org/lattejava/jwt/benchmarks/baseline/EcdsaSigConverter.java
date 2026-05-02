/*
 * Copyright (c) 2026, The Latte Project, All Rights Reserved
 * License: MIT (See LICENSE file in root)
 */
package org.lattejava.jwt.benchmarks.baseline;

/**
 * Convert ECDSA signatures between DER (JCA's native format) and JOSE concat-r-s
 * (JWS's required format per RFC 7518). For P-256, each component is 32 bytes.
 */
final class EcdsaSigConverter {

  static byte[] derToJOSE(byte[] der, int componentLen) {
    // DER layout: 0x30 <seq-len> 0x02 <r-len> [0x00] <r-bytes> 0x02 <s-len> [0x00] <s-bytes>
    int rOff = 4;
    int rLen = der[3] & 0xff;
    if (der[rOff] == 0x00) { rOff++; rLen--; }
    int sOff = 4 + (der[3] & 0xff) + 2;
    int sLen = der[sOff - 1] & 0xff;
    if (der[sOff] == 0x00) { sOff++; sLen--; }

    byte[] out = new byte[componentLen * 2];
    System.arraycopy(der, rOff, out, componentLen - rLen, rLen);
    System.arraycopy(der, sOff, out, componentLen + componentLen - sLen, sLen);
    return out;
  }

  static byte[] joseToDer(byte[] jose, int componentLen) {
    byte[] r = trimLeadingZeros(jose, 0, componentLen);
    byte[] s = trimLeadingZeros(jose, componentLen, componentLen);
    int rPad = (r[0] & 0x80) != 0 ? 1 : 0;
    int sPad = (s[0] & 0x80) != 0 ? 1 : 0;
    int totalLen = 2 + r.length + rPad + 2 + s.length + sPad;
    byte[] out = new byte[2 + totalLen];
    int p = 0;
    out[p++] = 0x30;
    out[p++] = (byte) totalLen;
    out[p++] = 0x02;
    out[p++] = (byte) (r.length + rPad);
    if (rPad == 1) out[p++] = 0x00;
    System.arraycopy(r, 0, out, p, r.length); p += r.length;
    out[p++] = 0x02;
    out[p++] = (byte) (s.length + sPad);
    if (sPad == 1) out[p++] = 0x00;
    System.arraycopy(s, 0, out, p, s.length);
    return out;
  }

  private static byte[] trimLeadingZeros(byte[] src, int off, int len) {
    int start = off;
    int end = off + len;
    while (start < end - 1 && src[start] == 0) start++;
    byte[] out = new byte[end - start];
    System.arraycopy(src, start, out, 0, out.length);
    return out;
  }

  private EcdsaSigConverter() {}
}
