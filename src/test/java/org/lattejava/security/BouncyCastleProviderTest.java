/*
 * Copyright (c) 2025, the latte-java project authors
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

package org.lattejava.security;

import org.lattejava.jwt.domain.Algorithm;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.testng.annotations.Test;

import javax.crypto.Mac;
import javax.net.ssl.SSLContext;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

/**
 * A playground for Bouncy Castle testing (mostly for FIPS).
 *
 * @author Brian Pontarelli
 */
public class BouncyCastleProviderTest {
//  static {
//    System.setProperty("org.bouncycastle.fips.approved_only", "true");
//    Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
//    SSLContext context = null;
//    try {
//      context = SSLContext.getDefault();
//      System.out.println(context.getProvider().getClass());
//    } catch (NoSuchAlgorithmException e) {
//      e.printStackTrace();
//    }
//    System.out.println(context);
//  }

  @Test(enabled = false)
  public void jca() {
    Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);

    for (Algorithm algorithm : Algorithm.values()) {
      try {
        Mac mac = Mac.getInstance(algorithm.getName());
//        System.out.println(mac.getClass());
        System.out.println("For algo [" + algorithm.getName() + "] " + mac.getProvider().getClass());
//        System.out.println();
      } catch (NoSuchAlgorithmException e) {
        System.out.println("Missing mac algo [" + algorithm.getName() + "]");
      }
    }

    for (Algorithm algorithm : Algorithm.values()) {
      try {
        Signature signature = Signature.getInstance(algorithm.getName());
//        System.out.println(signature.getClass());
        System.out.println("For algo [" + algorithm.getName() + "] " + signature.getProvider().getClass());
//        System.out.println();
      } catch (NoSuchAlgorithmException e) {
        System.out.println("Missing signature algo [" + algorithm.getName() + "]");
      }
    }

    try {
      MessageDigest md = MessageDigest.getInstance("SHA-512");
      System.out.println("For algo [SHA-512] " + md.getClass() + " " + md.getProvider());
    } catch (NoSuchAlgorithmException e) {
      System.out.println(e);
    }

    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      System.out.println("For algo [MD5] " + md.getClass() + " " + md.getProvider());
    } catch (NoSuchAlgorithmException e) {
      System.out.println(e);
    }
  }

  @Test(enabled = false)
  public void sslContext() throws Exception {
    Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
    var context = SSLContext.getDefault();
    System.out.println(context);
  }
}
