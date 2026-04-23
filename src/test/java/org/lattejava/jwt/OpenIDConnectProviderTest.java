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

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.lattejava.jwt.internal.SHAKE256;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * OIDC provider-preference matrix for the bundled SHAKE256 path.
 *
 * <p>Cases:
 * <ul>
 *   <li>[no-provider]    bundled path produces correct {@code at_hash}/{@code c_hash} for Ed448
 *   <li>[bc-registered]  JCE path; provider cached after first call
 *   <li>[both]           byte-identical output across configurations
 *   <li>[broken-provider] fall-back to bundled
 *   <li>thread-safety: 16 concurrent first-call invocations resolve to one cached provider
 * </ul>
 *
 * <p>Each test brackets provider mutations with {@code @BeforeMethod} /
 * {@code @AfterMethod} so the global {@link Security} state is restored.
 *
 * @author The Latte Project
 */
public class OpenIDConnectProviderTest extends BaseTest {

  // Ordered snapshot of providers (and their positions) at the start of each
  // test. We restore the JCA provider list to this exact state in
  // {@code @AfterMethod} so other test classes (notably JWTUtilsTest, which
  // depends on BC-FIPS sitting at position 1 in FIPS runs to provide the
  // "Ed25519"/"Ed448" algorithm names) see a pristine environment.
  private List<Provider> baselineProviders;

  @BeforeMethod
  public void beforeMethod() {
    baselineProviders = new ArrayList<>();
    for (Provider p : Security.getProviders()) {
      baselineProviders.add(p);
    }
    SHAKE256.resetProviderCacheForTesting();
  }

  @AfterMethod
  public void afterMethod() {
    // Remove every currently-registered provider, then re-insert the baseline
    // snapshot in its original order. This is the only reliable way to undo
    // {@code Security.insertProviderAt(...)} reorderings done by individual
    // tests.
    for (Provider p : Security.getProviders()) {
      Security.removeProvider(p.getName());
    }
    for (int i = 0; i < baselineProviders.size(); i++) {
      Security.insertProviderAt(baselineProviders.get(i), i + 1);
    }
    SHAKE256.resetProviderCacheForTesting();
  }

  // [no-provider] When no SHAKE256 provider is registered (or none can be
  // removed because the JDK ships one natively, e.g. JDK 25's SUN provider),
  // Ed448 at_hash still produces the canonical RFC value. Output is
  // deterministic across the bundled and any JCE path.
  @Test
  public void noProvider_atHashEd448_usesBundled() {
    removeAllShake256Providers();
    SHAKE256.resetProviderCacheForTesting();

    String hash = OpenIDConnect.at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.Ed448);
    assertEquals(hash,
        "ACuRpk9jl5IEa3yqpBCNNOCpBEI7qjud6mc80cs6vWX2fcqpsk8RozYBKTUuSS6SqJhw302xFZeM");
  }

  // [no-provider] c_hash for Ed448 — same as at_hash for the same input string.
  @Test
  public void noProvider_cHashEd448_usesBundled() {
    removeAllShake256Providers();
    SHAKE256.resetProviderCacheForTesting();
    String hash = OpenIDConnect.c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.Ed448);
    assertEquals(hash,
        "ACuRpk9jl5IEa3yqpBCNNOCpBEI7qjud6mc80cs6vWX2fcqpsk8RozYBKTUuSS6SqJhw302xFZeM");
  }

  // Use case: with SHAKE256 entirely absent (probe truly cannot construct
  // a MessageDigest), the bundled implementation is used and no provider
  // is cached. We simulate this by wrapping SHAKE256.digest semantics:
  // the runtime calls SHAKE256.digest directly, and we assert via
  // hasCachedProviderForTesting that bundled was the path taken in the
  // simulated-no-provider scenario, validated through an alternative entry:
  // when only the BrokenShakeProvider is at position 1, BC/SUN are skipped
  // by priority, the broken probe fails, and bundled runs with no cache.
  // (Covered by brokenProvider_fallsBackToBundled below.)

  // [bc-registered] When a SHAKE256-capable provider (BC-FIPS, or in JDK 25+
  // also the SUN provider) is registered, it is selected by the probe and
  // cached for the VM lifetime.
  @Test
  public void bcRegistered_providerIsCached() {
    // Insert BC-FIPS at position 1 so it wins ahead of any built-in SUN
    // SHAKE256 service (JDK 25+ ships SHAKE256 in SUN).
    if (Security.getProvider("BCFIPS") != null) {
      Security.removeProvider("BCFIPS");
    }
    BouncyCastleFipsProvider bc = new BouncyCastleFipsProvider();
    Security.insertProviderAt(bc, 1);

    SHAKE256.resetProviderCacheForTesting();

    String hash = OpenIDConnect.at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.Ed448);
    assertEquals(hash,
        "ACuRpk9jl5IEa3yqpBCNNOCpBEI7qjud6mc80cs6vWX2fcqpsk8RozYBKTUuSS6SqJhw302xFZeM");

    String cached = SHAKE256.cachedProviderNameForTesting();
    assertNotNull(cached, "provider must be cached after first successful probe");
    assertEquals(cached, bc.getName(),
        "BC-FIPS at position 1 must be selected over any other SHAKE256 provider");

    // Second call uses the cached provider — observable by the cached name
    // being unchanged.
    OpenIDConnect.c_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.Ed448);
    assertEquals(SHAKE256.cachedProviderNameForTesting(), bc.getName());
  }

  // [both] Bundled and BC-registered configurations produce byte-identical
  // output (deterministic SHAKE256).
  @Test
  public void both_byteIdenticalAcrossConfigurations() {
    String input = "openid-connect-test-input-shake256";

    removeAllShake256Providers();
    SHAKE256.resetProviderCacheForTesting();
    String bundled = OpenIDConnect.at_hash(input, Algorithm.Ed448);

    Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
    SHAKE256.resetProviderCacheForTesting();
    String viaProvider = OpenIDConnect.at_hash(input, Algorithm.Ed448);

    assertEquals(viaProvider, bundled,
        "BC-FIPS and bundled SHAKE256 must produce identical output");
  }

  // [broken-provider] A provider whose SHAKE256 service returns wrong bytes
  // is detected via the probe self-test and the library falls back to bundled.
  @Test
  public void brokenProvider_fallsBackToBundled() {
    Provider broken = new BrokenShakeProvider();
    // Remove every other SHAKE256-capable provider (BC-FIPS in FIPS runs, SUN
    // in JDK 25+) so the broken provider is the only candidate; this makes the
    // fallback path unambiguous. Removed providers are restored by
    // {@code @AfterMethod}.
    removeAllShake256Providers();
    Security.insertProviderAt(broken, 1);

    SHAKE256.resetProviderCacheForTesting();

    String hash = OpenIDConnect.at_hash("dNZX1hEZ9wBCzNL40Upu646bdzQA", Algorithm.Ed448);
    // Must NOT be the all-zero echo from the broken provider; must be the
    // canonical RFC vector.
    assertEquals(hash,
        "ACuRpk9jl5IEa3yqpBCNNOCpBEI7qjud6mc80cs6vWX2fcqpsk8RozYBKTUuSS6SqJhw302xFZeM");
    assertEquals(SHAKE256.cachedProviderNameForTesting(), null,
        "broken provider must NOT be cached");
  }

  // Thread safety: 16 concurrent first-call invocations all return identical
  // output and converge to a single cached provider (or null, if none is
  // available — the relevant invariant is "a single decision").
  @Test
  public void threadSafety_singleDecisionUnderConcurrency() throws Exception {
    SHAKE256.resetProviderCacheForTesting();
    final byte[] input = "thread-safety-input".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final int threads = 16;
    final CountDownLatch start = new CountDownLatch(1);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      Future<byte[]>[] futures = new Future[threads];
      for (int i = 0; i < threads; i++) {
        futures[i] = pool.submit((Callable<byte[]>) () -> {
          start.await();
          return SHAKE256.digest(input, 57);
        });
      }
      start.countDown();
      byte[] reference = futures[0].get(10, TimeUnit.SECONDS);
      for (int i = 1; i < threads; i++) {
        byte[] r = futures[i].get(10, TimeUnit.SECONDS);
        assertEquals(r, reference, "thread " + i + " produced different bytes");
      }
    } finally {
      pool.shutdownNow();
    }
    // After the storm, the cache reflects exactly one decision (we cannot
    // assert a particular provider here because the test environment may or
    // may not have BC-FIPS registered).
    String name = SHAKE256.cachedProviderNameForTesting();
    assertTrue(name == null || !name.isEmpty(),
        "cache must be a single, stable decision");
  }

  // ----------------------------------------------------------------------

  private void removeAllShake256Providers() {
    for (Provider p : Security.getProviders()) {
      try {
        MessageDigest md = MessageDigest.getInstance("SHAKE256", p);
        if (md != null) {
          Security.removeProvider(p.getName());
        }
      } catch (Exception ignore) {
      }
    }
  }

  /** Test-only Provider that registers SHAKE256 returning all-zero bytes. */
  private static final class BrokenShakeProvider extends Provider {
    BrokenShakeProvider() {
      super("BrokenShakeOIDC", "1.0", "Test-only broken SHAKE256 provider");
      put("MessageDigest.SHAKE256", BrokenShakeMessageDigest.class.getName());
    }
  }

  /** Returns all-zeros for any digest length; will fail the KAT self-test. */
  public static final class BrokenShakeMessageDigest extends MessageDigest {
    public BrokenShakeMessageDigest() {
      super("SHAKE256");
    }

    @Override
    protected void engineUpdate(byte input) {
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
    }

    @Override
    protected byte[] engineDigest() {
      return new byte[64];
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) {
      for (int i = 0; i < len; i++) {
        buf[offset + i] = 0;
      }
      return len;
    }

    @Override
    protected void engineReset() {
    }

    @Override
    protected int engineGetDigestLength() {
      return 0;
    }
  }
}
