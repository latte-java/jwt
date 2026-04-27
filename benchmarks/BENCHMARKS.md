# JWT Library Benchmarks

This is the auto-generated benchmark report. The methodology is documented in
[the benchmark framework spec](../specs/benchmark-framework.md). To run benchmarks yourself,
see [`benchmarks/README.md`](README.md).

The numbers below come from a single run on a single machine. Relative ranking between libraries
is what matters; absolute ops/sec depend on hardware and JVM. Always re-run on your own
hardware before quoting absolute numbers.

<!-- BENCHMARKS:START -->

## Overall leaderboard — decode-verify-validate (the headline op)

Mean ops/sec across HS256, RS256, ES256 decode-verify-validate (Throughput mode):

| # | Library | mean ops/sec |
|--:|---------|-------------:|
| 1 | fusionauth-jwt | 280758 |
| 2 | auth0-java-jwt | 268537 |
| 3 | vertx-auth-jwt | 258409 |
| 4 | latte-jwt | 189859 |
| 5 | nimbus-jose-jwt | 102493 |
| 6 | jose4j | 66098 |
| 7 | jjwt | 50101 |
| | _baseline (JCA)_ | _402163_ |

## Throughput by algorithm (ops/sec, higher is better)

### HS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 1097686 | 100.0 % | 113.6 % |
| 2 | latte-jwt | 965913 | 88.0 % | 100.0 % |
| 3 | auth0-java-jwt | 879384 | 80.1 % | 91.0 % |
| 4 | fusionauth-jwt | 642519 | 58.5 % | 66.5 % |
| 5 | nimbus-jose-jwt | 474231 | 43.2 % | 49.1 % |
| 6 | jjwt | 258497 | 23.5 % | 26.8 % |
| 7 | jose4j | 199056 | 18.1 % | 20.6 % |
| | _baseline (JCA)_ | _2231726_ | _203.3 %_ | _231.0 %_ |

### HS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | fusionauth-jwt | 805843 | 100.0 % | 152.9 % |
| 2 | auth0-java-jwt | 761017 | 94.4 % | 144.4 % |
| 3 | vertx-auth-jwt | 732531 | 90.9 % | 139.0 % |
| 4 | latte-jwt | 526910 | 65.4 % | 100.0 % |
| 5 | nimbus-jose-jwt | 268075 | 33.3 % | 50.9 % |
| 6 | jose4j | 161605 | 20.1 % | 30.7 % |
| 7 | jjwt | 113501 | 14.1 % | 21.5 % |
| | _baseline (JCA)_ | _1161652_ | _144.2 %_ | _220.5 %_ |

### RS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 1699 | 100.0 % | 100.6 % |
| 2 | nimbus-jose-jwt | 1694 | 99.7 % | 100.3 % |
| 3 | latte-jwt | 1689 | 99.4 % | 100.0 % |
| 4 | jose4j | 1678 | 98.8 % | 99.4 % |
| 5 | jjwt | 1599 | 94.1 % | 94.7 % |
| 6 | vertx-auth-jwt | 1593 | 93.7 % | 94.3 % |
| 7 | fusionauth-jwt | 1460 | 85.9 % | 86.5 % |
| | _baseline (JCA)_ | _1673_ | _98.4 %_ | _99.0 %_ |

### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 41204 | 100.0 % | 104.7 % |
| 2 | vertx-auth-jwt | 39737 | 96.4 % | 100.9 % |
| 3 | latte-jwt | 39366 | 95.5 % | 100.0 % |
| 4 | nimbus-jose-jwt | 36041 | 87.5 % | 91.6 % |
| 5 | jjwt | 33505 | 81.3 % | 85.1 % |
| 6 | fusionauth-jwt | 33476 | 81.2 % | 85.0 % |
| 7 | jose4j | 33355 | 81.0 % | 84.7 % |
| | _baseline (JCA)_ | _42100_ | _102.2 %_ | _106.9 %_ |

### ES256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 11364 | 100.0 % | 100.0 % |
| 2 | auth0-java-jwt | 11206 | 98.6 % | 98.6 % |
| 3 | nimbus-jose-jwt | 11133 | 98.0 % | 98.0 % |
| 4 | vertx-auth-jwt | 10951 | 96.4 % | 96.4 % |
| 5 | fusionauth-jwt | 10880 | 95.7 % | 95.7 % |
| 6 | jose4j | 10787 | 94.9 % | 94.9 % |
| 7 | jjwt | 10708 | 94.2 % | 94.2 % |
| | _baseline (JCA)_ | _8626_ | _75.9 %_ | _75.9 %_ |

### ES256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 3391 | 100.0 % | 102.7 % |
| 2 | nimbus-jose-jwt | 3363 | 99.2 % | 101.9 % |
| 3 | jose4j | 3335 | 98.4 % | 101.1 % |
| 4 | latte-jwt | 3300 | 97.3 % | 100.0 % |
| 5 | jjwt | 3298 | 97.3 % | 99.9 % |
| 6 | vertx-auth-jwt | 2957 | 87.2 % | 89.6 % |
| 7 | fusionauth-jwt | 2956 | 87.2 % | 89.6 % |
| | _baseline (JCA)_ | _2738_ | _80.8 %_ | _83.0 %_ |

## Supporting operations

### Unsafe decode (no signature verification)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | fusionauth-jwt | 1701800 | 100.0 % | 247.5 % |
| 2 | nimbus-jose-jwt | 1689505 | 99.3 % | 245.7 % |
| 3 | auth0-java-jwt | 1133356 | 66.6 % | 164.8 % |
| 4 | latte-jwt | 687607 | 40.4 % | 100.0 % |
| 5 | jose4j | 180988 | 10.6 % | 26.3 % |
| | _baseline (JCA)_ | _10600358_ | _622.9 %_ | _1541.6 %_ |

## Run conditions

```json
{
  "uname": "Darwin Mac.localdomain 24.6.0 Darwin Kernel Version 24.6.0: Wed Nov  5 21:34:00 PST 2025; root:xnu-11417.140.69.705.2~1/RELEASE_ARM64_T8132 arm64\n",
  "hardware": "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac16,13\n      Model Number: Z1DG000FZLL/A\n      Chip: Apple M4\n      Total Number of Cores: 10 (4 performance and 6 efficiency)\n      Memory: 24 GB\n      System Firmware Version: 13822.61.10\n      OS Loader Version: 11881.140.96\n      Serial Number (system): M09PFPW9V2\n      Hardware UUID: 16709DC3-9DCC-545C-AEA0-380D76082CD4\n      Provisioning UDID: 00008132-000A103C02F8801C\n\n",
  "thermal": "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
  "java": "    java.version = 25.0.2\n    java.version.date = 2026-01-20\n    java.vm.compressedOopsMode = Zero based\n    java.vm.info = mixed mode, sharing\n    java.vm.name = OpenJDK 64-Bit Server VM\n    java.vm.specification.name = Java Virtual Machine Specification\n    java.vm.specification.vendor = Oracle Corporation\n    java.vm.specification.version = 25\n    java.vm.vendor = Eclipse Adoptium\n    java.vm.version = 25.0.2+10-LTS\n    os.arch = aarch64\n    os.name = Mac OS X\n    os.version = 15.7.3\n    sun.arch.data.model = 64\n",
  "jmh_args": "-wi 2 -w 5s -i 3 -r 10s -f 1 -t 1 -rf json",
  "captured_at": "2026-04-27T01:43:45Z"
}
```

<!-- BENCHMARKS:END -->

