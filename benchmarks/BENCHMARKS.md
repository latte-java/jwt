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
| 1 | latte-jwt | 355694 |
| 2 | fusionauth-jwt | 250648 |
| 3 | vertx-auth-jwt | 238132 |
| 4 | auth0-java-jwt | 234137 |
| 5 | latte-jwt-jackson | 181624 |
| 6 | nimbus-jose-jwt | 93027 |
| 7 | jjwt | 62883 |
| 8 | jose4j | 59815 |
| | _baseline (JCA)_ | _455102_ |

## Throughput by algorithm (ops/sec, higher is better)

### HS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 1089742 | 100.0 % | 106.1 % |
| 2 | latte-jwt | 1026861 | 94.2 % | 100.0 % |
| 3 | latte-jwt-jackson | 894084 | 82.0 % | 87.1 % |
| 4 | fusionauth-jwt | 808988 | 74.2 % | 78.8 % |
| 5 | auth0-java-jwt | 737308 | 67.7 % | 71.8 % |
| 6 | nimbus-jose-jwt | 422450 | 38.8 % | 41.1 % |
| 7 | jjwt | 222377 | 20.4 % | 21.7 % |
| 8 | jose4j | 178596 | 16.4 % | 17.4 % |
| | _baseline (JCA)_ | _2400547_ | _220.3 %_ | _233.8 %_ |

### HS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1024076 | 100.0 % | 100.0 % |
| 2 | fusionauth-jwt | 710477 | 69.4 % | 69.4 % |
| 3 | vertx-auth-jwt | 670971 | 65.5 % | 65.5 % |
| 4 | auth0-java-jwt | 659895 | 64.4 % | 64.4 % |
| 5 | latte-jwt-jackson | 503100 | 49.1 % | 49.1 % |
| 6 | nimbus-jose-jwt | 241553 | 23.6 % | 23.6 % |
| 7 | jjwt | 155819 | 15.2 % | 15.2 % |
| 8 | jose4j | 145477 | 14.2 % | 14.2 % |
| | _baseline (JCA)_ | _1321779_ | _129.1 %_ | _129.1 %_ |

### RS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1623 | 100.0 % | 100.0 % |
| 2 | auth0-java-jwt | 1599 | 98.5 % | 98.5 % |
| 3 | vertx-auth-jwt | 1598 | 98.5 % | 98.5 % |
| 4 | latte-jwt-jackson | 1569 | 96.7 % | 96.7 % |
| 5 | nimbus-jose-jwt | 1555 | 95.9 % | 95.9 % |
| 6 | jjwt | 1522 | 93.8 % | 93.8 % |
| 7 | jose4j | 1519 | 93.6 % | 93.6 % |
| 8 | fusionauth-jwt | 1471 | 90.7 % | 90.7 % |
| | _baseline (JCA)_ | _1625_ | _100.2 %_ | _100.2 %_ |

### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 40075 | 100.0 % | 100.9 % |
| 2 | latte-jwt | 39730 | 99.1 % | 100.0 % |
| 3 | auth0-java-jwt | 39413 | 98.3 % | 99.2 % |
| 4 | latte-jwt-jackson | 38863 | 97.0 % | 97.8 % |
| 5 | fusionauth-jwt | 38439 | 95.9 % | 96.7 % |
| 6 | nimbus-jose-jwt | 34345 | 85.7 % | 86.4 % |
| 7 | jose4j | 30934 | 77.2 % | 77.9 % |
| 8 | jjwt | 29915 | 74.6 % | 75.3 % |
| | _baseline (JCA)_ | _40198_ | _100.3 %_ | _101.2 %_ |

### ES256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 11093 | 100.0 % | 102.6 % |
| 2 | latte-jwt | 10816 | 97.5 % | 100.0 % |
| 3 | nimbus-jose-jwt | 10584 | 95.4 % | 97.9 % |
| 4 | auth0-java-jwt | 10441 | 94.1 % | 96.5 % |
| 5 | fusionauth-jwt | 10065 | 90.7 % | 93.1 % |
| 6 | latte-jwt-jackson | 9830 | 88.6 % | 90.9 % |
| 7 | jose4j | 9711 | 87.5 % | 89.8 % |
| 8 | jjwt | 9517 | 85.8 % | 88.0 % |
| | _baseline (JCA)_ | _11118_ | _100.2 %_ | _102.8 %_ |

### ES256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 3350 | 100.0 % | 102.3 % |
| 2 | latte-jwt | 3276 | 97.8 % | 100.0 % |
| 3 | nimbus-jose-jwt | 3183 | 95.0 % | 97.2 % |
| 4 | auth0-java-jwt | 3104 | 92.7 % | 94.7 % |
| 5 | jose4j | 3034 | 90.6 % | 92.6 % |
| 6 | fusionauth-jwt | 3027 | 90.4 % | 92.4 % |
| 7 | jjwt | 2914 | 87.0 % | 88.9 % |
| 8 | latte-jwt-jackson | 2908 | 86.8 % | 88.8 % |
| | _baseline (JCA)_ | _3330_ | _99.4 %_ | _101.7 %_ |

## Supporting operations

### Unsafe decode — claims only (base64 + JSON parse of payload, no signature verification, no header parse)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 2260249 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 1690892 | 74.8 % | 74.8 % |
| 3 | fusionauth-jwt | 1256951 | 55.6 % | 55.6 % |
| 4 | nimbus-jose-jwt | 264113 | 11.7 % | 11.7 % |
| | _baseline (JCA)_ | _10307348_ | _456.0 %_ | _456.0 %_ |

### Unsafe decode — full (header + claims, no signature verification)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | nimbus-jose-jwt | 1550467 | 100.0 % | 101.3 % |
| 2 | latte-jwt | 1530630 | 98.7 % | 100.0 % |
| 3 | auth0-java-jwt | 1057208 | 68.2 % | 69.1 % |
| 4 | latte-jwt-jackson | 1015506 | 65.5 % | 66.3 % |
| 5 | jose4j | 159891 | 10.3 % | 10.4 % |
| | _baseline (JCA)_ | _8714002_ | _562.0 %_ | _569.3 %_ |

## Run conditions

```json
{
  "uname": "Darwin Mac.localdomain 24.6.0 Darwin Kernel Version 24.6.0: Wed Nov  5 21:34:00 PST 2025; root:xnu-11417.140.69.705.2~1/RELEASE_ARM64_T8132 arm64\n",
  "hardware": "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac16,13\n      Model Number: Z1DG000FZLL/A\n      Chip: Apple M4\n      Total Number of Cores: 10 (4 performance and 6 efficiency)\n      Memory: 24 GB\n      System Firmware Version: 13822.61.10\n      OS Loader Version: 11881.140.96\n      Serial Number (system): M09PFPW9V2\n      Hardware UUID: 16709DC3-9DCC-545C-AEA0-380D76082CD4\n      Provisioning UDID: 00008132-000A103C02F8801C\n\n",
  "thermal": "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
  "java": "    java.version = 25.0.2\n    java.version.date = 2026-01-20\n    java.vm.compressedOopsMode = Zero based\n    java.vm.info = mixed mode, sharing\n    java.vm.name = OpenJDK 64-Bit Server VM\n    java.vm.specification.name = Java Virtual Machine Specification\n    java.vm.specification.vendor = Oracle Corporation\n    java.vm.specification.version = 25\n    java.vm.vendor = Eclipse Adoptium\n    java.vm.version = 25.0.2+10-LTS\n    os.arch = aarch64\n    os.name = Mac OS X\n    os.version = 15.7.3\n    sun.arch.data.model = 64\n",
  "jmh_args": "-wi 2 -w 5s -i 3 -r 10s -f 3 -t 1 -rf json",
  "captured_at": "2026-05-01T17:13:41Z"
}
```

<!-- BENCHMARKS:END -->

