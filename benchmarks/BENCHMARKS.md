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
| 1 | latte-jwt | 319537 |
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
| 1 | vertx-auth-jwt | 1089742 | 100.0 % | 116.8 % |
| 2 | latte-jwt | 933365 | 85.7 % | 100.0 % |
| 3 | latte-jwt-jackson | 894084 | 82.0 % | 95.8 % |
| 4 | fusionauth-jwt | 808988 | 74.2 % | 86.7 % |
| 5 | auth0-java-jwt | 737308 | 67.7 % | 79.0 % |
| 6 | nimbus-jose-jwt | 422450 | 38.8 % | 45.3 % |
| 7 | jjwt | 222377 | 20.4 % | 23.8 % |
| 8 | jose4j | 178596 | 16.4 % | 19.1 % |
| | _baseline (JCA)_ | _2400547_ | _220.3 %_ | _257.2 %_ |

### HS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 915132 | 100.0 % | 100.0 % |
| 2 | fusionauth-jwt | 710477 | 77.6 % | 77.6 % |
| 3 | vertx-auth-jwt | 670971 | 73.3 % | 73.3 % |
| 4 | auth0-java-jwt | 659895 | 72.1 % | 72.1 % |
| 5 | latte-jwt-jackson | 503100 | 55.0 % | 55.0 % |
| 6 | nimbus-jose-jwt | 241553 | 26.4 % | 26.4 % |
| 7 | jjwt | 155819 | 17.0 % | 17.0 % |
| 8 | jose4j | 145477 | 15.9 % | 15.9 % |
| | _baseline (JCA)_ | _1321779_ | _144.4 %_ | _144.4 %_ |

### RS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1641 | 100.0 % | 100.0 % |
| 2 | auth0-java-jwt | 1599 | 97.4 % | 97.4 % |
| 3 | vertx-auth-jwt | 1598 | 97.3 % | 97.3 % |
| 4 | latte-jwt-jackson | 1569 | 95.6 % | 95.6 % |
| 5 | nimbus-jose-jwt | 1555 | 94.8 % | 94.8 % |
| 6 | jjwt | 1522 | 92.7 % | 92.7 % |
| 7 | jose4j | 1519 | 92.6 % | 92.6 % |
| 8 | fusionauth-jwt | 1471 | 89.6 % | 89.6 % |
| | _baseline (JCA)_ | _1625_ | _99.0 %_ | _99.0 %_ |

### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 40150 | 100.0 % | 100.0 % |
| 2 | vertx-auth-jwt | 40075 | 99.8 % | 99.8 % |
| 3 | auth0-java-jwt | 39413 | 98.2 % | 98.2 % |
| 4 | latte-jwt-jackson | 38863 | 96.8 % | 96.8 % |
| 5 | fusionauth-jwt | 38439 | 95.7 % | 95.7 % |
| 6 | nimbus-jose-jwt | 34345 | 85.5 % | 85.5 % |
| 7 | jose4j | 30934 | 77.0 % | 77.0 % |
| 8 | jjwt | 29915 | 74.5 % | 74.5 % |
| | _baseline (JCA)_ | _40198_ | _100.1 %_ | _100.1 %_ |

### ES256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 11093 | 100.0 % | 100.7 % |
| 2 | latte-jwt | 11013 | 99.3 % | 100.0 % |
| 3 | nimbus-jose-jwt | 10584 | 95.4 % | 96.1 % |
| 4 | auth0-java-jwt | 10441 | 94.1 % | 94.8 % |
| 5 | fusionauth-jwt | 10065 | 90.7 % | 91.4 % |
| 6 | latte-jwt-jackson | 9830 | 88.6 % | 89.3 % |
| 7 | jose4j | 9711 | 87.5 % | 88.2 % |
| 8 | jjwt | 9517 | 85.8 % | 86.4 % |
| | _baseline (JCA)_ | _11118_ | _100.2 %_ | _101.0 %_ |

### ES256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 3350 | 100.0 % | 100.6 % |
| 2 | latte-jwt | 3329 | 99.4 % | 100.0 % |
| 3 | nimbus-jose-jwt | 3183 | 95.0 % | 95.6 % |
| 4 | auth0-java-jwt | 3104 | 92.7 % | 93.2 % |
| 5 | jose4j | 3034 | 90.6 % | 91.1 % |
| 6 | fusionauth-jwt | 3027 | 90.4 % | 90.9 % |
| 7 | jjwt | 2914 | 87.0 % | 87.5 % |
| 8 | latte-jwt-jackson | 2908 | 86.8 % | 87.3 % |
| | _baseline (JCA)_ | _3330_ | _99.4 %_ | _100.0 %_ |

## Supporting operations

### Unsafe decode — claims only (base64 + JSON parse of payload, no signature verification, no header parse)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 2301329 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 1690892 | 73.5 % | 73.5 % |
| 3 | fusionauth-jwt | 1256951 | 54.6 % | 54.6 % |
| 4 | nimbus-jose-jwt | 264113 | 11.5 % | 11.5 % |
| | _baseline (JCA)_ | _10307348_ | _447.9 %_ | _447.9 %_ |

### Unsafe decode — full (header + claims, no signature verification)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | nimbus-jose-jwt | 1550467 | 100.0 % | 129.4 % |
| 2 | latte-jwt | 1198383 | 77.3 % | 100.0 % |
| 3 | auth0-java-jwt | 1057208 | 68.2 % | 88.2 % |
| 4 | latte-jwt-jackson | 1015506 | 65.5 % | 84.7 % |
| 5 | jose4j | 159891 | 10.3 % | 13.3 % |
| | _baseline (JCA)_ | _8714002_ | _562.0 %_ | _727.1 %_ |

## Run conditions

```json
{
  "uname": "Darwin Mac.localdomain 24.6.0 Darwin Kernel Version 24.6.0: Wed Nov  5 21:34:00 PST 2025; root:xnu-11417.140.69.705.2~1/RELEASE_ARM64_T8132 arm64\n",
  "hardware": "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac16,13\n      Model Number: Z1DG000FZLL/A\n      Chip: Apple M4\n      Total Number of Cores: 10 (4 performance and 6 efficiency)\n      Memory: 24 GB\n      System Firmware Version: 13822.61.10\n      OS Loader Version: 11881.140.96\n      Serial Number (system): M09PFPW9V2\n      Hardware UUID: 16709DC3-9DCC-545C-AEA0-380D76082CD4\n      Provisioning UDID: 00008132-000A103C02F8801C\n\n",
  "thermal": "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
  "java": "    java.version = 25.0.2\n    java.version.date = 2026-01-20\n    java.vm.compressedOopsMode = Zero based\n    java.vm.info = mixed mode, sharing\n    java.vm.name = OpenJDK 64-Bit Server VM\n    java.vm.specification.name = Java Virtual Machine Specification\n    java.vm.specification.vendor = Oracle Corporation\n    java.vm.specification.version = 25\n    java.vm.vendor = Eclipse Adoptium\n    java.vm.version = 25.0.2+10-LTS\n    os.arch = aarch64\n    os.name = Mac OS X\n    os.version = 15.7.3\n    sun.arch.data.model = 64\n",
  "jmh_args": "-wi 2 -w 5s -i 3 -r 10s -f 3 -t 1 -rf json",
  "captured_at": "2026-05-01T05:46:07Z"
}
```

<!-- BENCHMARKS:END -->

