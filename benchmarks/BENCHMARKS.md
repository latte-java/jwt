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
| 1 | latte-jwt | 281278 |
| 2 | fusionauth-jwt | 258512 |
| 3 | vertx-auth-jwt | 231308 |
| 4 | auth0-java-jwt | 206954 |
| 5 | latte-jwt-jackson | 159389 |
| 6 | nimbus-jose-jwt | 81057 |
| 7 | jjwt | 59043 |
| 8 | jose4j | 40788 |
| | _baseline (JCA)_ | _417870_ |

## Throughput by algorithm (ops/sec, higher is better)

### HS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 1091414 | 100.0 % | 136.2 % |
| 2 | fusionauth-jwt | 836771 | 76.7 % | 104.4 % |
| 3 | latte-jwt-jackson | 810414 | 74.3 % | 101.1 % |
| 4 | latte-jwt | 801562 | 73.4 % | 100.0 % |
| 5 | auth0-java-jwt | 657653 | 60.3 % | 82.0 % |
| 6 | nimbus-jose-jwt | 361829 | 33.2 % | 45.1 % |
| 7 | jjwt | 204213 | 18.7 % | 25.5 % |
| 8 | jose4j | 152172 | 13.9 % | 19.0 % |
| | _baseline (JCA)_ | _2333550_ | _213.8 %_ | _291.1 %_ |

### HS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 802135 | 100.0 % | 100.0 % |
| 2 | fusionauth-jwt | 732842 | 91.4 % | 91.4 % |
| 3 | vertx-auth-jwt | 652526 | 81.3 % | 81.3 % |
| 4 | auth0-java-jwt | 584536 | 72.9 % | 72.9 % |
| 5 | latte-jwt-jackson | 440187 | 54.9 % | 54.9 % |
| 6 | nimbus-jose-jwt | 211859 | 26.4 % | 26.4 % |
| 7 | jjwt | 145804 | 18.2 % | 18.2 % |
| 8 | jose4j | 95152 | 11.9 % | 11.9 % |
| | _baseline (JCA)_ | _1210418_ | _150.9 %_ | _150.9 %_ |

### RS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 1570 | 100.0 % | 104.3 % |
| 2 | fusionauth-jwt | 1540 | 98.1 % | 102.3 % |
| 3 | latte-jwt | 1506 | 95.9 % | 100.0 % |
| 4 | latte-jwt-jackson | 1360 | 86.6 % | 90.3 % |
| 5 | auth0-java-jwt | 1346 | 85.7 % | 89.4 % |
| 6 | jose4j | 1332 | 84.8 % | 88.4 % |
| 7 | nimbus-jose-jwt | 1278 | 81.4 % | 84.9 % |
| 8 | jjwt | 1105 | 70.4 % | 73.4 % |
| | _baseline (JCA)_ | _1588_ | _101.1 %_ | _105.5 %_ |

### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | fusionauth-jwt | 39745 | 100.0 % | 101.9 % |
| 2 | latte-jwt | 38995 | 98.1 % | 100.0 % |
| 3 | vertx-auth-jwt | 38592 | 97.1 % | 99.0 % |
| 4 | latte-jwt-jackson | 35398 | 89.1 % | 90.8 % |
| 5 | auth0-java-jwt | 33643 | 84.6 % | 86.3 % |
| 6 | nimbus-jose-jwt | 28858 | 72.6 % | 74.0 % |
| 7 | jjwt | 28661 | 72.1 % | 73.5 % |
| 8 | jose4j | 24441 | 61.5 % | 62.7 % |
| | _baseline (JCA)_ | _39944_ | _100.5 %_ | _102.4 %_ |

### ES256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | fusionauth-jwt | 9360 | 100.0 % | 102.2 % |
| 2 | auth0-java-jwt | 9267 | 99.0 % | 101.2 % |
| 3 | latte-jwt | 9159 | 97.9 % | 100.0 % |
| 4 | latte-jwt-jackson | 8934 | 95.4 % | 97.5 % |
| 5 | jose4j | 8625 | 92.2 % | 94.2 % |
| 6 | nimbus-jose-jwt | 8379 | 89.5 % | 91.5 % |
| 7 | vertx-auth-jwt | 8272 | 88.4 % | 90.3 % |
| 8 | jjwt | 7993 | 85.4 % | 87.3 % |
| | _baseline (JCA)_ | _10485_ | _112.0 %_ | _114.5 %_ |

### ES256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | fusionauth-jwt | 2950 | 100.0 % | 109.1 % |
| 2 | vertx-auth-jwt | 2806 | 95.1 % | 103.7 % |
| 3 | jose4j | 2771 | 93.9 % | 102.5 % |
| 4 | latte-jwt | 2704 | 91.7 % | 100.0 % |
| 5 | auth0-java-jwt | 2684 | 91.0 % | 99.2 % |
| 6 | jjwt | 2665 | 90.3 % | 98.5 % |
| 7 | latte-jwt-jackson | 2581 | 87.5 % | 95.4 % |
| 8 | nimbus-jose-jwt | 2454 | 83.2 % | 90.7 % |
| | _baseline (JCA)_ | _3247_ | _110.1 %_ | _120.1 %_ |

## Supporting operations

### Unsafe decode — claims only (base64 + JSON parse of payload, no signature verification, no header parse)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1963677 | 100.0 % | 100.0 % |
| 2 | fusionauth-jwt | 1648114 | 83.9 % | 83.9 % |
| 3 | latte-jwt-jackson | 1565578 | 79.7 % | 79.7 % |
| 4 | nimbus-jose-jwt | 216996 | 11.1 % | 11.1 % |
| | _baseline (JCA)_ | _9275066_ | _472.3 %_ | _472.3 %_ |

### Unsafe decode — full (header + claims, no signature verification)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | nimbus-jose-jwt | 1349064 | 100.0 % | 116.7 % |
| 2 | latte-jwt | 1156183 | 85.7 % | 100.0 % |
| 3 | auth0-java-jwt | 874320 | 64.8 % | 75.6 % |
| 4 | latte-jwt-jackson | 863599 | 64.0 % | 74.7 % |
| 5 | jose4j | 131333 | 9.7 % | 11.4 % |
| | _baseline (JCA)_ | _7323401_ | _542.9 %_ | _633.4 %_ |

## Run conditions

```json
{
  "uname": "Darwin Mac.localdomain 24.6.0 Darwin Kernel Version 24.6.0: Wed Nov  5 21:34:00 PST 2025; root:xnu-11417.140.69.705.2~1/RELEASE_ARM64_T8132 arm64\n",
  "hardware": "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac16,13\n      Model Number: Z1DG000FZLL/A\n      Chip: Apple M4\n      Total Number of Cores: 10 (4 performance and 6 efficiency)\n      Memory: 24 GB\n      System Firmware Version: 13822.61.10\n      OS Loader Version: 11881.140.96\n      Serial Number (system): M09PFPW9V2\n      Hardware UUID: 16709DC3-9DCC-545C-AEA0-380D76082CD4\n      Provisioning UDID: 00008132-000A103C02F8801C\n\n",
  "thermal": "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
  "java": "    java.version = 25.0.2\n    java.version.date = 2026-01-20\n    java.vm.compressedOopsMode = Zero based\n    java.vm.info = mixed mode, sharing\n    java.vm.name = OpenJDK 64-Bit Server VM\n    java.vm.specification.name = Java Virtual Machine Specification\n    java.vm.specification.vendor = Oracle Corporation\n    java.vm.specification.version = 25\n    java.vm.vendor = Eclipse Adoptium\n    java.vm.version = 25.0.2+10-LTS\n    os.arch = aarch64\n    os.name = Mac OS X\n    os.version = 15.7.3\n    sun.arch.data.model = 64\n",
  "jmh_args": "-wi 2 -w 5s -i 3 -r 10s -f 1 -t 1 -rf json",
  "captured_at": "2026-05-01T00:31:48Z"
}
```

<!-- BENCHMARKS:END -->

