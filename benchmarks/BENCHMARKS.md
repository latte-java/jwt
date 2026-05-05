# JWT Library Benchmarks

This is the auto-generated benchmark report. The methodology is documented in
[the benchmark framework spec](../specs/benchmark-framework.md). To run benchmarks yourself,
see [`benchmarks/README.md`](README.md).

The numbers below come from a single run on a single machine. Relative ranking between libraries
is what matters; absolute ops/sec depend on hardware and JVM. Always re-run on your own
hardware before quoting absolute numbers.

If a Java JWT library is missing from this comparison, open an issue and we'll add it. The
only restriction is that this suite covers Java libraries only — JVM-language ports (Kotlin,
Scala, etc.) that wrap a Java library are already represented by their underlying Java
dependency, and non-JVM libraries are out of scope.

<!-- BENCHMARKS:START -->

## Overall leaderboard — decode-verify-validate (the headline op)

Mean ops/sec across HS256, RS256, ES256 decode-verify-validate (Throughput mode):

| # | Library | mean ops/sec |
|--:|---------|-------------:|
| 1 | latte-jwt | 385,645 |
| 2 | fusionauth-jwt | 231,151 |
| 3 | latte-jwt-jackson | 226,977 |
| 4 | vertx-auth-jwt | 211,514 |
| 5 | auth0-java-jwt | 201,997 |
| 6 | nimbus-jose-jwt | 83,941 |
| 7 | jjwt | 56,990 |
| 8 | jose4j | 48,637 |
| | _baseline (JCA)_ | _470,864_ |

## Throughput by algorithm (ops/sec, higher is better)

### HS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt-jackson | 1,250,322 | 100.0 % | 110.1 % |
| 2 | latte-jwt | 1,135,251 | 90.8 % | 100.0 % |
| 3 | vertx-auth-jwt | 907,227 | 72.6 % | 79.9 % |
| 4 | fusionauth-jwt | 735,859 | 58.9 % | 64.8 % |
| 5 | auth0-java-jwt | 557,034 | 44.6 % | 49.1 % |
| 6 | nimbus-jose-jwt | 393,453 | 31.5 % | 34.7 % |
| 7 | jjwt | 199,358 | 15.9 % | 17.6 % |
| 8 | jose4j | 145,057 | 11.6 % | 12.8 % |
| | _baseline (JCA)_ | _2,421,119_ | _193.6 %_ | _213.3 %_ |

### HS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1,111,626 | 100.0 % | 100.0 % |
| 2 | fusionauth-jwt | 653,153 | 58.8 % | 58.8 % |
| 3 | latte-jwt-jackson | 636,603 | 57.3 % | 57.3 % |
| 4 | vertx-auth-jwt | 594,880 | 53.5 % | 53.5 % |
| 5 | auth0-java-jwt | 574,234 | 51.7 % | 51.7 % |
| 6 | nimbus-jose-jwt | 216,553 | 19.5 % | 19.5 % |
| 7 | jjwt | 140,123 | 12.6 % | 12.6 % |
| 8 | jose4j | 112,900 | 10.2 % | 10.2 % |
| | _baseline (JCA)_ | _1,366,885_ | _123.0 %_ | _123.0 %_ |

### RS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1,712 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 1,698 | 99.2 % | 99.2 % |
| 3 | jose4j | 1,525 | 89.1 % | 89.1 % |
| 4 | fusionauth-jwt | 1,525 | 89.1 % | 89.1 % |
| 5 | nimbus-jose-jwt | 1,502 | 87.7 % | 87.7 % |
| 6 | jjwt | 1,492 | 87.2 % | 87.2 % |
| 7 | auth0-java-jwt | 1,465 | 85.6 % | 85.6 % |
| 8 | vertx-auth-jwt | 1,359 | 79.4 % | 79.4 % |
| | _baseline (JCA)_ | _1,712_ | _100.0 %_ | _100.0 %_ |

### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 41,839 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 40,864 | 97.7 % | 97.7 % |
| 3 | fusionauth-jwt | 37,409 | 89.4 % | 89.4 % |
| 4 | vertx-auth-jwt | 37,165 | 88.8 % | 88.8 % |
| 5 | nimbus-jose-jwt | 32,426 | 77.5 % | 77.5 % |
| 6 | jose4j | 30,326 | 72.5 % | 72.5 % |
| 7 | auth0-java-jwt | 28,860 | 69.0 % | 69.0 % |
| 8 | jjwt | 28,044 | 67.0 % | 67.0 % |
| | _baseline (JCA)_ | _42,321_ | _101.2 %_ | _101.2 %_ |

### ES256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 11,447 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 11,424 | 99.8 % | 99.8 % |
| 3 | auth0-java-jwt | 9,570 | 83.6 % | 83.6 % |
| 4 | fusionauth-jwt | 9,511 | 83.1 % | 83.1 % |
| 5 | nimbus-jose-jwt | 9,401 | 82.1 % | 82.1 % |
| 6 | vertx-auth-jwt | 8,792 | 76.8 % | 76.8 % |
| 7 | jjwt | 8,767 | 76.6 % | 76.6 % |
| 8 | jose4j | 8,130 | 71.0 % | 71.0 % |
| | _baseline (JCA)_ | _11,294_ | _98.7 %_ | _98.7 %_ |

### ES256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 3,469 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 3,464 | 99.8 % | 99.8 % |
| 3 | auth0-java-jwt | 2,897 | 83.5 % | 83.5 % |
| 4 | fusionauth-jwt | 2,891 | 83.3 % | 83.3 % |
| 5 | nimbus-jose-jwt | 2,844 | 82.0 % | 82.0 % |
| 6 | jjwt | 2,803 | 80.8 % | 80.8 % |
| 7 | jose4j | 2,684 | 77.4 % | 77.4 % |
| 8 | vertx-auth-jwt | 2,496 | 71.9 % | 71.9 % |
| | _baseline (JCA)_ | _3,388_ | _97.7 %_ | _97.7 %_ |

## Supporting operations

### Unsafe decode — claims only (base64 + JSON parse of payload, no signature verification, no header parse)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 2,407,744 | 100.0 % | 100.0 % |
| 2 | latte-jwt-jackson | 1,859,926 | 77.2 % | 77.2 % |
| 3 | fusionauth-jwt | 1,459,806 | 60.6 % | 60.6 % |
| 4 | nimbus-jose-jwt | 259,438 | 10.8 % | 10.8 % |
| | _baseline (JCA)_ | _10,822,244_ | _449.5 %_ | _449.5 %_ |

### Unsafe decode — full (header + claims, no signature verification)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 1,584,619 | 100.0 % | 100.0 % |
| 2 | nimbus-jose-jwt | 1,364,834 | 86.1 % | 86.1 % |
| 3 | latte-jwt-jackson | 1,079,807 | 68.1 % | 68.1 % |
| 4 | auth0-java-jwt | 926,159 | 58.4 % | 58.4 % |
| 5 | jose4j | 110,838 | 7.0 % | 7.0 % |
| | _baseline (JCA)_ | _9,307,242_ | _587.3 %_ | _587.3 %_ |

## Run conditions

```json
{
  "uname": "Darwin Mac.localdomain 24.6.0 Darwin Kernel Version 24.6.0: Wed Nov  5 21:34:00 PST 2025; root:xnu-11417.140.69.705.2~1/RELEASE_ARM64_T8132 arm64\n",
  "hardware": "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac16,13\n      Model Number: Z1DG000FZLL/A\n      Chip: Apple M4\n      Total Number of Cores: 10 (4 performance and 6 efficiency)\n      Memory: 24 GB\n      System Firmware Version: 13822.61.10\n      OS Loader Version: 11881.140.96\n      Serial Number (system): M09PFPW9V2\n      Hardware UUID: 16709DC3-9DCC-545C-AEA0-380D76082CD4\n      Provisioning UDID: 00008132-000A103C02F8801C\n      Activation Lock Status: Enabled\n\n",
  "thermal": "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
  "java": "    java.version = 25.0.2\n    java.version.date = 2026-01-20\n    java.vm.compressedOopsMode = Zero based\n    java.vm.info = mixed mode, sharing\n    java.vm.name = OpenJDK 64-Bit Server VM\n    java.vm.specification.name = Java Virtual Machine Specification\n    java.vm.specification.vendor = Oracle Corporation\n    java.vm.specification.version = 25\n    java.vm.vendor = Eclipse Adoptium\n    java.vm.version = 25.0.2+10-LTS\n    os.arch = aarch64\n    os.name = Mac OS X\n    os.version = 15.7.3\n    sun.arch.data.model = 64\n",
  "jmh_args": "-wi 2 -w 5s -i 3 -r 10s -f 3 -t 1 -rf json",
  "captured_at": "2026-05-02T12:59:13Z"
}
```

<!-- BENCHMARKS:END -->

