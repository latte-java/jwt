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
| 1 | vertx-auth-jwt | 299054 |
| 2 | fusionauth-jwt | 275825 |
| 3 | auth0-java-jwt | 262012 |
| 4 | latte-jwt | 187460 |
| 5 | nimbus-jose-jwt | 103278 |
| 6 | jjwt | 73516 |
| 7 | jose4j | 67928 |
| | _baseline (JCA)_ | _472459_ |

## Throughput by algorithm (ops/sec, higher is better)

### HS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 1302246 | 100.0 % | 134.8 % |
| 2 | fusionauth-jwt | 986380 | 75.7 % | 102.1 % |
| 3 | latte-jwt | 966262 | 74.2 % | 100.0 % |
| 4 | auth0-java-jwt | 919806 | 70.6 % | 95.2 % |
| 5 | nimbus-jose-jwt | 500327 | 38.4 % | 51.8 % |
| 6 | jjwt | 261479 | 20.1 % | 27.1 % |
| 7 | jose4j | 198785 | 15.3 % | 20.6 % |
| | _baseline (JCA)_ | _2367512_ | _181.8 %_ | _245.0 %_ |

### HS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | vertx-auth-jwt | 854035 | 100.0 % | 164.2 % |
| 2 | fusionauth-jwt | 783457 | 91.7 % | 150.7 % |
| 3 | auth0-java-jwt | 741400 | 86.8 % | 142.6 % |
| 4 | latte-jwt | 519965 | 60.9 % | 100.0 % |
| 5 | nimbus-jose-jwt | 270230 | 31.6 % | 52.0 % |
| 6 | jjwt | 183518 | 21.5 % | 35.3 % |
| 7 | jose4j | 166645 | 19.5 % | 32.0 % |
| | _baseline (JCA)_ | _1371543_ | _160.6 %_ | _263.8 %_ |

### RS256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 1708 | 100.0 % | 100.3 % |
| 2 | latte-jwt | 1703 | 99.7 % | 100.0 % |
| 3 | jose4j | 1700 | 99.5 % | 99.8 % |
| 4 | jjwt | 1694 | 99.2 % | 99.5 % |
| 5 | nimbus-jose-jwt | 1691 | 99.0 % | 99.3 % |
| 6 | fusionauth-jwt | 1689 | 98.9 % | 99.2 % |
| 7 | vertx-auth-jwt | 1649 | 96.5 % | 96.8 % |
| | _baseline (JCA)_ | _1685_ | _98.6 %_ | _99.0 %_ |

### RS256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 41242 | 100.0 % | 105.8 % |
| 2 | fusionauth-jwt | 40712 | 98.7 % | 104.5 % |
| 3 | vertx-auth-jwt | 39717 | 96.3 % | 101.9 % |
| 4 | latte-jwt | 38969 | 94.5 % | 100.0 % |
| 5 | nimbus-jose-jwt | 36182 | 87.7 % | 92.8 % |
| 6 | jose4j | 33741 | 81.8 % | 86.6 % |
| 7 | jjwt | 33660 | 81.6 % | 86.4 % |
| | _baseline (JCA)_ | _42403_ | _102.8 %_ | _108.8 %_ |

### ES256 — encode

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | auth0-java-jwt | 11445 | 100.0 % | 100.9 % |
| 2 | latte-jwt | 11338 | 99.1 % | 100.0 % |
| 3 | vertx-auth-jwt | 11301 | 98.7 % | 99.7 % |
| 4 | nimbus-jose-jwt | 11204 | 97.9 % | 98.8 % |
| 5 | fusionauth-jwt | 10954 | 95.7 % | 96.6 % |
| 6 | jjwt | 10841 | 94.7 % | 95.6 % |
| 7 | jose4j | 10735 | 93.8 % | 94.7 % |
| | _baseline (JCA)_ | _11245_ | _98.3 %_ | _99.2 %_ |

### ES256 — decode + verify + validate

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | latte-jwt | 3445 | 100.0 % | 100.0 % |
| 2 | nimbus-jose-jwt | 3422 | 99.3 % | 99.3 % |
| 3 | vertx-auth-jwt | 3408 | 98.9 % | 98.9 % |
| 4 | jose4j | 3397 | 98.6 % | 98.6 % |
| 5 | auth0-java-jwt | 3393 | 98.5 % | 98.5 % |
| 6 | jjwt | 3370 | 97.8 % | 97.8 % |
| 7 | fusionauth-jwt | 3306 | 96.0 % | 96.0 % |
| | _baseline (JCA)_ | _3429_ | _99.5 %_ | _99.5 %_ |

## Supporting operations

### Unsafe decode (no signature verification)

| # | Library | ops/sec | vs leader | vs latte-jwt |
|--:|---------|--------:|----------:|-------------:|
| 1 | nimbus-jose-jwt | 1890558 | 100.0 % | 274.6 % |
| 2 | fusionauth-jwt | 1854461 | 98.1 % | 269.4 % |
| 3 | auth0-java-jwt | 1269434 | 67.1 % | 184.4 % |
| 4 | latte-jwt | 688386 | 36.4 % | 100.0 % |
| 5 | jose4j | 178689 | 9.5 % | 26.0 % |
| | _baseline (JCA)_ | _10777503_ | _570.1 %_ | _1565.6 %_ |

## Run conditions

```json
{
  "uname": "Darwin Mac.localdomain 24.6.0 Darwin Kernel Version 24.6.0: Wed Nov  5 21:34:00 PST 2025; root:xnu-11417.140.69.705.2~1/RELEASE_ARM64_T8132 arm64\n",
  "hardware": "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac16,13\n      Model Number: Z1DG000FZLL/A\n      Chip: Apple M4\n      Total Number of Cores: 10 (4 performance and 6 efficiency)\n      Memory: 24 GB\n      System Firmware Version: 13822.61.10\n      OS Loader Version: 11881.140.96\n      Serial Number (system): M09PFPW9V2\n      Hardware UUID: 16709DC3-9DCC-545C-AEA0-380D76082CD4\n      Provisioning UDID: 00008132-000A103C02F8801C\n\n",
  "thermal": "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
  "java": "    java.version = 25.0.2\n    java.version.date = 2026-01-20\n    java.vm.compressedOopsMode = Zero based\n    java.vm.info = mixed mode, sharing\n    java.vm.name = OpenJDK 64-Bit Server VM\n    java.vm.specification.name = Java Virtual Machine Specification\n    java.vm.specification.vendor = Oracle Corporation\n    java.vm.specification.version = 25\n    java.vm.vendor = Eclipse Adoptium\n    java.vm.version = 25.0.2+10-LTS\n    os.arch = aarch64\n    os.name = Mac OS X\n    os.version = 15.7.3\n    sun.arch.data.model = 64\n",
  "jmh_args": "-wi 2 -w 2s -i 3 -r 2s -f 1 -t 1 -rf json",
  "captured_at": "2026-04-26T23:51:13Z"
}
```

<!-- BENCHMARKS:END -->

