#!/usr/bin/env bash
# Copyright (c) 2026, The Latte Project. License: MIT.
set -euo pipefail

# ── locate repo + benchmarks dir
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
BENCH_DIR="${SCRIPT_DIR}"
RESULTS_DIR="${BENCH_DIR}/results"
FIXTURES_DIR="${BENCH_DIR}/fixtures"
mkdir -p "${RESULTS_DIR}"

# ── defaults (override via CLI)
LIBRARIES=""
ALGORITHMS=""
OPERATIONS=""
LABEL=""
DURATION=""
QUICK=0
NO_BUILD=0
DO_UPDATE=0

usage() {
  cat <<'EOF'
Usage: run-benchmarks.sh [options]

  --libraries  <list>   Subset of libraries (comma-separated)
  --algorithms <list>   Subset of algorithms (comma-separated)
  --operations <list>   Subset of operations (comma-separated)
  --label      <name>   Appended to results filename
  --duration   <time>   Shortcut: sets warmup-time AND measurement-time (e.g. 5s)
  --quick               Preset: 5s warmup, 10s measurement, 1 fork
  --no-build            Skip latte build, reuse existing JARs
  --update              Run update-benchmarks.sh after the run completes
  -h, --help            This message
EOF
}

capture_run_conditions() {
  local out="$1"
  {
    echo '{'
    printf '  "uname": %s,\n' "$(uname -a | jq -Rs .)"
    if [[ "$(uname -s)" == "Darwin" ]]; then
      printf '  "hardware": %s,\n' "$(system_profiler SPHardwareDataType 2>/dev/null | jq -Rs .)"
      printf '  "thermal":  %s,\n' "$(pmset -g therm 2>/dev/null | jq -Rs .)"
    else
      printf '  "hardware": %s,\n' "$(lscpu 2>/dev/null | jq -Rs .)"
      if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        printf '  "cpufreq_governor": %s,\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor | jq -Rs .)"
      fi
    fi
    printf '  "java": %s,\n' "$(java -XshowSettings:properties -version 2>&1 | grep -E "^[[:space:]]+(java\.version|os\.|sun\.arch|java\.vm)" | jq -Rs .)"
    printf '  "jmh_args": "%s",\n' "${JMH_ARGS[*]}"
    printf '  "captured_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo '}'
  } > "${out}"
}

# ── arg parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --libraries)  LIBRARIES="$2";  shift 2 ;;
    --algorithms) ALGORITHMS="$2"; shift 2 ;;
    --operations) OPERATIONS="$2"; shift 2 ;;
    --label)      LABEL="$2";      shift 2 ;;
    --duration)   DURATION="$2";   shift 2 ;;
    --quick)      QUICK=1;         shift   ;;
    --no-build)   NO_BUILD=1;      shift   ;;
    --update)     DO_UPDATE=1;     shift   ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# ── load YAML (parse a few keys via grep/sed)
yaml_libraries() { sed -n '/^libraries:/,/^[a-zA-Z]/p' "${BENCH_DIR}/benchmarks.yaml" | sed -n 's/^  - //p'; }
yaml_jmh()       { grep -E "^[[:space:]]+$1:" "${BENCH_DIR}/benchmarks.yaml" | head -1 | awk '{print $2}'; }

DEFAULT_LIBS="$(yaml_libraries | paste -sd ',' -)"
LIBS_TO_RUN="${LIBRARIES:-${DEFAULT_LIBS}}"
WARMUP_ITERS="$(yaml_jmh warmup-iterations)"
WARMUP_TIME="$(yaml_jmh warmup-time)"
MEASURE_ITERS="$(yaml_jmh measurement-iterations)"
MEASURE_TIME="$(yaml_jmh measurement-time)"
FORKS="$(yaml_jmh forks)"
THREADS="$(yaml_jmh threads)"

if (( QUICK == 1 )); then
  WARMUP_TIME="5s"; MEASURE_TIME="10s"; FORKS=1
fi
if [[ -n "${DURATION}" ]]; then
  WARMUP_TIME="${DURATION}"; MEASURE_TIME="${DURATION}"
fi

# ── sanity check
echo "→ sanity check"
command -v latte >/dev/null || { echo "latte not on PATH" >&2; exit 1; }
java -version 2>&1 | head -1 | grep -qE 'version "(2[1-9]|[3-9][0-9])' || {
  echo "Java 21+ required" >&2
  java -version >&2
  exit 1
}
[[ -d "${FIXTURES_DIR}" ]] || { echo "fixtures missing: ${FIXTURES_DIR}" >&2; exit 1; }
[[ -f "${FIXTURES_DIR}/claims.json" ]] || { echo "fixtures incomplete (no claims.json)" >&2; exit 1; }
IFS=',' read -ra LIBS_ARRAY <<< "${LIBS_TO_RUN}"
for lib in "${LIBS_ARRAY[@]}"; do
  [[ -d "${BENCH_DIR}/${lib}" ]] || { echo "library dir missing: ${lib}" >&2; exit 1; }
done
echo "  ok"

# ── build
if (( NO_BUILD == 0 )); then
  echo "→ build"
  for lib in "${LIBS_ARRAY[@]}"; do
    echo "  building ${lib}…"
    ( cd "${BENCH_DIR}/${lib}" && latte build ) >"${RESULTS_DIR}/.${lib}.build.log" 2>&1 || {
      echo "build failed for ${lib} — see ${RESULTS_DIR}/.${lib}.build.log" >&2
      exit 1
    }
  done
fi

# ── classpath assembly
#
# Approach: two-tier cache.
#
# Latte publishes integration artifacts to ~/.cache/latte/ with the layout:
#   ~/.cache/latte/<group-dots-as-slashes>/<artifact>/<version>/<artifact>-<version>.jar
# Example:
#   ~/.cache/latte/org/lattejava/jwt/benchmarks/harness/0.1.0-{integration}/harness-0.1.0-{integration}.jar
#
# JMH (jmh-core, jopt-simple, commons-math3) is declared in each adapter's project.latte but
# Latte resolves it from Maven Central into ~/.m2/repository/ (Maven local cache) because the
# JMH group (org.openjdk.jmh) is not managed by Latte. So JMH transitives are sourced from:
#   ~/.m2/repository/org/openjdk/jmh/jmh-core/1.37/jmh-core-1.37.jar
#   ~/.m2/repository/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar
#   ~/.m2/repository/org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar
#
# The per-library JAR is always in <lib>/build/jars/ and is the only artifact NOT in the cache.

LATTE_CACHE="${HOME}/.cache/latte"
M2_REPO="${HOME}/.m2/repository"
JMH_VERSION="1.37"

# Shared JARs required by every adapter.
HARNESS_JAR="${LATTE_CACHE}/org/lattejava/jwt/benchmarks/harness/0.1.0-{integration}/harness-0.1.0-{integration}.jar"
JMH_CORE_JAR="${M2_REPO}/org/openjdk/jmh/jmh-core/${JMH_VERSION}/jmh-core-${JMH_VERSION}.jar"
JOPT_JAR="${M2_REPO}/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar"
MATH3_JAR="${M2_REPO}/org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar"

# JAR for the latte-jwt library itself (only needed by the latte-jwt adapter).
LATTE_JWT_JAR="${LATTE_CACHE}/org/lattejava/jwt/0.1.0-{integration}/jwt-0.1.0-{integration}.jar"

# JARs for the auth0/java-jwt adapter and its Jackson 2.15.4 transitives.
# auth0/java-jwt is a Maven Central artifact; Latte resolves it into ~/.m2/repository.
AUTH0_JWT_JAR="${M2_REPO}/com/auth0/java-jwt/4.5.0/java-jwt-4.5.0.jar"
JACKSON_DATABIND_JAR="${M2_REPO}/com/fasterxml/jackson/core/jackson-databind/2.15.4/jackson-databind-2.15.4.jar"
JACKSON_CORE_JAR="${M2_REPO}/com/fasterxml/jackson/core/jackson-core/2.15.4/jackson-core-2.15.4.jar"
JACKSON_ANNOTATIONS_JAR="${M2_REPO}/com/fasterxml/jackson/core/jackson-annotations/2.15.4/jackson-annotations-2.15.4.jar"

# JARs for the jose4j adapter and its SLF4J API transitive.
# jose4j is a Maven Central artifact; Latte resolves it into ~/.m2/repository.
JOSE4J_JAR="${M2_REPO}/org/bitbucket/b_c/jose4j/0.9.6/jose4j-0.9.6.jar"
SLF4J_API_JAR="${M2_REPO}/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar"

# JAR for the nimbus-jose-jwt adapter.
# nimbus-jose-jwt 10.x uses JDK crypto for standard JWS algorithms (HS256, RS256, ES256);
# all optional compile-scope deps (BouncyCastle, Tink) are not required at runtime here.
NIMBUS_JAR="${M2_REPO}/com/nimbusds/nimbus-jose-jwt/10.3/nimbus-jose-jwt-10.3.jar"

# JAR for the fusionauth-jwt adapter.
# fusionauth-jwt 5.3.3 depends on Jackson 2.15.4 (core, databind, annotations) at runtime;
# those JARs are already present from the auth0-java-jwt adapter declaration above.
FUSIONAUTH_JWT_JAR="${M2_REPO}/io/fusionauth/fusionauth-jwt/5.3.3/fusionauth-jwt-5.3.3.jar"

# JARs for the jjwt adapter.
# jjwt is a multi-jar library: API + impl + jackson binding. jjwt-jackson 0.12.6 depends on
# jackson-databind 2.12.7.1 (four-part version), which Latte maps to 2.12.7 via semanticVersions.
# At runtime we use the 2.15.4 Jackson JARs already present from the auth0 adapter — they are
# backward-compatible with the 2.12.x API surface that jjwt-jackson uses.
JJWT_API_JAR="${M2_REPO}/io/jsonwebtoken/jjwt-api/0.12.6/jjwt-api-0.12.6.jar"
JJWT_IMPL_JAR="${M2_REPO}/io/jsonwebtoken/jjwt-impl/0.12.6/jjwt-impl-0.12.6.jar"
JJWT_JACKSON_JAR="${M2_REPO}/io/jsonwebtoken/jjwt-jackson/0.12.6/jjwt-jackson-0.12.6.jar"

# JARs for the vertx-auth-jwt adapter.
# vertx-auth-jwt 4.5.14 has heavy transitives: vertx-core pulls in a large Netty surface (13 modules)
# plus jackson-core 2.16.1. vertx-auth-jwt itself depends on vertx-auth-common (where JWTOptions,
# PubSecKeyOptions, and User live). vertx-auth-common is declared explicitly in the adapter's
# project.latte so it appears as a direct compile dep and resolves to a separate JAR here.
# jackson-databind is NOT required at runtime — vertx uses JsonObject (its own JSON layer backed
# by jackson-core only). All Netty JARs use the .Final qualifier (mapped to plain semver in
# project.latte via semanticVersions so Latte can resolve them, but on disk they remain .Final).
VERTX_NETTY="4.1.118.Final"
VERTX_AUTH_COMMON_JAR="${M2_REPO}/io/vertx/vertx-auth-common/4.5.14/vertx-auth-common-4.5.14.jar"
VERTX_AUTH_JWT_JAR="${M2_REPO}/io/vertx/vertx-auth-jwt/4.5.14/vertx-auth-jwt-4.5.14.jar"
VERTX_CORE_JAR="${M2_REPO}/io/vertx/vertx-core/4.5.14/vertx-core-4.5.14.jar"
NETTY_BUFFER_JAR="${M2_REPO}/io/netty/netty-buffer/${VERTX_NETTY}/netty-buffer-${VERTX_NETTY}.jar"
NETTY_CODEC_DNS_JAR="${M2_REPO}/io/netty/netty-codec-dns/${VERTX_NETTY}/netty-codec-dns-${VERTX_NETTY}.jar"
NETTY_CODEC_HTTP_JAR="${M2_REPO}/io/netty/netty-codec-http/${VERTX_NETTY}/netty-codec-http-${VERTX_NETTY}.jar"
NETTY_CODEC_HTTP2_JAR="${M2_REPO}/io/netty/netty-codec-http2/${VERTX_NETTY}/netty-codec-http2-${VERTX_NETTY}.jar"
NETTY_CODEC_JAR="${M2_REPO}/io/netty/netty-codec/${VERTX_NETTY}/netty-codec-${VERTX_NETTY}.jar"
NETTY_CODEC_SOCKS_JAR="${M2_REPO}/io/netty/netty-codec-socks/${VERTX_NETTY}/netty-codec-socks-${VERTX_NETTY}.jar"
NETTY_COMMON_JAR="${M2_REPO}/io/netty/netty-common/${VERTX_NETTY}/netty-common-${VERTX_NETTY}.jar"
NETTY_HANDLER_JAR="${M2_REPO}/io/netty/netty-handler/${VERTX_NETTY}/netty-handler-${VERTX_NETTY}.jar"
NETTY_HANDLER_PROXY_JAR="${M2_REPO}/io/netty/netty-handler-proxy/${VERTX_NETTY}/netty-handler-proxy-${VERTX_NETTY}.jar"
NETTY_RESOLVER_DNS_JAR="${M2_REPO}/io/netty/netty-resolver-dns/${VERTX_NETTY}/netty-resolver-dns-${VERTX_NETTY}.jar"
NETTY_RESOLVER_JAR="${M2_REPO}/io/netty/netty-resolver/${VERTX_NETTY}/netty-resolver-${VERTX_NETTY}.jar"
NETTY_TRANSPORT_JAR="${M2_REPO}/io/netty/netty-transport/${VERTX_NETTY}/netty-transport-${VERTX_NETTY}.jar"
NETTY_TRANSPORT_UNIX_JAR="${M2_REPO}/io/netty/netty-transport-native-unix-common/${VERTX_NETTY}/netty-transport-native-unix-common-${VERTX_NETTY}.jar"
VERTX_JACKSON_CORE_JAR="${M2_REPO}/com/fasterxml/jackson/core/jackson-core/2.16.1/jackson-core-2.16.1.jar"

# Return the per-library JAR path. Latte names it <artifact>-<version>.jar inside build/jars/.
# The project name (from project.latte) may differ from the directory name (e.g. latte-jwt dir
# uses artifact "latte-jwt-bench"), so we glob for the primary (non-test, non-src) JAR.
lib_jar_for() {
  local lib="$1"
  local jar
  jar="$(find "${BENCH_DIR}/${lib}/build/jars" -maxdepth 1 -name '*.jar' \
         ! -name '*-test-*' ! -name '*-src*' 2>/dev/null | head -1)"
  if [[ -z "${jar}" ]]; then
    echo "cannot find built JAR for ${lib} under ${BENCH_DIR}/${lib}/build/jars/" >&2
    exit 1
  fi
  echo "${jar}"
}

classpath_for_library() {
  local lib="$1"
  local lib_jar
  lib_jar="$(lib_jar_for "${lib}")"

  local cp="${lib_jar}:${HARNESS_JAR}:${JMH_CORE_JAR}:${JOPT_JAR}:${MATH3_JAR}"

  # Adapters that wrap third-party libraries need those JARs on the classpath.
  case "${lib}" in
    auth0-java-jwt)  cp="${cp}:${AUTH0_JWT_JAR}:${JACKSON_DATABIND_JAR}:${JACKSON_CORE_JAR}:${JACKSON_ANNOTATIONS_JAR}" ;;
    fusionauth-jwt)  cp="${cp}:${FUSIONAUTH_JWT_JAR}:${JACKSON_DATABIND_JAR}:${JACKSON_CORE_JAR}:${JACKSON_ANNOTATIONS_JAR}" ;;
    jjwt)            cp="${cp}:${JJWT_API_JAR}:${JJWT_IMPL_JAR}:${JJWT_JACKSON_JAR}:${JACKSON_DATABIND_JAR}:${JACKSON_CORE_JAR}:${JACKSON_ANNOTATIONS_JAR}" ;;
    jose4j)          cp="${cp}:${JOSE4J_JAR}:${SLF4J_API_JAR}" ;;
    latte-jwt)       cp="${cp}:${LATTE_JWT_JAR}" ;;
    latte-jwt-jackson) cp="${cp}:${LATTE_JWT_JAR}:${JACKSON_DATABIND_JAR}:${JACKSON_CORE_JAR}:${JACKSON_ANNOTATIONS_JAR}" ;;
    nimbus-jose-jwt) cp="${cp}:${NIMBUS_JAR}" ;;
    vertx-auth-jwt)
      cp="${cp}:${VERTX_AUTH_JWT_JAR}:${VERTX_AUTH_COMMON_JAR}:${VERTX_CORE_JAR}"
      cp="${cp}:${NETTY_BUFFER_JAR}:${NETTY_CODEC_DNS_JAR}:${NETTY_CODEC_HTTP_JAR}:${NETTY_CODEC_HTTP2_JAR}"
      cp="${cp}:${NETTY_CODEC_JAR}:${NETTY_CODEC_SOCKS_JAR}:${NETTY_COMMON_JAR}:${NETTY_HANDLER_JAR}"
      cp="${cp}:${NETTY_HANDLER_PROXY_JAR}:${NETTY_RESOLVER_DNS_JAR}:${NETTY_RESOLVER_JAR}"
      cp="${cp}:${NETTY_TRANSPORT_JAR}:${NETTY_TRANSPORT_UNIX_JAR}:${VERTX_JACKSON_CORE_JAR}"
      ;;
  esac

  echo "${cp}"
}

# ── main class mapping
#
# The package suffix was chosen when the adapter was authored. The pattern of stripping dashes
# from the directory name (latte-jwt → lattejwt) works for today's two libraries but does NOT
# generalise — auth0-java-jwt was specified as package suffix "auth0" in the plan, for instance.
# Add a case entry here when each new library adapter is implemented (Tasks 13-19).
main_class_for_library() {
  local lib="$1"
  case "${lib}" in
    auth0-java-jwt)  echo "org.lattejava.jwt.benchmarks.auth0.Main" ;;
    baseline)        echo "org.lattejava.jwt.benchmarks.baseline.Main" ;;
    fusionauth-jwt)  echo "org.lattejava.jwt.benchmarks.fusionauth.Main" ;;
    jjwt)            echo "org.lattejava.jwt.benchmarks.jjwt.Main" ;;
    jose4j)          echo "org.lattejava.jwt.benchmarks.jose4j.Main" ;;
    latte-jwt)       echo "org.lattejava.jwt.benchmarks.lattejwt.Main" ;;
    latte-jwt-jackson) echo "org.lattejava.jwt.benchmarks.lattejwtjackson.Main" ;;
    nimbus-jose-jwt) echo "org.lattejava.jwt.benchmarks.nimbus.Main" ;;
    vertx-auth-jwt)  echo "org.lattejava.jwt.benchmarks.vertx.Main" ;;
    *) echo "unknown library: ${lib}" >&2; exit 1 ;;
  esac
}

# ── validate shared JARs exist before running anything
for jar in "${HARNESS_JAR}" "${JMH_CORE_JAR}" "${JOPT_JAR}" "${MATH3_JAR}"; do
  [[ -f "${jar}" ]] || {
    echo "required JAR not found: ${jar}" >&2
    echo "  harness: run 'latte int' in benchmarks/harness" >&2
    echo "  JMH:     run 'latte build' in any adapter to populate ~/.m2" >&2
    exit 1
  }
done

# ── parity check
echo "→ parity check"
for lib in "${LIBS_ARRAY[@]}"; do
  cp="$(classpath_for_library "${lib}")"
  main_class="$(main_class_for_library "${lib}")"
  echo "  ${lib}…"
  BENCHMARK_FIXTURES="${FIXTURES_DIR}" java -cp "${cp}" "${main_class}" --parity-check || {
    echo "parity FAILED for ${lib}" >&2
    exit 1
  }
done
echo "  ok"

# ── measurement
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SUFFIX=""
[[ -n "${LABEL}" ]] && SUFFIX="-${LABEL}"
MERGED="${RESULTS_DIR}/${TS}${SUFFIX}.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

JMH_ARGS=(
  -wi "${WARMUP_ITERS}" -w "${WARMUP_TIME}"
  -i  "${MEASURE_ITERS}" -r  "${MEASURE_TIME}"
  -f  "${FORKS}" -t  "${THREADS}"
  -rf json
)

declare -a SUCCESS=()
declare -a FAILED=()

echo "→ measurement"
for lib in "${LIBS_ARRAY[@]}"; do
  cp="$(classpath_for_library "${lib}")"
  main_class="$(main_class_for_library "${lib}")"
  out="${TMP_DIR}/${lib}.json"
  echo "  ${lib} → ${out}"
  if BENCHMARK_FIXTURES="${FIXTURES_DIR}" java -cp "${cp}" "${main_class}" "${JMH_ARGS[@]}" -rff "${out}"; then
    SUCCESS+=("${lib}")
  else
    echo "    ${lib} measurement FAILED — continuing" >&2
    FAILED+=("${lib}")
  fi
done

# ── merge JSON arrays
echo "→ merge"
# Each per-library JSON file is a top-level JSON array of JMH benchmark records.
# `jq -s 'add'` slurps them and concatenates the arrays.
shopt -s nullglob
result_files=("${TMP_DIR}"/*.json)
shopt -u nullglob
if [[ ${#result_files[@]} -gt 0 ]]; then
  jq -s 'add' "${result_files[@]}" > "${MERGED}"
  cp "${MERGED}" "${RESULTS_DIR}/latest.json"
  capture_run_conditions "${MERGED%.json}.conditions.json"
  cp "${MERGED%.json}.conditions.json" "${RESULTS_DIR}/latest.conditions.json"
else
  echo "  no result files produced — skipping merge" >&2
fi

echo
echo "  results: ${MERGED}"
echo "  latest:  ${RESULTS_DIR}/latest.json"
echo "  succeeded: ${SUCCESS[*]:-(none)}"
[[ ${#FAILED[@]} -gt 0 ]] && echo "  failed:    ${FAILED[*]}"

# ── update report
if (( DO_UPDATE == 1 )); then
  if [[ -x "${BENCH_DIR}/update-benchmarks.sh" ]]; then
    "${BENCH_DIR}/update-benchmarks.sh" "${MERGED}"
  else
    echo "  --update requested but update-benchmarks.sh not found yet (built in Task 21)" >&2
  fi
fi
