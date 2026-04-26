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

  # Adapters that wrap latte-jwt need the jwt implementation JAR on the classpath.
  case "${lib}" in
    latte-jwt) cp="${cp}:${LATTE_JWT_JAR}" ;;
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
    baseline)  echo "org.lattejava.jwt.benchmarks.baseline.Main" ;;
    latte-jwt) echo "org.lattejava.jwt.benchmarks.lattejwt.Main" ;;
    # Future adapters — add a case when the adapter is built:
    # auth0-java-jwt)          echo "org.lattejava.jwt.benchmarks.auth0.Main" ;;
    # jose4j)                  echo "org.lattejava.jwt.benchmarks.jose4j.Main" ;;
    # nimbus-jose-jwt)         echo "org.lattejava.jwt.benchmarks.nimbus.Main" ;;
    # jjwt)                    echo "org.lattejava.jwt.benchmarks.jjwt.Main" ;;
    # fusionauth-jwt)          echo "org.lattejava.jwt.benchmarks.fusionauth.Main" ;;
    # vertx-auth-jwt)          echo "org.lattejava.jwt.benchmarks.vertx.Main" ;;
    # inverno-security-jose)   echo "org.lattejava.jwt.benchmarks.inverno.Main" ;;
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

# stub: measurement phase implemented in Task 11
echo "(measurement phase not yet implemented — run later tasks)"
