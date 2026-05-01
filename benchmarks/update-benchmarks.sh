#!/usr/bin/env bash
# Copyright (c) 2026, The Latte Project. License: MIT.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESULTS_FILE="${1:-${SCRIPT_DIR}/results/latest.json}"
CONDITIONS_FILE="${RESULTS_FILE%.json}.conditions.json"
[[ -f "${CONDITIONS_FILE}" ]] || CONDITIONS_FILE="${SCRIPT_DIR}/results/latest.conditions.json"
TARGET="${SCRIPT_DIR}/BENCHMARKS.md"

# extract per-(library, op, mode) score from JMH JSON
# outputs TSV: lib op mode score err unit
extract() {
  jq -r '
    .[] | {
      lib:   (.benchmark | split(".") | .[-2]),
      op:    (.benchmark | split(".") | .[-1]),
      mode:  .mode,
      score: .primaryMetric.score,
      err:   .primaryMetric.scoreError,
      unit:  .primaryMetric.scoreUnit
    } | [.lib, .op, .mode, .score, .err, .unit] | @tsv
  ' "${RESULTS_FILE}"
}

# render one leaderboard table for (op, mode)
# Score is in ops/us (thrpt); multiply by 1,000,000 to display ops/sec.
render_leaderboard() {
  local op="$1"
  local mode="$2"
  local title="$3"

  local rows
  rows=$(extract | awk -F'\t' -v op="${op}" -v mode="${mode}" '$2==op && $3==mode { print }')
  [[ -z "${rows}" ]] && return 0

  echo "### ${title}"
  echo

  # leader = highest ops/us among non-baseline libraries
  local leader_score
  leader_score=$(printf '%s' "${rows}" | awk -F'\t' '$1!="BaselineBenchmark" {print $4}' | sort -gr | head -1)

  local latte_score
  latte_score=$(printf '%s' "${rows}" | awk -F'\t' '$1=="LatteJWTBenchmark" {print $4}')

  echo "| # | Library | ops/sec | vs leader | vs latte-jwt |"
  echo "|--:|---------|--------:|----------:|-------------:|"

  # competitive rows (not baseline) sorted by score descending
  printf '%s\n' "${rows}" | awk -F'\t' '$1!="BaselineBenchmark" {print}' | sort -t$'\t' -k4 -gr | \
    awk -F'\t' -v ld="${leader_score}" -v lt="${latte_score}" '
    BEGIN { rank = 0 }
    {
      rank++
      ops_per_sec = $4 * 1000000
      vs_leader   = (ld > 0) ? ($4 / ld) * 100 : 0
      libn = $1
      sub(/Benchmark$/, "", libn)
      if      (libn == "LatteJWTJackson") libn = "latte-jwt-jackson"
      else if (libn == "LatteJWT")   libn = "latte-jwt"
      else if (libn == "Auth0")      libn = "auth0-java-jwt"
      else if (libn == "Jose4j")     libn = "jose4j"
      else if (libn == "Nimbus")     libn = "nimbus-jose-jwt"
      else if (libn == "Jjwt")       libn = "jjwt"
      else if (libn == "FusionAuth") libn = "fusionauth-jwt"
      else if (libn == "Vertx")      libn = "vertx-auth-jwt"
      else                           libn = tolower(libn)
      vs_latte_str = (lt > 0) ? sprintf("%.1f %%", ($4 / lt) * 100) : "—"
      printf "| %d | %s | %d | %.1f %% | %s |\n", rank, libn, ops_per_sec, vs_leader, vs_latte_str
    }
  '

  # baseline row in italics, appended last
  printf '%s\n' "${rows}" | awk -F'\t' -v ld="${leader_score}" -v lt="${latte_score}" '
    $1 == "BaselineBenchmark" {
      ops_per_sec = $4 * 1000000
      vs_leader   = (ld > 0) ? ($4 / ld) * 100 : 0
      vs_latte_str = (lt > 0) ? sprintf("%.1f %%", ($4 / lt) * 100) : "—"
      printf "| | _baseline (JCA)_ | _%d_ | _%.1f %%_ | _%s_ |\n", ops_per_sec, vs_leader, vs_latte_str
    }
  '
  echo
}

# top-of-page aggregate leaderboard (mean across HS256/RS256/ES256 decode-verify-validate thrpt)
render_aggregate() {
  echo "## Overall leaderboard — decode-verify-validate (the headline op)"
  echo
  echo "Mean ops/sec across HS256, RS256, ES256 decode-verify-validate (Throughput mode):"
  echo
  echo "| # | Library | mean ops/sec |"
  echo "|--:|---------|-------------:|"

  extract | awk -F'\t' '
    $2 ~ /_decode_verify_validate$/ && $3 == "thrpt" && $1 != "BaselineBenchmark" {
      sum[$1] += $4
      n[$1]++
    }
    END {
      for (lib in sum) printf "%s\t%.9f\n", lib, sum[lib] / n[lib]
    }
  ' | sort -t$'\t' -k2 -gr | awk -F'\t' '
    BEGIN { rank = 0 }
    {
      rank++
      libn = $1
      sub(/Benchmark$/, "", libn)
      if      (libn == "LatteJWTJackson") libn = "latte-jwt-jackson"
      else if (libn == "LatteJWT")   libn = "latte-jwt"
      else if (libn == "Auth0")      libn = "auth0-java-jwt"
      else if (libn == "Jose4j")     libn = "jose4j"
      else if (libn == "Nimbus")     libn = "nimbus-jose-jwt"
      else if (libn == "Jjwt")       libn = "jjwt"
      else if (libn == "FusionAuth") libn = "fusionauth-jwt"
      else if (libn == "Vertx")      libn = "vertx-auth-jwt"
      else                           libn = tolower(libn)
      printf "| %d | %s | %d |\n", rank, libn, $2 * 1000000
    }
  '

  extract | awk -F'\t' '
    $2 ~ /_decode_verify_validate$/ && $3 == "thrpt" && $1 == "BaselineBenchmark" {
      sum += $4
      n++
    }
    END {
      if (n > 0) printf "| | _baseline (JCA)_ | _%d_ |\n", (sum / n) * 1000000
    }
  '
  echo
}

generate_body() {
  echo "<!-- BENCHMARKS:START -->"
  echo
  render_aggregate
  echo "## Throughput by algorithm (ops/sec, higher is better)"
  echo
  render_leaderboard "hs256_encode"                 "thrpt" "HS256 — encode"
  render_leaderboard "hs256_decode_verify_validate" "thrpt" "HS256 — decode + verify + validate"
  render_leaderboard "rs256_encode"                 "thrpt" "RS256 — encode"
  render_leaderboard "rs256_decode_verify_validate" "thrpt" "RS256 — decode + verify + validate"
  render_leaderboard "es256_encode"                 "thrpt" "ES256 — encode"
  render_leaderboard "es256_decode_verify_validate" "thrpt" "ES256 — decode + verify + validate"
  echo "## Supporting operations"
  echo
  render_leaderboard "unsafe_decode_claims" "thrpt" "Unsafe decode — claims only (base64 + JSON parse of payload, no signature verification, no header parse)"
  render_leaderboard "unsafe_decode_full"   "thrpt" "Unsafe decode — full (header + claims, no signature verification)"

  echo "## Run conditions"
  if [[ -f "${CONDITIONS_FILE}" ]]; then
    echo
    echo '```json'
    jq . "${CONDITIONS_FILE}"
    echo '```'
  fi
  echo
  echo "<!-- BENCHMARKS:END -->"
}

# preserve hand-edited prose outside the sentinels
BODY_TMP="$(mktemp)"
trap 'rm -f "${BODY_TMP}"' EXIT
generate_body > "${BODY_TMP}"

if [[ -f "${TARGET}" ]] && grep -q 'BENCHMARKS:START' "${TARGET}"; then
  awk -v bodytmp="${BODY_TMP}" '
    /BENCHMARKS:START/ {
      while ((getline line < bodytmp) > 0) print line
      close(bodytmp)
      in_block = 1
      next
    }
    /BENCHMARKS:END/   { in_block = 0; next }
    !in_block          { print }
  ' "${TARGET}" > "${TARGET}.tmp" && mv "${TARGET}.tmp" "${TARGET}"
else
  {
    cat <<'PREAMBLE'
# JWT Library Benchmarks

This is the auto-generated benchmark report. The methodology is documented in
[the benchmark framework spec](../specs/benchmark-framework.md). To run benchmarks yourself,
see [`benchmarks/README.md`](README.md).

The numbers below come from a single run on a single machine. Relative ranking between libraries
is what matters; absolute ops/sec depend on hardware and JVM. Always re-run on your own
hardware before quoting absolute numbers.

PREAMBLE
    cat "${BODY_TMP}"
    echo
  } > "${TARGET}"
fi

echo "wrote ${TARGET}"

# ── README.md performance section
README="${SCRIPT_DIR}/../README.md"
if [[ -f "${README}" ]] && grep -q 'README:PERFORMANCE:START' "${README}"; then
  README_BODY="$(render_leaderboard "rs256_decode_verify_validate" "thrpt" "RS256 — decode + verify + validate")"
  # write body to temp file (same pattern as the BENCHMARKS.md awk replace)
  README_BODY_FILE="$(mktemp)"
  echo "${README_BODY}" > "${README_BODY_FILE}"
  awk -v body_file="${README_BODY_FILE}" '
    BEGIN {
      while ((getline line < body_file) > 0) body = body == "" ? line : body "\n" line
      close(body_file)
    }
    /README:PERFORMANCE:START/ { print; print body; in_block=1; next }
    /README:PERFORMANCE:END/   { in_block=0; print; next }
    !in_block { print }
  ' "${README}" > "${README}.tmp" && mv "${README}.tmp" "${README}"
  rm -f "${README_BODY_FILE}"
  echo "wrote ${README}"
fi
