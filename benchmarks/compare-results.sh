#!/usr/bin/env bash
# Copyright (c) 2026, The Latte Project. License: MIT.
# Usage: compare-results.sh <baseline.json> <candidate.json> [--threshold N] [--algorithm <hs256|rs256|es256>]
set -euo pipefail

THRESHOLD=5
ALG_FILTER=""
BASELINE=""
CANDIDATE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --algorithm) ALG_FILTER="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: compare-results.sh <baseline.json> <candidate.json> [options]

  --threshold N       Flag rows where |Δ%| ≥ N (default 5)
  --algorithm <name>  Filter to one of: hs256, rs256, es256

Exit non-zero if any candidate row regresses by more than threshold.
EOF
      exit 0 ;;
    *)
      if   [[ -z "${BASELINE}"  ]]; then BASELINE="$1";  shift
      elif [[ -z "${CANDIDATE}" ]]; then CANDIDATE="$1"; shift
      else echo "Unexpected: $1" >&2; exit 2; fi ;;
  esac
done

[[ -f "${BASELINE}"  ]] || { echo "Missing baseline:  ${BASELINE}"  >&2; exit 2; }
[[ -f "${CANDIDATE}" ]] || { echo "Missing candidate: ${CANDIDATE}" >&2; exit 2; }

extract() {
  jq -r '
    .[] | select(.mode=="thrpt") |
    [(.benchmark | split(".") | .[-2]),
     (.benchmark | split(".") | .[-1]),
     .primaryMetric.score] | @tsv
  ' "$1"
}

# Create temp files for baseline and candidate data
B_FILE=$(mktemp)
C_FILE=$(mktemp)
trap "rm -f '$B_FILE' '$C_FILE'" EXIT

extract "${BASELINE}" > "$B_FILE"
extract "${CANDIDATE}" > "$C_FILE"

regressed=0

# pretty library name from JMH benchmark class name
prettyname() {
  case "$1" in
    BaselineBenchmark)    echo "baseline (JCA)" ;;
    LatteJWTBenchmark)    echo "latte-jwt" ;;
    LatteJWTJacksonBenchmark) echo "latte-jwt-jackson" ;;
    Auth0Benchmark)       echo "auth0-java-jwt" ;;
    Jose4jBenchmark)      echo "jose4j" ;;
    NimbusBenchmark)      echo "nimbus-jose-jwt" ;;
    JjwtBenchmark)        echo "jjwt" ;;
    FusionAuthBenchmark)  echo "fusionauth-jwt" ;;
    VertxBenchmark)       echo "vertx-auth-jwt" ;;
    *) echo "$1" ;;
  esac
}

echo "| Op | Library | Baseline | Candidate | Δ % | Flag |"
echo "|----|---------|---------:|----------:|----:|:----:|"

# Process baseline, match against candidate
while IFS=$'\t' read -r lib op base; do
  [[ -n "${ALG_FILTER}" && "${op}" != "${ALG_FILTER}"* ]] && continue

  # Look up in candidate
  cand=$(awk -v lib="$lib" -v op="$op" '$1==lib && $2==op {print $3}' "$C_FILE")
  [[ -z "${cand}" ]] && continue

  delta=$(awk -v b="${base}" -v c="${cand}" 'BEGIN { printf "%.1f", ((c-b)/b)*100 }')
  abs_delta=$(awk -v d="${delta}" 'BEGIN { printf "%.1f", (d<0?-d:d) }')

  flag=""
  if awk -v d="${abs_delta}" -v t="${THRESHOLD}" 'BEGIN { exit !(d>=t) }'; then
    if awk -v d="${delta}" 'BEGIN { exit !(d<0) }'; then
      flag="▼"
      regressed=1
    else
      flag="▲"
    fi
  fi

  base_ops=$(awk -v s="${base}" 'BEGIN { printf "%d", s*1000000 }')
  cand_ops=$(awk -v s="${cand}" 'BEGIN { printf "%d", s*1000000 }')
  printf "| %s | %s | %s | %s | %s %% | %s |\n" \
    "${op}" "$(prettyname "${lib}")" "${base_ops}" "${cand_ops}" "${delta}" "${flag}"
done < "$B_FILE"

exit ${regressed}
