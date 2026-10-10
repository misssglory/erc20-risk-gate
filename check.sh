#!/usr/bin/env bash
set -euo pipefail

ADDR="${1:?usage: ./check.sh 0xTOKEN [chain]}"
CHAIN="${2:-4663}"
BASE_URL="${ERC20_RISK_GATE_URL:-http://127.0.0.1:8333}"
URL="${BASE_URL%/}/scan/${CHAIN}/${ADDR}"

BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT

HTTP_CODE="$(curl -sS -o "$BODY" -w '%{http_code}' "$URL")" || {
  rc=$?
  echo "erc20-risk-gate request failed: $URL" >&2
  exit "$rc"
}

if [[ ! "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
  echo "erc20-risk-gate returned HTTP $HTTP_CODE:" >&2
  if jq -e . >/dev/null 2>&1 < "$BODY"; then
    jq . < "$BODY" >&2
  else
    cat "$BODY" >&2
    printf '\n' >&2
  fi
  exit 1
fi

if ! jq -e . >/dev/null 2>&1 < "$BODY"; then
  echo "erc20-risk-gate returned a non-JSON response (HTTP $HTTP_CODE):" >&2
  cat "$BODY" >&2
  printf '\n' >&2
  exit 1
fi

jq . < "$BODY"
