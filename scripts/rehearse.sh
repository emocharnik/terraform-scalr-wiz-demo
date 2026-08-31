#!/usr/bin/env bash
#
# Rehearse the demo locally, without Scalr and without an AWS account.
#
#   ./scripts/rehearse.sh                    # test policies, plan every scenario
#   ./scripts/rehearse.sh 01-public-storage  # just one scenario
#
# What it does:
#   1. Runs `opa test` over the Wiz policies.
#   2. Plans each scenario and exports the plan JSON that Scalr would hand to
#      Wiz, at scenarios/<name>/plan.json.
#   3. If `wizcli` is installed and authenticated, scans each scenario so you
#      can confirm the findings and severities before you are in front of an
#      audience.
#
# The scenarios use fake AWS credentials and skip every API pre-flight check, so
# nothing here can touch a real account.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TF_BIN="${TF_BIN:-terraform}"
OPA_BIN="${OPA_BIN:-opa}"
FILTER="${1:-}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n'  "$*"; }

# --- 1. policies -----------------------------------------------------------
bold "==> Testing Wiz policies"

if ! command -v "$OPA_BIN" >/dev/null 2>&1; then
  red "opa not found. Install it: https://www.openpolicyagent.org/docs/latest/#running-opa"
  exit 1
fi

# `import rego.v1` needs OPA 0.59 or newer.
opa_version="$("$OPA_BIN" version | awk '/^Version:/ {print $2}')"
opa_major="${opa_version%%.*}"
opa_minor="$(printf '%s' "$opa_version" | cut -d. -f2)"
if [ "$opa_major" -eq 0 ] && [ "${opa_minor:-0}" -lt 59 ]; then
  red "OPA $opa_version is too old -- the policies use 'import rego.v1', which needs 0.59+."
  exit 1
fi

"$OPA_BIN" test policies/wiz/ --format pretty
green "policies OK"
echo

# --- 2. scenarios ----------------------------------------------------------
if ! command -v "$TF_BIN" >/dev/null 2>&1; then
  red "$TF_BIN not found. Set TF_BIN=tofu to use OpenTofu instead."
  exit 1
fi

have_wizcli=0
if command -v wizcli >/dev/null 2>&1; then
  have_wizcli=1
else
  echo "wizcli not on PATH -- skipping local Wiz scans, plans will still be generated."
  echo
fi

for dir in scenarios/*/; do
  name="$(basename "$dir")"
  [ -n "$FILTER" ] && [ "$name" != "$FILTER" ] && continue

  bold "==> $name"
  (
    cd "$dir"
    "$TF_BIN" init -input=false -no-color >/dev/null
    "$TF_BIN" plan -input=false -no-color -out=tfplan.out | grep -E '^(Plan|No changes)' || true
    "$TF_BIN" show -json tfplan.out > plan.json
    echo "    plan JSON -> ${dir}plan.json"

    if [ "$have_wizcli" -eq 1 ]; then
      # Mirrors what the Scalr integration does post-plan: scan the IaC.
      wizcli iac scan --path . --format json --output wiz.json 2>/dev/null \
        && echo "    wiz result -> ${dir}wiz.json" \
        || echo "    wizcli scan did not complete (is it authenticated?)"
    fi
  )
  echo
done

green "Rehearsal complete."
