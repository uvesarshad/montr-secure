#!/usr/bin/env bash
# Self-scan / dogfood (build-plan §4.8 & §9.2: "Montr Secure scans itself clean in CI").
#
# Runs the platform's own class of detectors over this repo, best-effort:
#   - gitleaks     (secrets)
#   - semgrep      (SAST)
#   - osv-scanner  (vulnerable dependencies)
#
# Best-effort by default so missing tools never break local dev. Set
# MONTR_SELFSCAN_STRICT=1 to fail when a tool is missing OR reports findings
# (the intended CI gate once the runner has the tools installed).
#
# Usage:  bash scripts/self-scan.sh
# Env:    MONTR_SELFSCAN_STRICT=1
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
STRICT="${MONTR_SELFSCAN_STRICT:-0}"

missing=0   # tools not installed
failures=0  # tools that reported findings / errored

run_tool() {
  # $1 = tool name, rest = command to run
  local name="$1"; shift
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "self-scan: SKIP ${name} (not installed)" >&2
    missing=$((missing + 1))
    return 0
  fi
  echo "self-scan: running ${name} ..."
  if "$@"; then
    echo "self-scan: ${name} OK (no findings)"
  else
    echo "self-scan: ${name} reported findings or errored" >&2
    failures=$((failures + 1))
  fi
}

run_tool gitleaks    gitleaks detect --source "${REPO_ROOT}" --no-banner --redact
run_tool semgrep     semgrep scan --config=auto --error --quiet "${REPO_ROOT}"
run_tool osv-scanner osv-scanner scan --recursive "${REPO_ROOT}"

echo "self-scan: summary — missing=${missing} failures=${failures}"

if [ "${STRICT}" = "1" ]; then
  if [ "${missing}" -gt 0 ] || [ "${failures}" -gt 0 ]; then
    echo "self-scan: MONTR_SELFSCAN_STRICT=1 -> failing (missing=${missing}, failures=${failures})." >&2
    exit 1
  fi
fi

# Best-effort: never fail the build on tool absence; surface findings as a soft signal.
if [ "${failures}" -gt 0 ]; then
  echo "self-scan: findings present (non-strict mode -> exit 0). Review output above." >&2
fi
exit 0
