#!/usr/bin/env bash
# SBOM generation for a Montr Secure release (build-plan §4.8: "SBOM per release (syft)").
#
# Best-effort by default so it never breaks a developer machine. Set
# MONTR_SBOM_STRICT=1 to fail when `syft` is not installed (e.g. on a CI runner
# that is expected to have it).
#
# Usage:  bash scripts/sbom.sh [output-path]
# Env:    SBOM_OUT (default <repo>/sbom.spdx.json), MONTR_SBOM_STRICT=1
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUT="${1:-${SBOM_OUT:-${REPO_ROOT}/sbom.spdx.json}}"
STRICT="${MONTR_SBOM_STRICT:-0}"

if ! command -v syft >/dev/null 2>&1; then
  echo "sbom: 'syft' not found on PATH." >&2
  echo "sbom: install from https://github.com/anchore/syft to generate an SBOM." >&2
  if [ "${STRICT}" = "1" ]; then
    echo "sbom: MONTR_SBOM_STRICT=1 -> failing." >&2
    exit 1
  fi
  echo "sbom: best-effort mode -> skipping (exit 0)." >&2
  exit 0
fi

echo "sbom: generating SPDX SBOM for ${REPO_ROOT} -> ${OUT}"
if syft "dir:${REPO_ROOT}" -o "spdx-json=${OUT}"; then
  echo "sbom: wrote ${OUT}"
  # A CycloneDX copy is handy for some scanners; ignore failure.
  syft "dir:${REPO_ROOT}" -o "cyclonedx-json=${OUT%.spdx.json}.cdx.json" >/dev/null 2>&1 || true
  exit 0
fi

echo "sbom: syft failed." >&2
[ "${STRICT}" = "1" ] && exit 1
exit 0
